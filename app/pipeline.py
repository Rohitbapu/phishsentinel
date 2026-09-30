"""Ingest -> tiers -> policy -> actions -> campaign -> audit. Pure Python, no web framework needed."""
import json, os, re, time
from . import db, explain, parser, policy, tiers
from .parser import registered_domain

VIPS = {v.strip().lower() for v in os.environ.get("PS_VIPS", "ceo@corp.test,cfo@corp.test").split(",") if v.strip()}
RATE_LIMIT = int(os.environ.get("PS_RATE_LIMIT", "300"))  # max automatic actions per minute
TIER_NAME = {0: "Tier 0 (fast rules)", 1: "Tier 1 (score)", 2: "Tier 2 (investigation)", 3: "Tier 2 (unresolved, needs analyst)"}

def ingest(reporter="anonymous", raw=None, text=None, subject=None, sender=None, links=None):
    p = parser.parse(raw, text, subject, sender, links)
    vip = 1 if (reporter or "").lower() in VIPS else 0
    disp = f'{p["sender_name"]} <{p["sender_addr"]}>' if p["sender_name"] else p["sender_addr"]
    rid = db.run("INSERT INTO reports(created_at,reporter,subject,sender,sender_domain,body,links,parsed,status,vip)"
                 " VALUES(?,?,?,?,?,?,?,?,?,?)",
                 (time.time(), reporter, p["subject"], disp, p["sender_domain"], p["body"][:5000],
                  json.dumps(p["links"]), json.dumps(p), "queued", vip))
    db.audit(rid, "ingested", {"reporter": reporter, "vip": bool(vip)})
    return rid

def _rationale(verdict, conf, tier, evidence):
    pos = sorted([e for e in evidence if e["weight"] > 0], key=lambda e: -e["weight"])[:3]
    neg = sorted([e for e in evidence if e["weight"] < 0], key=lambda e: e["weight"])[:2]
    head = {"phishing": "Phishing", "benign": "Benign", "needs_review": "Needs analyst review"}[verdict]
    s = f"{head} ({conf:.0%} confidence), resolved by {TIER_NAME[tier]}."
    if verdict == "needs_review":
        s += " Evidence is mixed, so the system will not guess."
    if pos: s += " Evidence for phishing: " + "; ".join(e["detail"] for e in pos) + "."
    if neg: s += " Evidence for safe: " + "; ".join(e["detail"] for e in neg) + "."
    return s

def process(rid):
    try:
        _process(rid)
    except Exception as exc:  # never lose a report silently
        db.run("UPDATE reports SET status='error', rationale=? WHERE id=?", (f"Processing error: {exc}", rid))
        db.audit(rid, "error", {"error": str(exc)})

def triage(p, prior=None, use_tier2=True):
    """Pure decision logic (no DB). Returns verdict, prob, tier, evidence, p1.
    use_tier2=False is the ablation used by tools/evaluate.py: borderline mail is left unresolved (tier 3)."""
    evidence = []
    t0 = tiers.tier0(p)
    if t0["resolved"]:
        return {"verdict": t0["verdict"], "prob": t0["p"], "tier": 0, "evidence": t0["evidence"], "p1": None}
    p1, ev1 = tiers.tier1(p)
    evidence += ev1
    s1 = policy.stage1(p1, ev1, p)
    if s1 != "investigate":
        return {"verdict": s1, "prob": p1, "tier": 1, "evidence": evidence, "p1": p1}
    if not use_tier2:
        return {"verdict": "needs_review", "prob": p1, "tier": 3, "evidence": evidence, "p1": p1}
    ev2 = tiers.tier2(p, prior or {"benign": 0, "phish": 0})
    evidence += ev2
    prob = tiers.fuse(p1, ev2)
    verdict = policy.final(prob)
    return {"verdict": verdict, "prob": prob, "tier": 3 if verdict == "needs_review" else 2, "evidence": evidence, "p1": p1}

def _auto_actions_last_minute():
    return db.one("SELECT COUNT(*) AS n FROM actions WHERE actor='system' AND ts>?", (time.time() - 60,))["n"]

def _process(rid):
    r = db.one("SELECT * FROM reports WHERE id=?", (rid,))
    p = json.loads(r["parsed"])
    pr = db.one("SELECT SUM(verdict='benign') AS b, SUM(verdict='phishing') AS ph FROM reports "
                "WHERE sender_domain=? AND id<>?", (r["sender_domain"], rid)) or {}
    d = triage(p, {"benign": pr.get("b") or 0, "phish": pr.get("ph") or 0})
    verdict, prob, tier, evidence = d["verdict"], d["prob"], d["tier"], d["evidence"]
    conf = prob if verdict == "phishing" else (1 - prob if verdict == "benign" else max(prob, 1 - prob))
    autonomy = db.get_setting("autonomy", "1") == "1"
    limited = _auto_actions_last_minute() >= RATE_LIMIT
    held = (not autonomy) or bool(r["vip"]) or limited
    if verdict == "needs_review":
        status = "needs_review"
    elif held:
        status = "held_for_approval"
    else:
        status = "auto_quarantined" if verdict == "phishing" else "auto_released"
    text = _rationale(verdict, conf, tier, evidence)
    if held and verdict != "needs_review":
        text += " Held for human approval: " + ("VIP mailbox." if r["vip"] else "autonomy is paused." if not autonomy else "auto-action rate limit reached.")
    db.run("UPDATE reports SET verdict=?, phish_prob=?, confidence=?, tier_resolved=?, evidence=?, rationale=?, "
           "status=?, processed_at=? WHERE id=?",
           (verdict, prob, conf, tier, json.dumps(evidence), text, status, time.time(), rid))
    db.audit(rid, "verdict", {"verdict": verdict, "p": round(prob, 3), "tier": tier, "status": status})
    if status == "auto_quarantined": quarantine(rid, "system")
    elif status == "auto_released": release(rid, "system")
    if verdict != "benign": assign_campaign(rid, p, verdict)
    if tier in (2, 3) and explain.ENABLED:   # slow, optional, evidence-only, never affects the verdict
        note = explain.summarize(verdict, conf, evidence)
        if note:
            db.run("UPDATE reports SET explanation=? WHERE id=?", (note, rid))
            db.audit(rid, "llm_explanation", {"model": explain.MODEL})

# ---------------- actions (all reversible) ----------------
def quarantine(rid, actor="analyst"):
    db.run("UPDATE reports SET quarantined=1 WHERE id=?", (rid,))
    db.run("INSERT INTO actions(report_id,action,ts,actor) VALUES(?,?,?,?)", (rid, "quarantine", time.time(), actor))
    db.audit(rid, "action", {"action": "quarantine", "actor": actor})

def release(rid, actor="analyst"):
    db.run("UPDATE reports SET quarantined=0 WHERE id=?", (rid,))
    db.run("INSERT INTO actions(report_id,action,ts,actor) VALUES(?,?,?,?)", (rid, "release", time.time(), actor))
    db.audit(rid, "action", {"action": "release", "actor": actor})

def undo(rid, actor="analyst"):
    a = db.one("SELECT * FROM actions WHERE report_id=? AND undone=0 ORDER BY id DESC LIMIT 1", (rid,))
    if not a:
        return False
    db.run("UPDATE actions SET undone=1 WHERE id=?", (a["id"],))
    db.run("UPDATE reports SET quarantined=0, status='needs_review', verdict='needs_review', resolved_by=NULL WHERE id=?", (rid,))
    db.audit(rid, "undo", {"undone": a["action"], "actor": actor})
    return True

def apply_feedback(rid, label, analyst="analyst"):
    """Analyst confirms a verdict. Also the approval path for held (VIP / autonomy-paused) reports."""
    if label not in ("phishing", "benign"):
        raise ValueError("label must be 'phishing' or 'benign'")
    r = db.one("SELECT * FROM reports WHERE id=?", (rid,))
    status = "analyst_quarantined" if label == "phishing" else "analyst_released"
    db.run("UPDATE reports SET verdict=?, status=?, resolved_by=?, confidence=1.0 WHERE id=?", (label, status, analyst, rid))
    db.audit(rid, "feedback", {"label": label, "analyst": analyst})
    if label == "phishing":
        quarantine(rid, analyst)
        if not r["campaign_id"]:
            assign_campaign(rid, json.loads(r["parsed"]), "phishing")
    else:
        release(rid, analyst)

# ---------------- campaigns ----------------
def _tokens(p):
    words = re.findall(r"[a-z]{4,}", (p["subject"] + " " + p["body"][:400]).lower())
    return set(words)

def assign_campaign(rid, p, verdict):
    toks = _tokens(p)
    doms = {reg for _, reg, _ in tiers.link_domains(p) if reg not in tiers.ALLOW}
    sreg = registered_domain(p["sender_domain"])
    if verdict == "phishing" and sreg and sreg not in tiers.ALLOW and sreg not in tiers.FREEMAIL:
        doms.add(sreg)
    best = None
    for c in db.rows("SELECT * FROM campaigns"):
        cd, ct = set(json.loads(c["domains"])), set(json.loads(c["tokens"]))
        jac = len(toks & ct) / max(len(toks | ct), 1)
        if (doms & cd) or jac >= 0.55:
            best = (c, cd, ct)
            break
    if best:
        c, cd, ct = best
        db.run("UPDATE campaigns SET size=size+1, domains=?, tokens=? WHERE id=?",
               (json.dumps(sorted(cd | doms)), json.dumps(sorted(ct | toks)), c["id"]))
        cid = c["id"]
    else:
        cid = db.run("INSERT INTO campaigns(created_at,label,domains,tokens,size) VALUES(?,?,?,?,1)",
                     (time.time(), (p["subject"] or "(no subject)")[:70], json.dumps(sorted(doms)), json.dumps(sorted(toks))))
    db.run("UPDATE reports SET campaign_id=? WHERE id=?", (cid, rid))
    db.audit(rid, "campaign", {"campaign_id": cid})

def quarantine_campaign(cid, actor="analyst"):
    ids = [r["id"] for r in db.rows("SELECT id FROM reports WHERE campaign_id=? AND quarantined=0 AND verdict<>'benign'", (cid,))]
    for rid in ids:
        db.run("UPDATE reports SET verdict='phishing', status='analyst_quarantined', resolved_by=? WHERE id=?", (actor, rid))
        quarantine(rid, actor)
    return len(ids)

# ---------------- stats for the dashboard ----------------
def stats():
    tiers_n = {r["t"]: r["n"] for r in db.rows("SELECT tier_resolved AS t, COUNT(*) AS n FROM reports WHERE tier_resolved IS NOT NULL GROUP BY tier_resolved")}
    verd = {r["v"]: r["n"] for r in db.rows("SELECT verdict AS v, COUNT(*) AS n FROM reports WHERE verdict IS NOT NULL GROUP BY verdict")}
    total = db.one("SELECT COUNT(*) AS n FROM reports")["n"]
    grouped = db.one("SELECT COUNT(*) AS n FROM reports WHERE campaign_id IS NOT NULL")["n"]
    camps = db.one("SELECT COUNT(*) AS n FROM campaigns")["n"]
    return {"total": total, "tier0": tiers_n.get(0, 0), "tier1": tiers_n.get(1, 0), "tier2": tiers_n.get(2, 0),
            "human": tiers_n.get(3, 0), "verdicts": verd, "campaigns": camps,
            "compression": round(grouped / camps, 1) if camps else 0,
            "autonomy": db.get_setting("autonomy", "1") == "1"}
