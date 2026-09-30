"""Runs the whole pipeline without a web server:  python -m tests.test_pipeline"""
import os, tempfile, collections
os.environ["PS_DB"] = os.path.join(tempfile.mkdtemp(), "test.db")
from app import db, pipeline
from tools.replay import build_samples, phish_known, benign_github, bec_freemail, mk
import random

db.init()
def run_one(raw, reporter="emp1@corp.test"):
    rid = pipeline.ingest(reporter=reporter, raw=raw)
    pipeline.process(rid)
    return db.one("SELECT * FROM reports WHERE id=?", (rid,))

r = random.Random(1)
a = run_one(phish_known(r));   assert a["verdict"] == "phishing" and a["tier_resolved"] == 0, a
b = run_one(benign_github(r)); assert b["verdict"] == "benign" and b["tier_resolved"] == 0, b
c = run_one(bec_freemail(r));  assert c["verdict"] == "phishing" and c["tier_resolved"] == 2, (c["verdict"], c["tier_resolved"], c["rationale"])
vip = run_one(phish_known(r), reporter="ceo@corp.test"); assert vip["status"] == "held_for_approval" and vip["quarantined"] == 0, vip
pipeline.apply_feedback(vip["id"], "phishing"); assert db.one("SELECT quarantined FROM reports WHERE id=?", (vip["id"],))["quarantined"] == 1
assert pipeline.undo(vip["id"]) and db.one("SELECT quarantined FROM reports WHERE id=?", (vip["id"],))["quarantined"] == 0

# bulk replay
db.run("DELETE FROM reports"); db.run("DELETE FROM campaigns")
rows = []
for s in build_samples(80):
    row = run_one(s["raw"], s["reporter"]); row["truth"], row["kind"] = s["truth"], s["kind"]; rows.append(row)
print("tier funnel:", collections.Counter(x["tier_resolved"] for x in rows))
print("verdicts   :", collections.Counter(x["verdict"] for x in rows))
by_kind = collections.defaultdict(collections.Counter)
for x in rows: by_kind[x["kind"]][f'{x["verdict"]}@t{x["tier_resolved"]}'] += 1
for k, v in by_kind.items(): print(f"  {k:18s}", dict(v))
wrong = [x for x in rows if (x["truth"] == "phishing" and x["verdict"] == "benign") or (x["truth"] == "benign" and x["verdict"] == "phishing")]
print("hard errors :", len(wrong))
print("stats       :", pipeline.stats())
assert not wrong

# ---- pure triage(): Tier 2 ablation ----
from app import parser
pb = parser.parse(bec_freemail(random.Random(2)))
full, base = pipeline.triage(pb, use_tier2=True), pipeline.triage(pb, use_tier2=False)
assert full["verdict"] == "phishing" and full["tier"] == 2, full["verdict"]
assert base["verdict"] == "needs_review" and base["tier"] == 3   # without Tier 2 it stays unresolved
print("triage ablation: BEC mail resolves at Tier 2 only")

# ---- rate limit guardrail: auto-actions are held once the per-minute cap is hit ----
db.run("DELETE FROM reports"); db.run("DELETE FROM campaigns"); db.run("DELETE FROM actions")
pipeline.RATE_LIMIT = 3
held = [run_one(phish_known(random.Random(i)))["status"] for i in range(6)]
assert held.count("auto_quarantined") == 3 and held.count("held_for_approval") == 3, held
pipeline.RATE_LIMIT = 300
print("rate limit: first 3 auto, next 3 held for approval")

# ---- kill switch holds everything ----
db.set_setting("autonomy", "0")
k = run_one(phish_known(random.Random(9))); assert k["status"] == "held_for_approval" and k["quarantined"] == 0
db.set_setting("autonomy", "1")

# ---- campaign quarantine + undo ----
db.run("DELETE FROM reports"); db.run("DELETE FROM campaigns"); db.run("DELETE FROM actions")
from tools.replay import phish_lookalike
pipeline.RATE_LIMIT = 0    # force everything into "held" so we can test the one-click campaign action
ids = [run_one(phish_lookalike(random.Random(i)))["id"] for i in range(5)]
pipeline.RATE_LIMIT = 300
cid = db.one("SELECT campaign_id FROM reports WHERE id=?", (ids[0],))["campaign_id"]
assert all(db.one("SELECT campaign_id FROM reports WHERE id=?", (i,))["campaign_id"] == cid for i in ids), "one campaign expected"
assert pipeline.quarantine_campaign(cid) == 5
assert db.one("SELECT COUNT(*) AS n FROM reports WHERE quarantined=1")["n"] == 5
assert pipeline.undo(ids[0]) and db.one("SELECT quarantined FROM reports WHERE id=?", (ids[0],))["quarantined"] == 0
print("campaign: 5 reports -> 1 incident -> quarantine all -> undo one")
print("ALL OK")
