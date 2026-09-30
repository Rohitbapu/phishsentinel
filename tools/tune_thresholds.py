"""Tune the four policy thresholds on a VALIDATION set, then report on the untouched TEST set.

  python -m tools.tune_thresholds --dir data/val                 # folders: data/val/phishing/*.eml, data/val/benign/*.eml
  python -m tools.tune_thresholds --dir data/val --write         # save the winner to data/policy.json (picked up on next start)
  python -m tools.tune_thresholds --synthetic 300                # plumbing check only, NOT a result

Cost model (change with flags; state your values on the slide):
  a missed attack (phishing auto-released)      --fn-cost   default 10
  a legitimate mail auto-quarantined            --fp-cost   default 3   (reversible, so cheaper than a miss)
  any report sent to a human analyst            --human-cost default 1
The search minimises total cost. Do NOT tune on the test set: tune here, then run tools.evaluate on the test set once.
"""
import argparse, itertools, json, os

from app import parser, pipeline, policy, tiers
from tools.evaluate import load_dir, load_synthetic

GRID = {"auto_phish": [0.80, 0.85, 0.90, 0.95, 0.98], "auto_benign": [0.02, 0.05, 0.10, 0.15, 0.20],
        "final_phish": [0.60, 0.70, 0.80, 0.90], "final_benign": [0.10, 0.20, 0.30, 0.40]}


def precompute(samples):
    """Score every email once. Thresholds only change the decision, not these scores."""
    out = []
    for s in samples:
        p = parser.parse(s["raw"])
        t0 = tiers.tier0(p)
        if t0["resolved"]:
            out.append({"truth": s["truth"], "fixed": t0["verdict"]}); continue
        p1, ev1 = tiers.tier1(p)
        prob2 = tiers.fuse(p1, tiers.tier2(p, {"benign": 0, "phish": 0}))
        out.append({"truth": s["truth"], "fixed": None, "p1": p1, "ev1": ev1, "parsed": p, "prob2": prob2})
    return out


def decide(row):
    if row["fixed"]:
        return row["fixed"], 0
    s1 = policy.stage1(row["p1"], row["ev1"], row["parsed"])
    if s1 != "investigate":
        return s1, 1
    v = policy.final(row["prob2"])
    return v, (3 if v == "needs_review" else 2)


def score(rows, costs):
    fn = fp = human = 0
    for r in rows:
        v, _ = decide(r)
        if v == "needs_review": human += 1
        elif v == "benign" and r["truth"] == "phishing": fn += 1
        elif v == "phishing" and r["truth"] == "benign": fp += 1
    cost = fn * costs[0] + fp * costs[1] + human * costs[2]
    return {"cost": cost, "missed": fn, "blocked_legit": fp, "to_human": human, "to_human_pct": round(100 * human / len(rows), 1)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir"); ap.add_argument("--synthetic", type=int, default=0)
    ap.add_argument("--fn-cost", type=float, default=10); ap.add_argument("--fp-cost", type=float, default=3)
    ap.add_argument("--human-cost", type=float, default=1); ap.add_argument("--write", action="store_true")
    ap.add_argument("--top", type=int, default=5)
    a = ap.parse_args()
    if a.synthetic: samples, stamp = load_synthetic(a.synthetic), "SYNTHETIC: plumbing check, NOT a result"
    elif a.dir: samples, stamp = load_dir(a.dir), "validation set"
    else: ap.error("give --dir or --synthetic N")
    samples = [s for s in samples if s["truth"] in ("phishing", "benign")]
    if len(samples) < 50:
        print(f"WARNING: only {len(samples)} labelled emails; thresholds tuned on so few will not generalise.")
    rows = precompute(samples)
    costs = (a.fn_cost, a.fp_cost, a.human_cost)

    current = dict(policy.T)
    base = score(rows, costs)
    results = []
    for combo in itertools.product(*GRID.values()):
        t = dict(zip(GRID, combo))
        if t["final_benign"] >= t["final_phish"] or t["auto_benign"] >= t["auto_phish"]:
            continue
        policy.T.update(t)
        results.append((score(rows, costs), t))
    policy.T.update(current)
    # lowest cost wins; ties go to fewer misses, then fewer human reviews, then the stricter auto-thresholds
    results.sort(key=lambda r: (r[0]["cost"], r[0]["missed"], r[0]["to_human"], -r[1]["auto_phish"]))

    print(f"{stamp} | n={len(rows)} | costs: miss={a.fn_cost} blocked-legit={a.fp_cost} human={a.human_cost}")
    print(f"current thresholds {current}: {base}")
    print(f"\ntop {a.top} of {len(results)} candidates:")
    for sc, t in results[:a.top]:
        print(f"  {t}\n     -> {sc}")
    best_sc, best_t = results[0]
    print(f"\nbest vs current: cost {base['cost']} -> {best_sc['cost']}")
    if a.write and not a.synthetic:
        os.makedirs(os.path.dirname(policy.OVERRIDE), exist_ok=True)
        json.dump(best_t, open(policy.OVERRIDE, "w"), indent=2)
        print(f"wrote {policy.OVERRIDE}. Restart the server; then run tools.evaluate on the TEST set.")
    elif a.write:
        print("not written: synthetic runs never overwrite real thresholds")


if __name__ == "__main__":
    main()
