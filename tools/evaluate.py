"""Evaluation: funnel, with/without Tier 2, precision/recall/FPR, calibration (ECE + reliability curve).

  python -m tools.evaluate --dir data/eval            # folders:  data/eval/phishing/*.eml   data/eval/benign/*.eml
  python -m tools.evaluate --dir data/hard --name hard
  python -m tools.evaluate --synthetic 300            # SMOKE TEST ONLY: templates written by us, NOT a result

Writes  eval_out/<name>/metrics.json, metrics.md, funnel.png, with_without_tier2.png, reliability.png
Rule: only numbers from a real labelled held-out set go into the deck. The synthetic run is stamped as such.

System A = Tier 0 + Tier 1 with a forced yes/no at 0.5 (what most tools do: the coin flip).
System B = full PhishSentinel (Tier 0 + 1 + 2, three states, borderline mail goes to a human).
"""
import argparse, glob, json, os
from collections import Counter

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from app import parser, pipeline


def load_dir(root):
    out = []
    for label in ("phishing", "benign"):
        for path in sorted(glob.glob(os.path.join(root, label, "*.eml"))):
            with open(path, "rb") as f:
                out.append({"id": os.path.basename(path), "truth": label, "raw": f.read()})
    return out


def load_synthetic(n):
    from tools.replay import build_samples
    return [{"id": f"syn{i}", "truth": s["truth"], "raw": s["raw"], "kind": s["kind"]}
            for i, s in enumerate(build_samples(n, seed=11))]


def ece_and_bins(y, p, bins=10):
    rows, ece = [], 0.0
    for i in range(bins):
        lo, hi = i / bins, (i + 1) / bins
        idx = [k for k, v in enumerate(p) if lo <= v < hi or (i == bins - 1 and v == 1.0)]
        if not idx:
            continue
        conf = sum(p[k] for k in idx) / len(idx)
        acc = sum(y[k] for k in idx) / len(idx)
        ece += len(idx) / len(p) * abs(acc - conf)
        rows.append({"bin": f"{lo:.1f}-{hi:.1f}", "n": len(idx), "mean_pred": round(conf, 3), "frac_phishing": round(acc, 3)})
    return ece, rows


def prf(tp, fp, fn):
    pr = tp / (tp + fp) if tp + fp else 0.0
    rc = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * pr * rc / (pr + rc) if pr + rc else 0.0
    return round(pr, 3), round(rc, 3), round(f1, 3)


def confusion(rows, key):
    """rows carry truth and a prediction under `key` in {phishing, benign, needs_review}."""
    tp = sum(r["truth"] == "phishing" and r[key] == "phishing" for r in rows)
    fp = sum(r["truth"] == "benign" and r[key] == "phishing" for r in rows)
    fn = sum(r["truth"] == "phishing" and r[key] == "benign" for r in rows)
    tn = sum(r["truth"] == "benign" and r[key] == "benign" for r in rows)
    abst_p = sum(r["truth"] == "phishing" and r[key] == "needs_review" for r in rows)
    abst_b = sum(r["truth"] == "benign" and r[key] == "needs_review" for r in rows)
    pr, rc, f1 = prf(tp, fp, fn)
    npos = sum(r["truth"] == "phishing" for r in rows)
    nneg = len(rows) - npos
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "to_human_phish": abst_p, "to_human_benign": abst_b,
            "precision": pr, "recall_auto": rc, "f1": f1,
            "false_positive_rate": round(fp / nneg, 4) if nneg else 0.0,
            "miss_rate": round(fn / npos, 4) if npos else 0.0,
            "sent_to_human_pct": round(100 * (abst_p + abst_b) / len(rows), 1)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir"); ap.add_argument("--synthetic", type=int, default=0)
    ap.add_argument("--name", default=None); ap.add_argument("--out", default="eval_out")
    ap.add_argument("--minutes", type=float, default=5.0, help="ASSUMED manual minutes per email (state it openly)")
    a = ap.parse_args()
    if a.synthetic:
        samples, name, stamp = load_synthetic(a.synthetic), a.name or "synthetic", "SYNTHETIC SMOKE TEST - NOT A RESULT"
    elif a.dir:
        samples, name, stamp = load_dir(a.dir), a.name or os.path.basename(os.path.normpath(a.dir)), "held-out labelled set"
    else:
        ap.error("give --dir or --synthetic N")
    samples = [s for s in samples if s["truth"] in ("phishing", "benign")]
    if not samples:
        raise SystemExit("no labelled samples found (need <dir>/phishing/*.eml and <dir>/benign/*.eml)")

    rows = []
    for s in samples:
        p = parser.parse(s["raw"])
        full = pipeline.triage(p, use_tier2=True)
        base = pipeline.triage(p, use_tier2=False)
        # System A: forced guess for whatever Tier 0/1 could not settle
        a_pred = base["verdict"] if base["verdict"] != "needs_review" else ("phishing" if base["p1"] >= 0.5 else "benign")
        rows.append({"id": s["id"], "truth": s["truth"], "A": a_pred, "B": full["verdict"], "tier": full["tier"],
                     "prob": full["prob"], "reached_tier2": full["tier"] in (2, 3)})

    n = len(rows)
    funnel = Counter(r["tier"] for r in rows)
    fun = {"tier0": funnel[0], "tier1": funnel[1], "tier2": funnel[2], "human": funnel[3]}
    A, B = confusion(rows, "A"), confusion(rows, "B")
    border = [r for r in rows if r["reached_tier2"]]
    bA, bB = (confusion(border, "A"), confusion(border, "B")) if border else (None, None)
    y = [1 if r["truth"] == "phishing" else 0 for r in rows]
    ece, bins = ece_and_bins(y, [r["prob"] for r in rows])
    auto = n - fun["human"]
    metrics = {"set": name, "stamp": stamp, "n": n, "phishing": sum(y), "benign": n - sum(y),
               "funnel_counts": fun, "funnel_pct": {k: round(100 * v / n, 1) for k, v in fun.items()},
               "system_A_forced_guess": A, "system_B_full": B,
               "borderline_only": {"n": len(border), "A": bA, "B": bB},
               "calibration": {"ece": round(ece, 4), "bins": bins},
               "analyst_time_saved": {"auto_resolved": auto, "assumed_minutes_per_email": a.minutes,
                                      "hours_saved": round(auto * a.minutes / 60, 1),
                                      "note": "minutes per email is an ASSUMPTION, not a measurement"}}

    out = os.path.join(a.out, name); os.makedirs(out, exist_ok=True)
    json.dump(metrics, open(os.path.join(out, "metrics.json"), "w"), indent=2)

    # ---- charts ----
    plt.rcParams.update({"figure.facecolor": "white", "axes.spines.top": False, "axes.spines.right": False})
    foot = f"{name} set, n={n} | {stamp}"

    fig, ax = plt.subplots(figsize=(6, 3.2))
    labels = ["Tier 0\nrules", "Tier 1\nscore", "Tier 2\ninvestigate", "Human\nanalyst"]
    vals = [fun["tier0"], fun["tier1"], fun["tier2"], fun["human"]]
    bars = ax.bar(labels, [100 * v / n for v in vals], color=["#0891b2", "#0e7490", "#f59e0b", "#dc2626"])
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 1, f"{v}", ha="center", fontsize=9)
    ax.set_ylabel("% of reports resolved here"); ax.set_title("Tier funnel"); fig.text(0.01, 0.01, foot, fontsize=7, color="#b91c1c" if a.synthetic else "#555")
    fig.tight_layout(rect=(0, 0.04, 1, 1)); fig.savefig(os.path.join(out, "funnel.png"), dpi=160); plt.close(fig)

    fig, ax = plt.subplots(figsize=(6.4, 3.6))
    cats = ["Missed attacks\n(false negatives)", "Legit mail blocked\n(false positives)", "Sent to human\n(no guess)"]
    src = bA if bA else A
    srcB = bB if bB else B
    va = [src["fn"], src["fp"], 0]
    vb = [srcB["fn"], srcB["fp"], srcB["to_human_phish"] + srcB["to_human_benign"]]
    x = range(3)
    ax.bar([i - 0.2 for i in x], va, 0.4, label="Without Tier 2 (forced yes/no)", color="#94a3b8")
    ax.bar([i + 0.2 for i in x], vb, 0.4, label="With Tier 2 (PhishSentinel)", color="#0891b2")
    for i in x:
        ax.text(i - 0.2, va[i] + 0.1, va[i], ha="center", fontsize=9); ax.text(i + 0.2, vb[i] + 0.1, vb[i], ha="center", fontsize=9)
    ax.set_xticks(list(x)); ax.set_xticklabels(cats, fontsize=8); ax.legend(fontsize=8, frameon=False)
    ax.set_title(f"Borderline emails only (n={len(border)}): with vs without Tier 2", fontsize=10)
    fig.text(0.01, 0.01, foot, fontsize=7, color="#b91c1c" if a.synthetic else "#555")
    fig.tight_layout(rect=(0, 0.04, 1, 1)); fig.savefig(os.path.join(out, "with_without_tier2.png"), dpi=160); plt.close(fig)

    fig, ax = plt.subplots(figsize=(4.2, 4.2))
    ax.plot([0, 1], [0, 1], "--", color="#94a3b8", label="perfect")
    if bins:
        ax.plot([b["mean_pred"] for b in bins], [b["frac_phishing"] for b in bins], "o-", color="#0891b2", label=f"ours (ECE {ece:.3f})")
    ax.set_xlabel("predicted P(phishing)"); ax.set_ylabel("observed fraction phishing"); ax.legend(fontsize=8, frameon=False)
    ax.set_title("Reliability curve", fontsize=10); fig.text(0.01, 0.01, foot, fontsize=6, color="#b91c1c" if a.synthetic else "#555")
    fig.tight_layout(rect=(0, 0.04, 1, 1)); fig.savefig(os.path.join(out, "reliability.png"), dpi=160); plt.close(fig)

    md = [f"# Evaluation: {name}", f"**{stamp}**  |  n={n} ({metrics['phishing']} phishing, {metrics['benign']} benign)", "",
          "| System | Precision | Recall (auto) | F1 | FP rate | Missed | Blocked legit | To human |", "|---|---|---|---|---|---|---|---|"]
    for label, m in (("A: Tier 0+1, forced yes/no", A), ("B: full (Tier 0+1+2)", B)):
        md.append(f"| {label} | {m['precision']} | {m['recall_auto']} | {m['f1']} | {m['false_positive_rate']} | {m['fn']} | {m['fp']} | {m['sent_to_human_pct']}% |")
    md += ["", f"Funnel: {metrics['funnel_pct']}", f"Calibration ECE: {metrics['calibration']['ece']}",
           f"Analyst time saved: {auto} auto-resolved x {a.minutes} min (ASSUMED) = {metrics['analyst_time_saved']['hours_saved']} h"]
    open(os.path.join(out, "metrics.md"), "w").write("\n".join(md) + "\n")
    print("\n".join(md)); print(f"\nsaved to {out}/")


if __name__ == "__main__":
    main()
