"""Train + calibrate the Tier 1 text model.

  python -m tools.train_tier1 data/emails.csv            # CSV columns: text,label   (1 = phishing, 0 = legitimate)
  python -m tools.train_tier1 data/emails.csv --out models

Writes models/tier1.joblib and models/calibration.json (Platt scaling fitted on a held-out validation split),
then prints test-set precision / recall / F1, Brier score and expected calibration error (ECE) before and after
calibration. Report THESE numbers, from your own held-out data, in the deck.
"""
import argparse, csv, json, math, os, sys
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import brier_score_loss, precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
import joblib

def logit(p):
    p = np.clip(p, 1e-4, 1 - 1e-4)
    return np.log(p / (1 - p))

def ece(y, p, bins=10):
    edges, e = np.linspace(0, 1, bins + 1), 0.0
    for lo, hi in zip(edges[:-1], edges[1:]):
        m = (p >= lo) & (p < hi if hi < 1 else p <= hi)
        if m.any():
            e += m.mean() * abs(y[m].mean() - p[m].mean())
    return float(e)

def report(name, y, p):
    pr, rc, f1, _ = precision_recall_fscore_support(y, p >= 0.5, average="binary", zero_division=0)
    print(f"{name:12s} precision={pr:.3f} recall={rc:.3f} F1={f1:.3f} Brier={brier_score_loss(y, p):.4f} ECE={ece(y, p):.4f}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("csv"); ap.add_argument("--out", default="models")
    ap.add_argument("--export-test", default=None, help="write the untouched TEST split as .eml folders for tools.evaluate (e.g. data/eval)")
    a = ap.parse_args()
    csv.field_size_limit(sys.maxsize)
    X, y = [], []
    with open(a.csv, newline="", encoding="utf-8", errors="ignore") as f:
        for row in csv.DictReader(f):
            X.append(row["text"]); y.append(int(row["label"]))
    y = np.array(y)
    Xtr, Xtmp, ytr, ytmp = train_test_split(X, y, test_size=0.4, stratify=y, random_state=42)
    Xva, Xte, yva, yte = train_test_split(Xtmp, ytmp, test_size=0.5, stratify=ytmp, random_state=42)
    pipe = make_pipeline(TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=50000, sublinear_tf=True),
                         LogisticRegression(max_iter=2000))
    pipe.fit(Xtr, ytr)
    lv = logit(pipe.predict_proba(Xva)[:, 1]).reshape(-1, 1)
    platt = LogisticRegression(C=1e6).fit(lv, yva)
    a_, b_ = float(platt.coef_[0][0]), float(platt.intercept_[0])
    raw = pipe.predict_proba(Xte)[:, 1]
    cal = 1 / (1 + np.exp(-(a_ * logit(raw) + b_)))
    report("uncalibrated", yte, raw); report("calibrated", yte, cal)
    os.makedirs(a.out, exist_ok=True)
    joblib.dump(pipe, os.path.join(a.out, "tier1.joblib"))
    json.dump({"a": a_, "b": b_}, open(os.path.join(a.out, "calibration.json"), "w"))
    if a.export_test:
        from email.message import EmailMessage
        for lab in ("phishing", "benign"):
            os.makedirs(os.path.join(a.export_test, lab), exist_ok=True)
        for i, (t, l) in enumerate(zip(Xte, yte)):
            m = EmailMessage(); m["From"] = "unknown@unknown.invalid"; m["Subject"] = ""; m.set_content(t)
            lab = "phishing" if l == 1 else "benign"
            open(os.path.join(a.export_test, lab, f"{i:05d}.eml"), "wb").write(m.as_bytes())
        print(f"exported {len(Xte)} held-out test emails to {a.export_test}/  ->  python -m tools.evaluate --dir {a.export_test}")
    print(f"saved to {a.out}/  (Platt a={a_:.3f}, b={b_:.3f}; train/val/test = {len(ytr)}/{len(yva)}/{len(yte)})")
