"""Fine-tune + calibrate a transformer encoder for Tier 1 (built for one 16 GB GPU, e.g. RTX 5060 Ti).

  python -m tools.finetune_encoder data/emails.csv                          # roberta-base, 3 epochs
  python -m tools.finetune_encoder data/emails.csv --model microsoft/deberta-v3-base --bs 16
  python -m tools.finetune_encoder data/emails.csv --max-rows 2000 --epochs 1   # quick smoke test first!
  python -m tools.finetune_encoder data/emails.csv --export-test data/eval  # also write held-out .eml folders

CSV columns: text,label   (1 = phishing, 0 = legitimate).  Train BODY TEXT only (strip headers) so the model
learns phishing language rather than dataset artefacts.  Remove near-duplicates BEFORE training.

Uses the SAME 60/20/20 split and seed as tools.train_tier1, so both models are scored on the identical test set.
Writes models/encoder/ (weights, tokenizer, calibration.json). The server picks it up automatically.

GPU note: an RTX 50-series card (Blackwell) needs a PyTorch build with CUDA 12.8 or newer, e.g.
  pip install torch --index-url https://download.pytorch.org/whl/cu128
If torch.cuda.is_available() prints False, that is almost always the reason.
"""
import argparse, csv, json, os, random, sys, time

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split

from tools.train_tier1 import ece, logit, report


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv")
    ap.add_argument("--model", default="roberta-base", help="any HF encoder: roberta-base, bert-base-uncased, microsoft/deberta-v3-base ...")
    ap.add_argument("--out", default="models/encoder")
    ap.add_argument("--epochs", type=int, default=3)
    ap.add_argument("--bs", type=int, default=16)
    ap.add_argument("--lr", type=float, default=2e-5)
    ap.add_argument("--max-len", type=int, default=256, help="256 is fast; 512 is slower but sees more of long emails")
    ap.add_argument("--max-rows", type=int, default=0, help="use only N rows (smoke test)")
    ap.add_argument("--export-test", default=None, help="write the untouched TEST split as .eml folders for tools.evaluate")
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()

    import torch
    from torch.utils.data import DataLoader
    from transformers import AutoModelForSequenceClassification, AutoTokenizer, get_linear_schedule_with_warmup

    random.seed(a.seed); np.random.seed(a.seed); torch.manual_seed(a.seed)
    dev = "cuda" if torch.cuda.is_available() else "cpu"
    print("device:", dev, "|", torch.cuda.get_device_name(0) if dev == "cuda" else "NO GPU (see the GPU note at the top of this file)")

    csv.field_size_limit(sys.maxsize)
    X, y = [], []
    with open(a.csv, newline="", encoding="utf-8", errors="ignore") as f:
        for row in csv.DictReader(f):
            X.append(row["text"]); y.append(int(row["label"]))
    if a.max_rows:
        idx = list(range(len(X))); random.Random(a.seed).shuffle(idx); idx = idx[:a.max_rows]
        X, y = [X[i] for i in idx], [y[i] for i in idx]
    y = np.array(y)
    # identical split to tools.train_tier1
    Xtr, Xtmp, ytr, ytmp = train_test_split(X, y, test_size=0.4, stratify=y, random_state=42)
    Xva, Xte, yva, yte = train_test_split(Xtmp, ytmp, test_size=0.5, stratify=ytmp, random_state=42)
    print(f"train/val/test = {len(ytr)}/{len(yva)}/{len(yte)}")

    tok = AutoTokenizer.from_pretrained(a.model)
    model = AutoModelForSequenceClassification.from_pretrained(a.model, num_labels=2).to(dev)

    def collate(batch):
        enc = tok([t for t, _ in batch], truncation=True, max_length=a.max_len, padding=True, return_tensors="pt")
        enc["labels"] = torch.tensor([int(l) for _, l in batch])
        return enc

    tr_dl = DataLoader(list(zip(Xtr, ytr)), batch_size=a.bs, shuffle=True, collate_fn=collate)
    steps = len(tr_dl) * a.epochs
    opt = torch.optim.AdamW(model.parameters(), lr=a.lr, weight_decay=0.01)
    sched = get_linear_schedule_with_warmup(opt, int(0.06 * steps), steps)
    amp = dict(device_type="cuda", dtype=torch.bfloat16, enabled=(dev == "cuda"))

    @torch.no_grad()
    def margins(texts):
        """logit(phishing) - logit(legit) for every text, in order."""
        model.eval(); out = []
        for i in range(0, len(texts), 64):
            enc = tok(texts[i:i + 64], truncation=True, max_length=a.max_len, padding=True, return_tensors="pt").to(dev)
            with torch.autocast(**amp):
                lg = model(**enc).logits.float().cpu()
            out += (lg[:, 1] - lg[:, 0]).tolist()
        return np.array(out)

    def logloss(y_, z):
        p = np.clip(1 / (1 + np.exp(-z)), 1e-6, 1 - 1e-6)
        return float(-np.mean(y_ * np.log(p) + (1 - y_) * np.log(1 - p)))

    best, best_state, t0, step = 1e9, None, time.time(), 0
    for ep in range(1, a.epochs + 1):
        model.train()
        for batch in tr_dl:
            batch = {k: v.to(dev) for k, v in batch.items()}
            with torch.autocast(**amp):
                loss = model(**batch).loss
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step(); sched.step(); opt.zero_grad(set_to_none=True); step += 1
            if step % 50 == 0:
                print(f"  epoch {ep} step {step}/{steps} loss {loss.item():.4f}  ({time.time() - t0:.0f}s)", flush=True)
        vl = logloss(yva, margins(Xva))
        print(f"epoch {ep}: validation log-loss {vl:.4f}")
        if vl < best:
            best = vl; best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
    model.load_state_dict(best_state)

    # ---- calibration (Platt scaling on the VALIDATION split) + honest test-set numbers ----
    zv, zt = margins(Xva), margins(Xte)
    platt = LogisticRegression(C=1e6).fit(zv.reshape(-1, 1), yva)
    a_, b_ = float(platt.coef_[0][0]), float(platt.intercept_[0])
    raw = 1 / (1 + np.exp(-zt)); cal = 1 / (1 + np.exp(-(a_ * zt + b_)))
    report("uncalibrated", yte, raw); report("calibrated", yte, cal)

    os.makedirs(a.out, exist_ok=True)
    model.save_pretrained(a.out); tok.save_pretrained(a.out)
    json.dump({"a": a_, "b": b_, "phish_index": 1, "max_len": a.max_len, "base_model": a.model,
               "split": [len(ytr), len(yva), len(yte)], "test_ece": round(ece(yte, cal), 4)},
              open(os.path.join(a.out, "calibration.json"), "w"), indent=2)
    print(f"saved to {a.out}/  (Platt a={a_:.3f}, b={b_:.3f}; {time.time() - t0:.0f}s total)")

    if a.export_test:
        from email.message import EmailMessage
        for lab in ("phishing", "benign"):
            os.makedirs(os.path.join(a.export_test, lab), exist_ok=True)
        for i, (t, l) in enumerate(zip(Xte, yte)):
            m = EmailMessage(); m["From"] = "unknown@unknown.invalid"; m["Subject"] = ""; m.set_content(t)
            open(os.path.join(a.export_test, "phishing" if l == 1 else "benign", f"{i:05d}.eml"), "wb").write(m.as_bytes())
        print(f"exported {len(Xte)} test emails -> python -m tools.evaluate --dir {a.export_test}")


if __name__ == "__main__":
    main()
