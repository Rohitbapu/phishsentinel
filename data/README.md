# Data layout (for Praveen)

## 1. Training CSV (Tier 1 text model)
`data/emails.csv` with columns `text,label` (1 = phishing, 0 = legitimate).
```
python -m tools.train_tier1 data/emails.csv --export-test data/eval
```
This splits 60/20/20 (train/validation/test), fits the model, calibrates it on validation, prints metrics on the
untouched test split and writes that test split to `data/eval/{phishing,benign}/*.eml`.
Remove near-duplicates from the CSV BEFORE training, otherwise the test numbers are inflated by leakage.

## 2. Evaluation sets (folders of .eml)
```
data/eval/phishing/*.eml    data/eval/benign/*.eml     # standard held-out test
data/hard/phishing/*.eml    data/hard/benign/*.eml     # 150-300 borderline emails
data/adversarial/...                                    # AI-written phish, look-alike domains, QR links
```
Run each: `python -m tools.evaluate --dir data/hard --name hard --minutes 5`
Outputs go to `eval_out/<name>/` (metrics.json, metrics.md, funnel.png, with_without_tier2.png, reliability.png).

## 3. Hard set ideas (these break simple classifiers)
Urgent but legitimate HR/IT mail, real password resets, aggressive marketing, well-written phishing with no links,
BEC from free-mail with a role name, benign look-alike domains, authenticated mail from unknown vendors.
Keep real .eml headers (Authentication-Results, Reply-To) where you can: Tier 0 and the header agent depend on them.

## 4. Rules
- Check each dataset's licence before use and note it in the README.
- No number goes into the deck unless it came from `tools.evaluate` on a real labelled set.
- `--minutes` (manual minutes per email) is an ASSUMPTION; say so on the slide.
