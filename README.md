# PhishSentinel: CS-02 Autonomous Phishing Email Triage

Investigate, don't guess. Every reported email goes through cheap checks first; unclear ones are investigated
(header, URL, intent, sender-context agents) before a verdict. Anything still unclear goes to an analyst as a case file.

## Run it (5 minutes)
```bash
pip install -r requirements.txt
python -m tests.test_pipeline              # 1) proves the core pipeline works (no web server needed)
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000     # 2) start server + dashboard
python -m tools.replay --n 80              # 3) in a second terminal: flood the queue with demo emails
```
Open http://127.0.0.1:8000 for the console. On Windows you can also double-click `run.bat`.

## What is where
| File | Purpose |
|---|---|
| `app/parser.py` | .eml or pasted text to one dict (headers, auth results, links, link-text mismatches, attachments) |
| `app/tiers.py` | Tier 0 rules, Tier 1 score, Tier 2 agents (header / url / intent / context), arbiter, `scan_url` |
| `app/policy.py` | Thresholds and the three-state decision (phishing / benign / needs_review) |
| `app/pipeline.py` | Orchestration, reversible actions, VIP + kill-switch guardrails, campaign grouping, audit log, stats |
| `app/main.py` | FastAPI endpoints (contract below) |
| `static/index.html` | Triage console: funnel, queue, case file with evidence, campaigns, paste/upload box, kill switch |
| `static/inbox.html` | Mock webmail page at `/inbox` for the demo (works with or without the extension) |
| `extension/` | Chrome MV3 extension: Report button on the mock inbox / Gmail / Outlook web, right-click link scan |
| `tools/evaluate.py` | Funnel, with vs without Tier 2, precision/recall/FPR, ECE + reliability curve, charts |
| `app/encoder.py` | Loads the fine-tuned transformer (GPU if present) and returns a calibrated P(phishing); fails soft |
| `app/explain.py` | Optional local-LLM (Ollama) case note; sees evidence only, never the email text; off unless `PS_LLM=1` |
| `tools/finetune_encoder.py` | Fine-tune + calibrate a transformer on your CSV (same split as `train_tier1`) |
| `app/lists.py` | Loads real Tier 0 feeds from `data/lists/` (with shared-host / brand / allow-list guards) |
| `tools/tune_thresholds.py` | Grid-searches the policy thresholds on a validation set with an explicit cost model; `--write` saves `data/policy.json` |
| `tools/replay.py` | Synthetic demo emails and bulk replay |
| `tools/train_tier1.py` | Train + calibrate the ML text model on your CSV; `--export-test` writes the held-out split for `evaluate.py` |
| `tests/test_pipeline.py` | End-to-end test of the logic |

## API (all under `/api/v1`, optional header `x-api-key` when `PS_API_KEY` is set)
- `POST /reports` `{reporter, raw_eml(base64) | text, subject, sender, links[]}` returns `{report_id, status:"queued"}`
- `GET /reports`, `GET /reports/{id}` (verdict, confidence, tier_resolved, evidence[], rationale, campaign_id, actions, audit)
- `POST /reports/{id}/feedback` `{label:"phishing"|"benign"}` (analyst confirm; also approves held VIP reports)
- `POST /actions/{report_id}/undo`, `POST /reports/{id}/quarantine`, `POST /reports/{id}/release`
- `GET /campaigns`, `POST /campaigns/{id}/quarantine`, `GET /stats`, `POST /settings/autonomy {enabled}`
- `POST /scan {url}` quick link check (same URL investigator as Tier 2)

### Extension hook (for the browser extension work)
```js
fetch(SERVER + "/api/v1/reports", {method:"POST", headers:{"Content-Type":"application/json","x-api-key":KEY},
  body: JSON.stringify({reporter: userEmail, sender: fromLine, subject, text: bodyText, links: hrefs})});
```
Keep `SERVER` in one config value. Set `PS_API_KEY` before exposing the server through any tunnel.

## Status: read this before the demo
**Verified in the build sandbox**
- `python -m tests.test_pipeline` passes: parser, all tiers, policy, campaigns, VIP hold, kill switch, rate limit, campaign quarantine, undo, Tier 2 ablation.
- `python -m tools.evaluate --synthetic 300` runs and writes metrics + 3 charts. `train_tier1 --export-test` -> `evaluate --dir` chain runs on toy data.
- Dashboard render code was run in Node against real pipeline output (queue, funnel, campaigns, case file, audit trail); extension JS and manifest pass syntax checks.

**NOT verified: do these on your laptop first (about 10 minutes)**
0. `app/encoder.py` and `tools/finetune_encoder.py` have never run against real PyTorch (none in the sandbox). Their logic is tested with stand-ins (`python -m tests.test_encoder_explain`); the GPU path, the Ollama call against a real model and the bf16 behaviour are unproven. Do the `--max-rows 2000 --epochs 1` smoke test first.
1. `app/main.py` has never been launched: FastAPI could not be installed in the sandbox (no network). Run the server; expect at most small typos.
2. The dashboard and `/inbox` have never been opened in a real browser.
3. The extension has never been loaded in Chrome (`chrome://extensions` -> Developer mode -> Load unpacked -> `extension/`). Gmail/Outlook selectors are best effort; use `/inbox` on stage.

**Numbers are not results.** The synthetic set uses templates we wrote, so its scores (near 1.0) only prove the plumbing. Real accuracy, calibration and the with/without Tier 2 chart must come from Praveen's labelled data and hard set. Every chart is stamped SYNTHETIC unless it was run on `--dir`.

**Placeholders to replace:** the built-in `KNOWN_BAD`/`ALLOW`/`BRAND_REAL` starter sets in `app/tiers.py` are tiny examples; add real feeds in `data/lists/` (see its README). Tier 1 is rule-based until a model is trained, and the rule score is not calibrated.

## Transformer model + local LLM (GPU)
```bash
pip install -r requirements.txt -r requirements-gpu.txt      # first install a CUDA 12.8+ torch for the RTX 5060 Ti (see requirements-gpu.txt)
python -m tools.finetune_encoder data/emails.csv --max-rows 2000 --epochs 1     # 1) smoke test, minutes
python -m tools.finetune_encoder data/emails.csv --export-test data/eval        # 2) real run (roberta-base by default)
python -m tools.evaluate --dir data/eval                                        # 3) honest held-out numbers
curl http://127.0.0.1:8000/health                                               # shows encoder loaded / device / calibrated
```
- The server uses `models/encoder/` automatically. To use a downloaded checkpoint instead, set `PS_ENCODER_DIR`; without our
  `calibration.json` its scores are UNCALIBRATED (`/health` says so), so calibrate before quoting anything.
- `PS_ENCODER=0` disables it (falls back to the TF-IDF model, then to rules only).
- Local LLM notes: install Ollama, `ollama pull qwen2.5:7b-instruct`, start the server with `PS_LLM=1`. The note appears as
  "AI case note" in the case file for Tier 2 / human-review reports only. It never changes a verdict.

## Next steps (in order)
1. Launch, replay, fix anything broken on the first run (Rohit). See `DEMO.md`.
2. Datasets into `data/` (format in `data/README.md`); train + calibrate Tier 1; run `tools.evaluate` on the test and hard sets (Praveen).
3. Tune thresholds: `python -m tools.tune_thresholds --dir data/val --write`, then run `tools.evaluate` ONCE on the test set. Record the final values and cost weights (never tune on test).
4. Real WHOIS/domain-age lookup with cached fallback, ATT&CK tags, local-LLM explanation text (COULD items).
