# Demo runbook (5 minutes)

**Setup (once):** `pip install -r requirements.txt`, then `python -m uvicorn app.main:app --host 127.0.0.1 --port 8000`.
Load the extension: chrome://extensions -> Developer mode -> Load unpacked -> `extension/`.
Keep the recorded backup video ready. Rehearse three times.

| Step | Do this | Audience sees |
|---|---|---|
| 0 | `python -m tools.replay --n 120 --reset --delay 0` in a second terminal, before going on stage if you like | Queue and counters fill |
| 1 Flood | Open http://127.0.0.1:8000 | Backlog counter climbing |
| 2 Cascade | Point at the tier funnel | Most reports resolved at Tier 0/1 |
| 3 Borderline | Click a `T2` or `Human` row | Evidence cards + plain-English rationale |
| 4 Campaign | Campaigns panel -> Quarantine all -> Undo one | Many reports = one incident |
| 5 Guardrail | Options page of the extension: set reporter to `ceo@corp.test`, report an email from /inbox | Status "held_for_approval", needs a human click |
| 5b Kill switch | Untick "Autonomy ON", replay a few more | Everything is held |
| 6 Numbers | Show `eval_out/<real set>/*.png` | With/without Tier 2, funnel, reliability curve |

Live extension moment: open http://127.0.0.1:8000/inbox, click an email, press "Report phishing", read the toast.
Fallback if the extension misbehaves: /inbox shows its own "Report phishing (no extension)" button; the dashboard has a paste box.
Reset between rehearsals: `python -m tools.replay --n 0 --reset`.
