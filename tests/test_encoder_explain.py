"""Tests for the transformer hook and the local-LLM note, using stand-ins (no GPU / torch / Ollama needed).
   python -m tests.test_encoder_explain"""
import json, os, random, subprocess, sys, tempfile, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
os.environ["PS_DB"] = os.path.join(tempfile.mkdtemp(), "t.db")
from app import db, encoder, explain, parser, pipeline, tiers
from tools.replay import bec_freemail, phish_known

db.init()
def run_one(raw):
    rid = pipeline.ingest("emp@corp.test", raw); pipeline.process(rid)
    return db.one("SELECT * FROM reports WHERE id=?", (rid,))

# 1. encoder fails soft: no dir, then a dir with no weights / no torch
encoder.DIR = "/nonexistent"; encoder._S["loaded"] = False
assert encoder.predict("hello") is None and encoder.status()["loaded"] is False
d = tempfile.mkdtemp(); encoder.DIR = d; encoder._S.update(loaded=False, model=None)
assert encoder.predict("hello") is None            # dir exists but is empty: must not raise
print("encoder: fails soft (missing dir, bad weights)")

# 2. a transformer score flows into Tier 1 and is labelled in the evidence
p = parser.parse(bec_freemail(random.Random(1)))
base_p, base_ev = tiers.tier1(p)
orig = encoder.predict
encoder.predict = lambda text: 0.97
hi_p, hi_ev = tiers.tier1(p)
encoder.predict = lambda text: 0.03
lo_p, lo_ev = tiers.tier1(p)
encoder.predict = orig
ml = [e for e in hi_ev if e["agent"] == "ml"][0]
assert "transformer" in ml["detail"] and ml["weight"] > 0
assert lo_p < base_p < hi_p, (lo_p, base_p, hi_p)
print(f"tier1 with transformer: low={lo_p:.2f} < rules-only={base_p:.2f} < high={hi_p:.2f}")

# 3. fake Ollama: note is stored, verdict unchanged, and the email body/subject never reach the LLM
seen = []
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        seen.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
        out = json.dumps({"response": "The sender uses free mail with a role-style name and asks for bank details."}).encode()
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(out)
    def log_message(self, *a): pass
srv = HTTPServer(("127.0.0.1", 0), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
explain.OLLAMA, explain.ENABLED = f"http://127.0.0.1:{srv.server_port}", True
without = run_one(bec_freemail(random.Random(5)))          # ENABLED but server used: has a note
assert without["tier_resolved"] == 2 and without["explanation"], without
assert without["verdict"] == "phishing"
prompt = seen[-1]["prompt"]
assert "account number" not in prompt and "payroll" not in prompt.lower().split("evidence:")[0], "email text leaked into prompt"
assert "Update payroll bank details before Friday" not in prompt, "subject leaked into prompt"
print("llm note stored; verdict unchanged; email subject/body not sent to the LLM")

# 4. Tier 0/1 mail gets no LLM call; server down means no note and no error
n_before = len(seen)
run_one(phish_known(random.Random(3)))
assert len(seen) == n_before
srv.shutdown(); explain.OLLAMA = "http://127.0.0.1:1"
down = run_one(bec_freemail(random.Random(6)))
assert down["verdict"] == "phishing" and not down["explanation"] and down["status"] != "error"
explain.ENABLED = False
print("llm: skipped for cheap tiers, fails soft when Ollama is down")

# 5. fine-tune script parses its CLI without torch installed
r = subprocess.run([sys.executable, "-m", "tools.finetune_encoder", "--help"], capture_output=True, text=True)
assert r.returncode == 0 and "--export-test" in r.stdout, r.stderr[-300:]
print("finetune_encoder --help OK")
print("ALL OK")
