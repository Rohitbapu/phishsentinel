"""python -m tests.test_lists_tune"""
import json, os, subprocess, sys, tempfile
from app import lists, parser, pipeline, policy, tiers

# 1. list loader: domains, URLs, PhishTank-style CSV rows, comments; shared hosts / brands / allow-list are protected
d = tempfile.mkdtemp()
open(os.path.join(d, "known_bad_feed.txt"), "w").write("""# comment
evil-login.top
http://bad-pay.click/verify?id=1
123,http://phish.example-kyc.xyz/login,2026-01-01,yes,online
http://someuser.github.io/paypal-login
https://www.paypal.com/x
corp-partner.com
""")
open(os.path.join(d, "allow_org.txt"), "w").write("corp-partner.com\n")
json.dump({"acmebank": ["acmebank.com"]}, open(os.path.join(d, "brands.json"), "w"))
lists.DIR = d
res = lists.load(tiers.BRAND_REAL)
assert res["known_bad"] == {"evil-login.top", "bad-pay.click", "example-kyc.xyz"}, res["known_bad"]
assert res["allow"] == {"corp-partner.com"} and res["brands"] == {"acmebank": ["acmebank.com"]}
assert lists.status()["skipped_shared_or_protected"] == 3   # github.io, paypal.com, allow-listed corp-partner.com
print("lists: feeds parsed; github.io / real brand / allow-listed domains NOT blocked")
lists.load(); lists.DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(lists.__file__))), "data", "lists")

# 2. a listed domain now resolves at Tier 0 (end to end through triage)
tiers.KNOWN_BAD.add("evil-login.top")
raw = b"From: Support <help@evil-login.top>\nTo: emp@corp.test\nSubject: Verify\nContent-Type: text/plain\n\nPlease verify at http://evil-login.top/a now"
r = pipeline.triage(parser.parse(raw))
assert r["verdict"] == "phishing" and r["tier"] == 0, r
tiers.KNOWN_BAD.discard("evil-login.top")
print("tier0: feed domain -> phishing at Tier 0")

# 3. policy overrides
orig = dict(policy.T)
p = os.path.join(d, "policy.json"); json.dump({"auto_phish": 0.95, "bogus": 1}, open(p, "w"))
assert policy.load_overrides(p)["auto_phish"] == 0.95 and "bogus" not in policy.T
open(p, "w").write("not json"); policy.load_overrides(p)          # bad file must not raise
policy.T.clear(); policy.T.update(orig)
print("policy: overrides applied, unknown keys and bad files ignored")

# 4. tuner runs, never writes for synthetic data, and leaves thresholds untouched
target = policy.OVERRIDE
had = os.path.exists(target)
out = subprocess.run([sys.executable, "-m", "tools.tune_thresholds", "--synthetic", "150", "--write"], capture_output=True, text=True)
assert out.returncode == 0, out.stderr[-400:]
assert "best vs current" in out.stdout and "synthetic runs never overwrite" in out.stdout
assert os.path.exists(target) == had
print("tuner: runs, synthetic never overwrites data/policy.json")
print("ALL OK")
