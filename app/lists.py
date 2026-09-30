"""Data-driven Tier 0 lists: drop files into data/lists/ (or PS_LISTS_DIR) instead of editing code.

  known_bad*.txt|csv   any file whose name starts with known_bad: one domain or URL per line, or a raw feed
                       (OpenPhish, PhishTank CSV, ...). URLs are reduced to their registered domain. '#' comments ok.
  allow*.txt           domains YOUR ORGANISATION trusts. Keep it small and vetted. Do NOT paste a top-sites list:
                       attackers host phishing on big domains, and an allow-list entry auto-releases mail.
  brands.json          {"paypal": ["paypal.com", ...]}  extends the built-in brand map used for look-alike detection.

Safety: feeds often contain phishing pages hosted on SHARED platforms (github.io, blogspot.com, sites.google.com ...).
Blocking the whole registered domain would block every innocent tenant, so those, anything on the allow-list, and
every real brand domain are skipped and counted in status()["skipped"].
"""
import glob, json, os, re

from .parser import host_of, registered_domain

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIR = os.environ.get("PS_LISTS_DIR", os.path.join(ROOT, "data", "lists"))

SHARED_HOSTS = {"github.io", "githubusercontent.com", "blogspot.com", "wordpress.com", "weebly.com", "wixsite.com", "wix.com",
                "netlify.app", "vercel.app", "pages.dev", "workers.dev", "web.app", "firebaseapp.com", "herokuapp.com",
                "glitch.me", "repl.co", "google.com", "googleapis.com", "googleusercontent.com", "sharepoint.com",
                "dropbox.com", "onedrive.live.com", "live.com", "microsoft.com", "amazonaws.com", "azurewebsites.net",
                "cloudfront.net", "notion.site", "canva.com", "typeform.com", "forms.gle", "bit.ly", "tinyurl.com", "t.co"}
_URL = re.compile(r"https?://[^\s,\"'<>]+", re.I)
_DOM = re.compile(r"^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$")
_STATE = {"skipped": 0, "files": []}

def _read_domains(path):
    out = set()
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            urls = _URL.findall(line)
            hosts = [host_of(u) for u in urls] if urls else [t for t in re.split(r"[,\s;]+", line) if "." in t][:1]
            for h in hosts:
                h = (h or "").lower().strip(".")
                if _DOM.match(h):
                    reg = registered_domain(h)
                    if reg:
                        out.add(reg)
    return out

def load(builtin_brands=None):
    """Return {"known_bad": set, "allow": set, "brands": dict}. Never raises on bad files."""
    res = {"known_bad": set(), "allow": set(), "brands": {}}
    _STATE.update(skipped=0, files=[])
    if not os.path.isdir(DIR):
        return res
    for kind, pattern in (("known_bad", "known_bad*"), ("allow", "allow*")):
        for path in sorted(glob.glob(os.path.join(DIR, pattern))):
            if path.endswith(".md") or os.path.isdir(path):
                continue
            try:
                res[kind] |= _read_domains(path); _STATE["files"].append(os.path.basename(path))
            except Exception:
                pass
    bj = os.path.join(DIR, "brands.json")
    if os.path.exists(bj):
        try:
            res["brands"] = {k.lower(): [d.lower() for d in v] for k, v in json.load(open(bj)).items()}
        except Exception:
            pass
    protected = set(SHARED_HOSTS) | res["allow"]
    for reals in list((builtin_brands or {}).values()) + list(res["brands"].values()):
        protected |= set(reals)
    kept = {d for d in res["known_bad"] if d not in protected}
    _STATE["skipped"] = len(res["known_bad"]) - len(kept)
    res["known_bad"] = kept
    return res

def status(known_bad=0, allow=0):
    return {"dir": DIR, "files": _STATE["files"], "known_bad": known_bad, "allow": allow, "skipped_shared_or_protected": _STATE["skipped"]}
