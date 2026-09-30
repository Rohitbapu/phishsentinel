"""Tier 0 (fast rules), Tier 1 (score), Tier 2 (investigators) and the arbiter.

Every piece of evidence is {agent, signal, detail, weight}. weight is in logit points:
positive = pushes toward phishing, negative = pushes toward benign.
"""
import json, math, os, re
from . import encoder, lists
from .parser import registered_domain, host_of

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ---- demo lists: replace with real org data ----
KNOWN_BAD = {"secure-login-verify.xyz", "paypa1-secure.com", "micros0ft-support.top", "hdfc-netbanking-alert.click"}
ALLOW = {"vcet.edu.in", "github.com", "google.com", "microsoft.com", "linkedin.com", "amazon.com"}
FREEMAIL = {"gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "proton.me", "protonmail.com", "rediffmail.com"}
BRAND_REAL = {
    "paypal": ["paypal.com"], "microsoft": ["microsoft.com", "office.com", "live.com", "outlook.com", "office365.com", "microsoftonline.com", "sharepoint.com"],
    "google": ["google.com", "gmail.com", "goo.gl", "googleusercontent.com", "googleapis.com", "gstatic.com", "youtube.com"],
    "amazon": ["amazon.com", "amazon.in", "amazonaws.com"], "apple": ["apple.com", "icloud.com"],
    "hdfc": ["hdfcbank.com"], "sbi": ["sbi.co.in", "onlinesbi.sbi"], "icici": ["icicibank.com"],
    "netflix": ["netflix.com"], "linkedin": ["linkedin.com"], "github": ["github.com", "github.io"],
    "dropbox": ["dropbox.com"], "docusign": ["docusign.com", "docusign.net"],
    "instagram": ["instagram.com"], "facebook": ["facebook.com"],
}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly"}
BAD_TLDS = {"xyz", "top", "click", "link", "icu", "work", "gq", "tk", "ml", "cf", "zip", "mov", "rest", "monster"}
RISKY_EXT = (".exe", ".scr", ".js", ".vbs", ".iso", ".html", ".htm", ".lnk", ".docm", ".xlsm", ".zip", ".rar", ".jar")
_L = lists.load(BRAND_REAL)   # real feeds from data/lists/ extend the built-in starter sets
KNOWN_BAD |= _L["known_bad"]; ALLOW |= _L["allow"]
for _b, _r in _L["brands"].items():
    BRAND_REAL[_b] = sorted(set(BRAND_REAL.get(_b, [])) | set(_r))

URGENT = re.compile(r"\b(urgent|immediately|within 24 hours|final notice|action required|suspend(ed)?|last warning|expires? (today|soon)|verify (now|your)|act now|password expires)\b", re.I)
CRED = re.compile(r"\b(password|passcode|otp|login|log in|sign in|verify your (account|identity)|credentials|bank details|account number|card number|cvv|update your (account|payment|billing))\b", re.I)
PAY = re.compile(r"\b(wire transfer|gift ?cards?|invoice|payment|bitcoin|payroll|salary)\b", re.I)
IMPERSON = re.compile(r"\b(it (support|helpdesk)|help ?desk|hr department|payroll|ceo|administrator|security team|your bank)\b", re.I)

def sigmoid(x): return 1 / (1 + math.exp(-x))
def logit(p):
    p = min(max(p, 1e-4), 1 - 1e-4)
    return math.log(p / (1 - p))
def ev(agent, signal, detail, weight):
    return {"agent": agent, "signal": signal, "detail": detail, "weight": round(weight, 2)}

def link_domains(p):
    seen, out = set(), []
    for u in p["links"]:
        host = host_of(u)
        reg = registered_domain(host)
        if reg and reg not in seen:
            seen.add(reg)
            out.append((host, reg, u))
    return out

_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "$": "s"})
def lookalike(reg):
    if not reg or reg in ALLOW:
        return None
    if any(reg in reals for reals in BRAND_REAL.values()):
        return None
    n = reg.lower().translate(_LEET).replace("rn", "m").replace("vv", "w")
    tokens = re.split(r"[-.]", n)
    for brand, reals in BRAND_REAL.items():
        if brand in tokens or (len(brand) >= 5 and brand in n.replace("-", "")):
            return brand, reals[0]
    return None

# ------------------------------------------------ Tier 0
def tier0(p):
    doms = link_domains(p)
    for _, reg, _ in doms:
        if reg in KNOWN_BAD:
            return {"resolved": True, "verdict": "phishing", "p": 0.99,
                    "evidence": [ev("ioc", "known_bad_domain", f"{reg} is on the known-bad list", 4.0)]}
    sreg = registered_domain(p["sender_domain"])
    if (sreg in ALLOW and p["auth"]["dmarc"] == "pass" and not p["link_mismatches"]
            and all(reg in ALLOW or reg == sreg for _, reg, _ in doms)):
        return {"resolved": True, "verdict": "benign", "p": 0.02,
                "evidence": [ev("allowlist", "trusted_authenticated_sender", f"{sreg} is allow-listed and DMARC passed", -3.0)]}
    return {"resolved": False, "evidence": []}

# ------------------------------------------------ Tier 1
_model = {"loaded": False, "pipe": None, "cal": None}
def _load_model():
    if _model["loaded"]:
        return
    _model["loaded"] = True
    path = os.path.join(ROOT, "models", "tier1.joblib")
    if os.path.exists(path):
        try:
            import joblib
            _model["pipe"] = joblib.load(path)
        except Exception:
            _model["pipe"] = None
    cal = os.path.join(ROOT, "models", "calibration.json")
    if os.path.exists(cal):
        _model["cal"] = json.load(open(cal))

def tier1(p):
    _load_model()
    text = p["subject"] + " " + p["body"]
    parts = []
    urg, cred = len(URGENT.findall(text)), len(CRED.findall(text))
    if urg: parts.append(ev("lexical", "urgency_language", f"{urg} urgency phrase(s)", min(urg, 3) * 0.6))
    if cred: parts.append(ev("lexical", "credential_request", f"{cred} credential/payment-detail phrase(s)", min(cred, 2) * 0.8))
    if p["links"]: parts.append(ev("structure", "contains_links", f"{len(p['links'])} link(s)", 0.3))
    fails = [k for k, v in p["auth"].items() if v in ("fail", "softfail")]
    if fails: parts.append(ev("auth", "auth_failure", "failed: " + ", ".join(fails), 1.2))
    risky = [a["name"] for a in p["attachments"] if a["name"].lower().endswith(RISKY_EXT)]
    if risky: parts.append(ev("attachment", "risky_attachment", ", ".join(risky), 1.2))
    x = -2.4 + sum(e["weight"] for e in parts)
    pm, src = None, None
    try:
        pm = encoder.predict(text)          # transformer, calibrated on our validation split (GPU if available)
        src = "transformer"
    except Exception:
        pm = None
    if pm is None and _model["pipe"] is not None:   # fallback: TF-IDF model
        try:
            pm = float(_model["pipe"].predict_proba([text])[0][1])
            cal = _model["cal"]
            if cal:
                pm = sigmoid(cal.get("a", 1.0) * logit(pm) + cal.get("b", 0.0))
            src = "tf-idf"
        except Exception:
            pm = None
    if pm is not None:   # averaged with the rules score
        lm = max(-4.0, min(4.0, logit(pm)))
        parts.append(ev("ml", "text_model", f"{src} text model probability {pm:.2f}", lm))
        x = 0.5 * x + 0.5 * lm
    return sigmoid(x), parts

# ------------------------------------------------ Tier 2 investigators
def header_agent(p):
    out, sreg = [], registered_domain(p["sender_domain"])
    for k, w in (("dmarc", 1.6), ("spf", 1.0), ("dkim", 0.8)):
        if p["auth"][k] in ("fail", "softfail"):
            out.append(ev("header", f"{k}_fail", f"{k.upper()} check failed", w))
    if p["auth"]["dmarc"] == "pass":
        out.append(ev("header", "dmarc_pass", "DMARC passed", -0.6))
    rreg = registered_domain(p["reply_to_domain"])
    if rreg and sreg and rreg != sreg:
        out.append(ev("header", "reply_to_mismatch", f"Reply-To goes to {rreg} but sender is {sreg}", 1.2))
    rp = registered_domain(p["return_path_domain"])
    if rp and sreg and rp != sreg:
        out.append(ev("header", "return_path_mismatch", f"Return-Path {rp} differs from sender {sreg}", 0.8))
    name = p["sender_name"].lower()
    for brand, reals in BRAND_REAL.items():
        if brand in name and sreg not in reals:
            out.append(ev("header", "display_name_spoof", f"Display name mentions '{brand}' but sends from {sreg}", 1.4))
            break
    else:
        if sreg in FREEMAIL and re.search(r"\b(hr|it|payroll|admin|support|security|ceo|helpdesk)\b", name):
            out.append(ev("header", "role_name_on_freemail", f"Role-style sender name '{p['sender_name']}' on free mail ({sreg})", 1.2))
    return out

def url_agent(p):
    out, doms = [], link_domains(p)[:8]
    for host, reg, url in doms:
        if reg in KNOWN_BAD: out.append(ev("url", "known_bad_domain", f"{reg} is on the known-bad list", 3.0))
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host): out.append(ev("url", "ip_host", f"Link goes to raw IP {host}", 1.6))
        if "xn--" in host: out.append(ev("url", "punycode", f"{host} uses punycode (possible homoglyph)", 1.2))
        if reg in SHORTENERS: out.append(ev("url", "url_shortener", f"{reg} hides the real destination", 0.8))
        if host.rsplit(".", 1)[-1] in BAD_TLDS: out.append(ev("url", "risky_tld", f"{reg} uses a high-abuse TLD", 0.9))
        la = lookalike(reg)
        if la: out.append(ev("url", "lookalike_domain", f"{reg} imitates {la[0]} ({la[1]})", 2.0))
        if host.count(".") >= 4: out.append(ev("url", "deep_subdomain", f"{host} has many subdomain levels", 0.5))
    if any("@" in u.split("//", 1)[-1].split("/")[0] for u in p["links"]):
        out.append(ev("url", "userinfo_in_url", "A link contains user@host trickery", 1.2))
    for shown, href in p["link_mismatches"][:3]:
        out.append(ev("url", "link_text_mismatch", f"Link text shows '{shown}' but goes to {registered_domain(host_of(href))}", 1.8))
    if any(u.lower().startswith("http://") for u in p["links"]):
        out.append(ev("url", "no_https", "A link uses plain http", 0.4))
    if doms and all(reg in ALLOW for _, reg, _ in doms):
        out.append(ev("url", "trusted_links", "All links go to allow-listed domains", -0.8))
    return out

def intent_agent(p):
    out, text = [], p["subject"] + " " + p["body"]
    urg, cred, pay = len(URGENT.findall(text)), len(CRED.findall(text)), len(PAY.findall(text))
    if urg: out.append(ev("intent", "urgency", "Pressure to act quickly", 1.0 if urg > 1 else 0.6))
    if cred: out.append(ev("intent", "credential_request", "Asks for credentials or account details", 1.0))
    if pay: out.append(ev("intent", "payment_request", "Mentions payment, payroll or invoices", 0.8))
    if IMPERSON.search(text): out.append(ev("intent", "authority_impersonation", "Claims to be IT, HR, payroll or leadership", 0.6))
    if urg and cred: out.append(ev("intent", "urgent_credential_request", "Urgency combined with a credential request", 0.8))
    return out

def context_agent(p, prior):
    out = []
    b, ph = prior.get("benign", 0), prior.get("phish", 0)
    if ph >= 1: out.append(ev("context", "seen_in_phishing", "Sender domain appeared in an earlier phishing report", 1.5))
    elif b >= 2: out.append(ev("context", "known_sender", f"Sender domain seen {b} times as benign", -0.9))
    elif CRED.search(p["subject"] + " " + p["body"]) or PAY.search(p["body"]):
        out.append(ev("context", "first_contact_request", "First contact from this domain asking for details or money", 0.6))
    return out

def tier2(p, prior):
    return header_agent(p) + url_agent(p) + intent_agent(p) + context_agent(p, prior)

def fuse(p1, evidence2):
    x = logit(p1) + 0.8 * sum(e["weight"] for e in evidence2)
    return sigmoid(max(-7.0, min(7.0, x)))

def scan_url(url):
    """Quick link check for the paste box and the extension (same URL investigator as Tier 2)."""
    p = {"links": [url], "link_mismatches": []}
    ev_list = url_agent(p)
    score = int(round(sigmoid(-1.2 + sum(e["weight"] for e in ev_list)) * 100))
    level = "CRITICAL" if score >= 70 else "WARNING" if score >= 40 else "CAUTION" if score >= 15 else "SAFE"
    return {"url": url, "risk_score": score, "threat_level": level,
            "short_explanation": ev_list[0]["detail"] if ev_list else "No suspicious signals found",
            "heuristics_flagged": [e["detail"] for e in ev_list if e["weight"] > 0]}
