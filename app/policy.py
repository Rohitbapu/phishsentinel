"""Decision policy. Starting values: tune on the validation set, then report the final numbers."""
import json, os
T = {"auto_phish": 0.90, "auto_benign": 0.10, "final_phish": 0.80, "final_benign": 0.20}
OVERRIDE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "policy.json")

def load_overrides(path=OVERRIDE):
    """Apply thresholds written by tools/tune_thresholds.py (data/policy.json). Ignores unknown keys / bad files."""
    try:
        if os.path.exists(path):
            T.update({k: float(v) for k, v in json.load(open(path)).items() if k in T})
    except Exception:
        pass
    return dict(T)

load_overrides()

def positive_agents(evidence):
    return {e["agent"] for e in evidence if e["weight"] >= 0.5}

def stage1(p, evidence, parsed):
    """After Tier 1: settle only when clear AND corroborated, otherwise investigate."""
    if p >= T["auto_phish"] and len(positive_agents(evidence)) >= 2:
        return "phishing"
    authed = parsed["auth"]["dmarc"] == "pass" or parsed["auth"]["spf"] == "pass"
    if p <= T["auto_benign"] and authed and not positive_agents(evidence):
        return "benign"
    return "investigate"

def final(p):
    """After Tier 2: three states, so uncertainty is explicit instead of a coin-flip."""
    if p >= T["final_phish"]:
        return "phishing"
    if p <= T["final_benign"]:
        return "benign"
    return "needs_review"
