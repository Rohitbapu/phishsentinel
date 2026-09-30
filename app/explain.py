"""Optional plain-English case note written by a LOCAL LLM (Ollama). Off by default: set PS_LLM=1.

Design rules (why this is safe to demo):
  * The model sees ONLY the verdict and the structured evidence list. It never sees the email subject or body,
    so text inside a phishing email cannot inject instructions into it.
  * It can never change the verdict, confidence, actions or campaign: it only fills `reports.explanation`.
  * Everything fails soft: Ollama down, slow or returning junk means no note, and triage is unaffected.
  * Data stays on the machine (default http://127.0.0.1:11434).

Setup:  install Ollama, then  `ollama pull qwen2.5:7b-instruct`   (or llama3.1:8b; set PS_LLM_MODEL)
"""
import json, os, urllib.request

# CHANGED FOR HACKATHON: Forced True so it runs without environment variables
ENABLED = True
OLLAMA = os.environ.get("PS_OLLAMA", "http://127.0.0.1:11434").rstrip("/")
# CHANGED FOR HACKATHON: Set default to qwen2.5:latest to match your local setup
MODEL = os.environ.get("PS_LLM_MODEL", "qwen2.5:latest")
TIMEOUT = 60.0

PROMPT = """You write short case notes for a security analyst who triages reported emails.
Rules:
- Use ONLY the evidence listed below. Do not invent facts, names, or domains that are not listed.
- Do NOT change or question the verdict. Explain why the evidence supports it.
- Write 2 or 3 plain-English sentences. No bullet points, no headings, no advice to the reader.
- Positive weights push toward phishing, negative weights toward safe.

Verdict: {verdict} ({conf:.0%} confidence)
Evidence:
{lines}

Case note:"""

def build_prompt(verdict, confidence, evidence):
    top = sorted(evidence, key=lambda e: -abs(e["weight"]))[:8]
    lines = "\n".join(f"- [{e['agent']}] {str(e['detail'])[:160]} (weight {e['weight']:+})" for e in top) or "- (no evidence)"
    return PROMPT.format(verdict=verdict.replace("_", " "), conf=confidence, lines=lines)

def summarize(verdict, confidence, evidence):
    """Return a short note or None. Never raises."""
    if not ENABLED:
        return None
    try:
        body = json.dumps({"model": MODEL, "prompt": build_prompt(verdict, confidence, evidence), "stream": False,
                           "options": {"temperature": 0.2, "num_predict": 160}}).encode()
        req = urllib.request.Request(OLLAMA + "/api/generate", data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
        text = (json.load(urllib.request.urlopen(req, timeout=TIMEOUT)).get("response") or "").strip()
        return text[:600] if len(text) >= 20 else None
    except Exception:
        return None

# --- NEW: Added exclusively for the Chrome Extension Live Scanner ---
def generate_explanation(prompt_text):
    """Synchronous summarization for the Extension's Recolour Flag."""
    if not ENABLED: return "Local LLM is disabled."
    try:
        body = json.dumps({
            "model": MODEL, 
            "prompt": prompt_text, 
            "stream": False,
            "options": {"temperature": 0.2, "num_predict": 100}
        }).encode()
        req = urllib.request.Request(OLLAMA + "/api/generate", data=body, method="POST", headers={"Content-Type": "application/json"})
        text = (json.load(urllib.request.urlopen(req, timeout=TIMEOUT)).get("response") or "").strip()
        return text
    except Exception as e:
        return f"LLM Error: Is Ollama running {MODEL}? ({e})"