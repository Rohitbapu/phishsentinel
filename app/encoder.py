"""Optional transformer text model for Tier 1 (uses the GPU when present, CPU otherwise).

Load order: env PS_ENCODER_DIR, else models/encoder/  (written by tools/finetune_encoder.py).
Set PS_ENCODER=0 to disable it and fall back to the TF-IDF model / rules.

calibration.json (next to the weights) holds Platt scaling fitted on OUR validation split:
    p = sigmoid(a * (logit_phish - logit_legit) + b)
If it is missing (e.g. a downloaded checkpoint) the output is UNCALIBRATED (a=1, b=0) and status() says so.
Everything here fails soft: any problem returns None and Tier 1 silently uses its other scorers.
"""
import json, math, os, threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIR = os.environ.get("PS_ENCODER_DIR", os.path.join(ROOT, "models", "encoder"))
_S = {"loaded": False, "tok": None, "model": None, "dev": None, "a": 1.0, "b": 0.0, "phish": 1,
      "max_len": 512, "calibrated": False, "error": None}
_lock = threading.Lock()

def _sigmoid(x):
    return 1 / (1 + math.exp(-max(-30.0, min(30.0, x))))

def enabled():
    return os.environ.get("PS_ENCODER", "1") != "0" and os.path.isdir(DIR)

def _load():
    with _lock:
        if _S["loaded"]:
            return
        _S["loaded"] = True
        if not enabled():
            return
        try:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
            dev = "cuda" if torch.cuda.is_available() else "cpu"
            _S["tok"] = AutoTokenizer.from_pretrained(DIR)
            _S["model"] = AutoModelForSequenceClassification.from_pretrained(DIR).to(dev).eval()
            _S["dev"] = dev
            cal = os.path.join(DIR, "calibration.json")
            if os.path.exists(cal):
                c = json.load(open(cal))
                _S.update(a=float(c.get("a", 1.0)), b=float(c.get("b", 0.0)), phish=int(c.get("phish_index", 1)),
                          max_len=int(c.get("max_len", 512)), calibrated=True)
        except Exception as exc:  # missing torch/transformers, bad weights, out of memory...
            _S["model"], _S["error"] = None, str(exc)[:200]

def predict(text):
    """Calibrated P(phishing) in [0,1], or None if the encoder is unavailable."""
    _load()
    if _S["model"] is None:
        return None
    try:
        import torch
        enc = _S["tok"](text, truncation=True, max_length=_S["max_len"], return_tensors="pt").to(_S["dev"])
        with torch.inference_mode(), torch.autocast(device_type="cuda", dtype=torch.bfloat16, enabled=_S["dev"] == "cuda"):
            lg = _S["model"](**enc).logits[0].float().cpu()
        ph = _S["phish"]
        z = float(lg[ph] - lg[1 - ph])
        return _sigmoid(_S["a"] * z + _S["b"])
    except Exception as exc:
        _S["error"] = str(exc)[:200]
        return None

def status():
    _load()
    return {"enabled": enabled(), "loaded": _S["model"] is not None, "device": _S["dev"],
            "calibrated": _S["calibrated"], "error": _S["error"], "dir": DIR}
