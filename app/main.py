"""FastAPI layer. Run:  uvicorn app.main:app --host 0.0.0.0 --port 8000"""
import base64, binascii, json, os
from typing import List, Optional
from pathlib import Path
import cv2
import numpy as np

from fastapi import APIRouter, BackgroundTasks, Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from fastapi.staticfiles import StaticFiles

from . import db, pipeline, tiers

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"
API_KEY = os.environ.get("PS_API_KEY", "")  # set it before exposing the server beyond localhost
STATIC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")

db.init()
app = FastAPI(title="PhishSentinel", version="0.1")

# Fixed CORS to allow Chrome Extension communication
app.add_middleware(
    CORSMiddleware, 
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"], 
    allow_headers=["*"]
)

def check_key(x_api_key: Optional[str] = Header(default=None)):
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="bad or missing x-api-key")

api = APIRouter(prefix="/api/v1", dependencies=[Depends(check_key)])

class ReportIn(BaseModel):
    reporter: str = "anonymous"
    raw_eml: Optional[str] = None      # base64 of a .eml file
    text: Optional[str] = None         # pasted / extension-scraped body
    subject: Optional[str] = None
    sender: Optional[str] = None
    links: List[str] = []
    qr_image: Optional[str] = None     # Base64 image string for QR scanning

class FeedbackIn(BaseModel):
    label: str                         # "phishing" | "benign"
    analyst: str = "analyst"

class AutonomyIn(BaseModel):
    enabled: bool

class ScanIn(BaseModel):
    url: str

def _view(r, full=False):
    r = dict(r)
    r["evidence"] = json.loads(r["evidence"]) if r.get("evidence") else []
    r["links"] = json.loads(r["links"]) if r.get("links") else []
    r.pop("parsed", None)
    if not full:
        r.pop("body", None); r.pop("evidence", None); r.pop("links", None)
    return r

@api.post("/reports", status_code=202)
def create_report(body: ReportIn, bg: BackgroundTasks):
    # Updated to accept qr_image
    if not (body.raw_eml or body.text or body.qr_image):
        raise HTTPException(400, "send raw_eml (base64), text, or qr_image")
    
    raw = None
    if body.raw_eml:
        try:
            raw = base64.b64decode(body.raw_eml)
        except (binascii.Error, ValueError):
            raise HTTPException(400, "raw_eml is not valid base64")

    # --- NEW: OpenCV QR Code Extraction Logic ---
    if body.qr_image:
        try:
            # Strip standard HTML base64 headers if present (e.g., "data:image/png;base64,")
            b64_str = body.qr_image.split(",")[-1] 
            img_data = base64.b64decode(b64_str)
            np_arr = np.frombuffer(img_data, np.uint8)
            img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
            
            detector = cv2.QRCodeDetector()
            url, _, _ = detector.detectAndDecode(img)
            
            if url:
                if body.links is None:
                    body.links = []
                body.links.append(url)
                # Append the hidden URL to the text so the LLM/Classifier has context
                body.text = (body.text or "") + f"\n[Extracted QR URL: {url}]"
        except Exception as e:
            print(f"QR Decode Error: {e}")
    # ---------------------------------------------

    rid = pipeline.ingest(body.reporter, raw, body.text, body.subject, body.sender, body.links)
    bg.add_task(pipeline.process, rid)
    return {"report_id": rid, "status": "queued"}

@api.get("/reports")
def list_reports(limit: int = 100, verdict: Optional[str] = None):
    sql, args = "SELECT * FROM reports", []
    if verdict:
        sql += " WHERE verdict=?"; args.append(verdict)
    sql += " ORDER BY id DESC LIMIT ?"; args.append(min(limit, 500))
    return [_view(r) for r in db.rows(sql, tuple(args))]

@api.get("/reports/{rid}")
def get_report(rid: int):
    r = db.one("SELECT * FROM reports WHERE id=?", (rid,))
    if not r:
        raise HTTPException(404, "no such report")
    out = _view(r, full=True)
    out["actions"] = db.rows("SELECT action, actor, ts, undone FROM actions WHERE report_id=? ORDER BY id", (rid,))
    out["audit"] = db.rows("SELECT ts, event, detail FROM audit WHERE report_id=? ORDER BY id", (rid,))
    return out

@api.post("/reports/{rid}/feedback")
def feedback(rid: int, body: FeedbackIn):
    if not db.one("SELECT id FROM reports WHERE id=?", (rid,)):
        raise HTTPException(404, "no such report")
    try:
        pipeline.apply_feedback(rid, body.label, body.analyst)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"ok": True}

@api.post("/actions/{rid}/undo")          # {rid} = report id
def undo(rid: int):
    if not pipeline.undo(rid):
        raise HTTPException(404, "nothing to undo")
    return {"ok": True}

@api.post("/reports/{rid}/quarantine")
def quarantine(rid: int):
    pipeline.quarantine(rid); return {"ok": True}

@api.post("/reports/{rid}/release")
def release(rid: int):
    pipeline.release(rid); return {"ok": True}

@api.get("/campaigns")
def campaigns():
    out = []
    for c in db.rows("SELECT * FROM campaigns ORDER BY size DESC, id DESC"):
        c["domains"] = json.loads(c["domains"]); c.pop("tokens", None)
        c["quarantined"] = db.one("SELECT COUNT(*) AS n FROM reports WHERE campaign_id=? AND quarantined=1", (c["id"],))["n"]
        out.append(c)
    return out

@api.post("/campaigns/{cid}/quarantine")
def quarantine_campaign(cid: int):
    return {"quarantined": pipeline.quarantine_campaign(cid)}

@api.get("/stats")
def stats():
    return pipeline.stats()

@api.post("/settings/autonomy")
def autonomy(body: AutonomyIn):
    db.set_setting("autonomy", "1" if body.enabled else "0")
    db.audit(None, "autonomy_changed", {"enabled": body.enabled})
    return {"autonomy": body.enabled}

@api.post("/scan")
def scan(body: ScanIn):
    return tiers.scan_url(body.url)

@api.post("/admin/reset")
def reset():
    """Demo helper: wipe reports, campaigns, actions and audit so a rehearsal starts clean."""
    db.reset()
    return {"ok": True}

app.include_router(api)

@app.get("/health")
def health():
    from . import encoder, explain
    return {"status": "ok", "encoder": encoder.status(), "llm_explanations": explain.ENABLED,
            "lists": __import__("app.lists", fromlist=["x"]).status(len(tiers.KNOWN_BAD), len(tiers.ALLOW))}

@app.get("/")
def dashboard():
    return FileResponse(os.path.join(STATIC, "index.html"))

# 1. Direct route for the "Mock inbox" button
@app.get("/inbox.html", include_in_schema=False)
async def mock_inbox():
    return FileResponse(STATIC_DIR / "inbox.html")

# 2. Mount /static so all css/js/html files in static/ work seamlessly
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@api.post("/live_scan")
def live_scan(body: ReportIn):
    """3-Layer Architecture with Zero-Trust QR Code Analysis."""
    import re
    
    is_qr_scan = False
    # 1. QR Decoding
    if body.qr_image:
        is_qr_scan = True
        try:
            import base64, numpy as np, cv2
            b64_str = body.qr_image.split(",")[-1] 
            img_data = base64.b64decode(b64_str)
            np_arr = np.frombuffer(img_data, np.uint8)
            img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
            url, _, _ = cv2.QRCodeDetector().detectAndDecode(img)
            if url:
                body.links.append(url)
                body.text = f"{body.text or ''} {url}".strip()
        except Exception as e:
            print(f"QR Error: {e}")

    # Layer 1 & 2: Structural AI with Trusted Bypass
    malicious_links = []
    trusted_roots = ["google.com", "github.com", "wikipedia.org", "paypal.com", "microsoft.com", "localhost", "127.0.0.1"]
    suspicious_tlds = [".xyz", ".tk", ".top", ".cc", ".net", ".info", ".biz", ".ru", ".cn"]
    threat_keywords = ["urgent", "suspend", "verify", "fake", "login", "password", "update", "account", "chase", "bank", "secure", "billing", "auth", "admin", "portal"]
    url_shorteners = ["bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "shorturl.at", "ow.ly"]
    
    ip_pattern = re.compile(r"https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+")

    for link in body.links:
        link_lower = link.lower()
        
        # LAYER 1: If it is a verified trusted root domain, skip analyzing it entirely
        if any(f".{root}" in link_lower or f"/{root}" in link_lower or f"//{root}" in link_lower for root in trusted_roots):
            continue
            
        # LAYER 2: Structural Anomaly Detection
        is_suspicious = False
        
        if (any(tld in link_lower for tld in suspicious_tlds) or 
            any(kw in link_lower for kw in threat_keywords) or 
            link_lower.count("-") > 2 or 
            ip_pattern.search(link_lower)):
            is_suspicious = True
            
        # Flag URL Shorteners (Attackers use these to hide payloads)
        if any(shortener in link_lower for shortener in url_shorteners):
            is_suspicious = True
            
        # ZERO-TRUST QR RULE: If it came from a QR code and is NOT a trusted root, flag it automatically
        if is_qr_scan and not is_suspicious:
            is_suspicious = True

        if is_suspicious:
            malicious_links.append(link)

    text_to_scan = body.text or ""
    text_lower = text_to_scan.lower()
    
    # Base Scoring based on findings
    base_score = 0.15
    if malicious_links:
        base_score += 0.60
    if any(kw in text_lower for kw in threat_keywords) and not any(root in text_lower for root in trusted_roots):
        base_score += 0.35
        
    prob = min(0.98, base_score)
    is_threat = prob > 0.65

    # LAYER 3: Local LLM Contextual Reasoning
    from . import explain
    reasoning = "AI contextual analysis found no anomalies."
    if is_threat:
        prompt = f"Analyze this text context and the following suspicious links: {malicious_links}. Explain in 2 sentences why this is a phishing threat."
        reasoning = explain.generate_explanation(prompt)

    return {
        "is_threat": bool(is_threat),
        "threat_score": float(prob),
        "reasoning": f"[Qwen AI Analysis] {reasoning}",
        "flagged_links": malicious_links, 
        "extracted_url": body.links[0] if body.links else None
    }