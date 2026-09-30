"""Turn a raw .eml (or pasted text + extension fields) into one normalised dict."""
import html as htmllib
import re
from email import message_from_bytes, policy
from email.utils import parseaddr

URL_RE = re.compile(r"https?://[^\s<>\"'\)\]]+", re.I)
TWO_LEVEL = {"co.uk", "co.in", "com.au", "ac.in", "org.in", "gov.in", "co.jp", "com.br", "edu.in"}

def registered_domain(host):
    host = (host or "").lower().strip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in TWO_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])

def host_of(url):
    m = re.match(r"https?://(?:[^/@]*@)?([^/:?#]+)", url, re.I)
    return m.group(1).lower() if m else ""

def strip_html(s):
    s = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", s)
    s = re.sub(r"(?s)<[^>]+>", " ", s)
    return re.sub(r"\s+", " ", htmllib.unescape(s)).strip()

def _auth(text):
    out = {"spf": "none", "dkim": "none", "dmarc": "none"}
    for k in out:
        m = re.search(rf"\b{k}=(\w+)", text, re.I)
        if m:
            out[k] = m.group(1).lower()
    return out

def _domain(addr):
    return addr.split("@")[-1].lower().strip(">") if "@" in addr else ""

def parse(raw=None, text=None, subject=None, sender=None, links=None):
    out = {"sender_name": "", "sender_addr": "", "sender_domain": "", "reply_to_domain": "",
           "return_path_domain": "", "subject": subject or "", "body": "", "links": [],
           "auth": {"spf": "none", "dkim": "none", "dmarc": "none"}, "attachments": [],
           "link_mismatches": [], "has_headers": False}
    html_body = ""
    parsed_ok = False
    if raw:
        try:
            msg = message_from_bytes(raw, policy=policy.default)
            name, addr = parseaddr(str(msg.get("From", "")))
            out.update(sender_name=name, sender_addr=addr, sender_domain=_domain(addr), has_headers=True)
            out["subject"] = str(msg.get("Subject", "")) or out["subject"]
            out["reply_to_domain"] = _domain(parseaddr(str(msg.get("Reply-To", "")))[1])
            out["return_path_domain"] = _domain(parseaddr(str(msg.get("Return-Path", "")))[1])
            out["auth"] = _auth(" ".join(str(v) for k, v in msg.items() if k.lower() == "authentication-results"))
            part = msg.get_body(preferencelist=("plain", "html"))
            if part is not None:
                content = part.get_content()
                if part.get_content_type() == "text/html":
                    html_body = content
                    out["body"] = strip_html(content)
                else:
                    out["body"] = content
                    alt = msg.get_body(preferencelist=("html",))
                    if alt is not None:
                        html_body = alt.get_content()
            for att in msg.iter_attachments():
                out["attachments"].append({"name": att.get_filename() or "", "type": att.get_content_type()})
            parsed_ok = True
        except Exception:
            parsed_ok = False
    if not parsed_ok:
        name, addr = parseaddr(sender or "")
        out.update(sender_name=name, sender_addr=addr, sender_domain=_domain(addr))
        out["body"] = text or (raw.decode("utf-8", "ignore") if raw else "")
    out["body"] = out["body"][:20000]

    found = URL_RE.findall(out["body"]) + list(links or [])
    if html_body:
        found += re.findall(r"href=[\"']([^\"']+)[\"']", html_body, re.I)
        for m in re.finditer(r"(?is)<a\s[^>]*href=[\"']([^\"']+)[\"'][^>]*>(.*?)</a>", html_body):
            href, shown = m.group(1), strip_html(m.group(2))
            if re.search(r"[a-z0-9-]+\.[a-z]{2,}", shown.lower()) and href.lower().startswith("http"):
                if registered_domain(host_of(href)) not in shown.lower():
                    out["link_mismatches"].append([shown[:80], href[:200]])
    seen, clean = set(), []
    for u in found:
        u = u.rstrip(".,;)")
        if u.lower().startswith("http") and u not in seen:
            seen.add(u)
            clean.append(u)
    out["links"] = clean[:50]
    return out
