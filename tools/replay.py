"""Generate realistic demo emails and (optionally) replay them into a running server.

  python -m tools.replay --n 80                      # send to http://127.0.0.1:8000
  python -m tools.replay --n 80 --url http://HOST:8000 --key SECRET --delay 0.2
"""
import argparse, base64, json, random, time, urllib.request
from email.message import EmailMessage

AUTH_PASS = "mx.corp.test; spf=pass; dkim=pass; dmarc=pass"
AUTH_FAIL = "mx.corp.test; spf=fail; dkim=fail; dmarc=fail"

def mk(frm, subject, body, auth=None, reply_to=None, html=None):
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = frm, "employee@corp.test", subject
    if auth: m["Authentication-Results"] = auth
    if reply_to: m["Reply-To"] = reply_to
    m.set_content(body)
    if html: m.add_alternative(html, subtype="html")
    return m.as_bytes()

def rid(r): return "".join(r.choice("abcdefghjkmnpqrstuvwxyz23456789") for _ in range(8))
def name(r): return r.choice(["Anita", "Ravi", "Meena", "Karthik", "Divya", "Suresh"])

def phish_known(r):
    return mk("PayPal Support <security@paypa1-secure.com>", "Action required: verify your account",
              f"Dear customer, your account will be suspended. Verify now: https://paypa1-secure.com/verify?id={rid(r)}", AUTH_FAIL)

def phish_lookalike(r):  # same campaign, new domain (not on any list)
    return mk(f"Microsoft 365 <no-reply@m1crosoft-verify.xyz>", f"Your password expires today ({name(r)})",
              f"Hi {name(r)}, your Microsoft 365 password expires today. Verify now to avoid suspension and log in "
              f"here: https://m1crosoft-verify.xyz/login?u={rid(r)}", AUTH_FAIL)

def bec_freemail(r):  # no links, needs header + intent evidence
    return mk("HR Department <hr.dept.vcet@gmail.com>", "Update payroll bank details before Friday",
              f"Hello {name(r)}, please update your payroll bank details before Friday's salary run. "
              "Reply with your account number and bank name.", None, reply_to="payroll.update@outlook.com")

def html_mismatch(r):
    h = ('<p>Your account needs attention.</p><p><a href="http://secure-paypal-account.top/login?s=%s">'
         'https://www.paypal.com/verify</a></p>' % rid(r))
    return mk("PayPal <alerts@paypal-alerts.top>", "Please confirm your recent activity",
              "Please confirm your recent activity.", AUTH_FAIL, html=h)

def benign_github(r):
    return mk("GitHub <noreply@github.com>", "[GitHub] A new pull request was opened",
              f"A pull request was opened. View it: https://github.com/team/repo/pull/{r.randint(1, 900)}", AUTH_PASS)

def benign_internal(r):
    return mk("HR <hr@vcet.edu.in>", "Holiday notice for Deepavali",
              "The college will remain closed on the festival day. See https://vcet.edu.in/notice/holiday for details.", AUTH_PASS)

def benign_invoice(r):  # unknown vendor, authenticated: should end benign after Tier 2
    return mk("Acme Billing <billing@acme-supplies.in>", f"Invoice INV-{r.randint(1000, 9999)} for October",
              f"Your invoice is ready. Payment is due in 15 days. https://acme-supplies.in/invoices/{rid(r)}", AUTH_PASS)

def marketing_urgent(r):  # genuinely ambiguous
    return mk("ShopNow Deals <deals@shopnow.in>", "Last chance: offer ends today",
              "Act now and log in to claim your offer. https://shopnow.in/sale", AUTH_PASS)

KINDS = [(phish_known, 10, "phishing"), (phish_lookalike, 12, "phishing"), (bec_freemail, 6, "phishing"),
         (html_mismatch, 5, "phishing"), (benign_github, 12, "benign"), (benign_internal, 8, "benign"),
         (benign_invoice, 4, "benign"), (marketing_urgent, 3, "ambiguous")]

def build_samples(n=60, seed=7):
    r = random.Random(seed)
    pool = [(f, label) for f, w, label in KINDS for _ in range(w)]
    return [dict(kind=f.__name__, truth=label, raw=f(r), reporter=r.choice(["emp1@corp.test", "emp2@corp.test", "emp3@corp.test"]))
            for f, label in (r.choice(pool) for _ in range(n))]

def post(url, key, body):
    req = urllib.request.Request(url + "/api/v1/reports", data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", **({"x-api-key": key} if key else {})})
    return json.load(urllib.request.urlopen(req, timeout=10))

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=60); ap.add_argument("--url", default="http://127.0.0.1:8000")
    ap.add_argument("--key", default=""); ap.add_argument("--delay", type=float, default=0.15)
    ap.add_argument("--reset", action="store_true", help="wipe the demo database first")
    a = ap.parse_args()
    if a.reset:
        urllib.request.urlopen(urllib.request.Request(a.url + "/api/v1/admin/reset", data=b"{}", method="POST",
                               headers={"Content-Type": "application/json", **({"x-api-key": a.key} if a.key else {})}), timeout=10)
    for i, s in enumerate(build_samples(a.n), 1):
        res = post(a.url, a.key, {"reporter": s["reporter"], "raw_eml": base64.b64encode(s["raw"]).decode()})
        print(i, s["kind"], "->", res["report_id"]); time.sleep(a.delay)
