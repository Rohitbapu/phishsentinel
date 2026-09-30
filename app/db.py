"""SQLite helpers. One short-lived connection per call keeps this safe for FastAPI background threads."""
import json, os, sqlite3, time
from contextlib import closing

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.environ.get("PS_DB", os.path.join(ROOT, "phishsentinel.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS reports(
  id INTEGER PRIMARY KEY AUTOINCREMENT, created_at REAL, processed_at REAL,
  reporter TEXT, subject TEXT, sender TEXT, sender_domain TEXT, body TEXT, links TEXT, parsed TEXT,
  status TEXT DEFAULT 'queued', verdict TEXT, phish_prob REAL, confidence REAL, tier_resolved INTEGER,
  evidence TEXT, rationale TEXT, campaign_id INTEGER, quarantined INTEGER DEFAULT 0,
  vip INTEGER DEFAULT 0, resolved_by TEXT);
CREATE TABLE IF NOT EXISTS campaigns(
  id INTEGER PRIMARY KEY AUTOINCREMENT, created_at REAL, label TEXT, domains TEXT, tokens TEXT, size INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS actions(
  id INTEGER PRIMARY KEY AUTOINCREMENT, report_id INTEGER, action TEXT, ts REAL, actor TEXT, undone INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS audit(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, report_id INTEGER, event TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
"""

def _conn():
    c = sqlite3.connect(DB_PATH, timeout=15)
    c.row_factory = sqlite3.Row
    return c

def init():
    with closing(_conn()) as c:
        c.execute("PRAGMA journal_mode=WAL")
        c.executescript(SCHEMA)
        cols = {r["name"] for r in c.execute("PRAGMA table_info(reports)").fetchall()}
        if "explanation" not in cols:   # migration: optional LLM case note
            c.execute("ALTER TABLE reports ADD COLUMN explanation TEXT")
        c.execute("INSERT OR IGNORE INTO settings(key,value) VALUES('autonomy','1')")
        c.commit()

def rows(sql, args=()):
    with closing(_conn()) as c:
        return [dict(r) for r in c.execute(sql, args).fetchall()]

def one(sql, args=()):
    r = rows(sql, args)
    return r[0] if r else None

def run(sql, args=()):
    with closing(_conn()) as c:
        cur = c.execute(sql, args)
        c.commit()
        return cur.lastrowid

def audit(report_id, event, detail=None):
    run("INSERT INTO audit(ts,report_id,event,detail) VALUES(?,?,?,?)",
        (time.time(), report_id, event, json.dumps(detail or {})))

def get_setting(key, default=None):
    r = one("SELECT value FROM settings WHERE key=?", (key,))
    return r["value"] if r else default

def set_setting(key, value):
    run("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, str(value)))

def reset():
    for t in ("reports", "campaigns", "actions", "audit"):
        run(f"DELETE FROM {t}")
    run("DELETE FROM sqlite_sequence")
    set_setting("autonomy", "1")
