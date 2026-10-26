"""
قاعدة بيانات موقع لَمْحَ | LAMH  (SQLite - مكتبة بايثون القياسية فقط)

الجداول:
  settings      إعدادات عامة (حدود الأحكام، مهلة الجلسة، حد الفحص...)
  rules         قواعد الفحص السبع (الوزن + مفعّلة/معطّلة)
  domain_lists  القائمة البيضاء / السوداء / أنماط انتحال العلامات
  scans         سجل الفحوصات
  admins        حسابات المسؤولين (كلمة السر مشفّرة بـ scrypt)
  sessions      جلسات الدخول (يُخزَّن بصمة التوكن فقط)
  login_attempts محاولات الدخول الفاشلة والقفل المؤقت
  audit_log     سجل التدقيق
"""
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from contextlib import contextmanager

DB_PATH = os.environ.get("LAMH_DB", os.path.join(os.path.dirname(__file__), "lamh.db"))

# نفس القيم الافتراضية الموجودة في الواجهة (CFG_DEF)
DEFAULT_WEIGHTS = {1: 20, 2: 20, 3: 15, 4: 10, 5: 10, 6: 25, 7: 10}
DEFAULT_SETTINGS = {"warn": 31, "danger": 66, "rate": 10, "timeout": 5}
LIST_TYPES = ("allow", "block", "brands")
VERDICTS = ("SAFE", "WARNING", "DANGER")
LOCK_MAX_FAILS = 5
LOCK_MINUTES = 5

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS rules (
    id      INTEGER PRIMARY KEY CHECK (id BETWEEN 1 AND 7),
    weight  INTEGER NOT NULL CHECK (weight BETWEEN 0 AND 100),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0,1))
);
CREATE TABLE IF NOT EXISTS domain_lists (
    list_type TEXT NOT NULL CHECK (list_type IN ('allow','block','brands')),
    domain    TEXT NOT NULL,
    PRIMARY KEY (list_type, domain)
);
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    url         TEXT NOT NULL,
    hostname    TEXT,
    score       INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
    verdict     TEXT NOT NULL CHECK (verdict IN ('SAFE','WARNING','DANGER')),
    modules     TEXT,              -- JSON: حالة كل وحدة فحص
    reasons     TEXT,              -- JSON: قائمة الأسباب
    duration_ms INTEGER DEFAULT 0,
    client_ip   TEXT,
    created_at  INTEGER NOT NULL   -- milliseconds since epoch
);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_verdict ON scans(verdict);
CREATE INDEX IF NOT EXISTS idx_scans_host    ON scans(hostname);

CREATE TABLE IF NOT EXISTS admins (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    admin_id   INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS login_attempts (
    key          TEXT PRIMARY KEY,
    fails        INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS audit_log (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    ts     INTEGER NOT NULL,
    actor  TEXT NOT NULL,
    action TEXT NOT NULL,
    params TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts DESC);
"""


def now_ms():
    return int(time.time() * 1000)


@contextmanager
def db():
    """اتصال قصير العمر: commit تلقائي، rollback عند الخطأ."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ----------------------------------------------------------------- كلمات السر
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${h.hex()}"


def check_password(password: str, stored: str) -> bool:
    try:
        _, salt_hex, h_hex = stored.split("$")
        h = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex),
                           n=2**14, r=8, p=1, dklen=32)
        return hmac.compare_digest(h.hex(), h_hex)
    except Exception:
        return False


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# ---------------------------------------------------------------- التهيئة
def init_db():
    """ينشئ الجداول والقيم الافتراضية. يرجع كلمة السر المولّدة إن أُنشئ مسؤول جديد."""
    first_password = None
    with db() as c:
        c.executescript(SCHEMA)
        for k, v in DEFAULT_SETTINGS.items():
            c.execute("INSERT OR IGNORE INTO settings VALUES (?,?)", (k, json.dumps(v)))
        for rid, w in DEFAULT_WEIGHTS.items():
            c.execute("INSERT OR IGNORE INTO rules VALUES (?,?,1)", (rid, w))
        if c.execute("SELECT COUNT(*) FROM admins").fetchone()[0] == 0:
            first_password = os.environ.get("LAMH_ADMIN_PASSWORD") or secrets.token_urlsafe(10)
            c.execute("INSERT INTO admins (username,password_hash,created_at) VALUES (?,?,?)",
                      ("admin", hash_password(first_password), now_ms()))
            c.execute("INSERT INTO audit_log (ts,actor,action,params) VALUES (?,?,?,?)",
                      (now_ms(), "system", "init_db", None))
    return first_password


# ---------------------------------------------------------------- التدقيق
def audit(conn, actor, action, *params):
    conn.execute("INSERT INTO audit_log (ts,actor,action,params) VALUES (?,?,?,?)",
                 (now_ms(), actor, action, json.dumps(params, ensure_ascii=False)))


def log_export(actor, fmt):
    with db() as c:
        audit(c, actor, "au_export", str(fmt).upper()[:10])


def list_audit(limit=200):
    with db() as c:
        rows = c.execute("SELECT * FROM audit_log ORDER BY ts DESC, id DESC LIMIT ?", (limit,)).fetchall()
    return [{"id": r["id"], "ts": r["ts"], "by": r["actor"], "a": r["action"],
             "p": json.loads(r["params"] or "[]")} for r in rows]


# ---------------------------------------------------------------- الإعدادات
def get_config():
    """يرجع نفس شكل CFG الذي تتوقعه الواجهة: w, on, warn, danger, allow, block, brands, rate, timeout."""
    with db() as c:
        s = {r["key"]: json.loads(r["value"]) for r in c.execute("SELECT * FROM settings")}
        rules = c.execute("SELECT * FROM rules ORDER BY id").fetchall()
        lists = {t: [] for t in LIST_TYPES}
        for r in c.execute("SELECT * FROM domain_lists ORDER BY domain"):
            lists[r["list_type"]].append(r["domain"])
    return {
        "w": {str(r["id"]): r["weight"] for r in rules},
        "on": {str(r["id"]): r["enabled"] for r in rules},
        "warn": s["warn"], "danger": s["danger"], "rate": s["rate"], "timeout": s["timeout"],
        **lists,
    }


def _clean_domain(x: str) -> str:
    x = x.strip().lower()
    for p in ("https://", "http://"):
        if x.startswith(p):
            x = x[len(p):]
    if x.startswith("www."):
        x = x[4:]
    return x.split("/")[0]


def update_config(data: dict, actor="admin"):
    """تحديث جزئي: أي مفتاح غير موجود يُتجاهل. يرمي ValueError عند قيمة غير صالحة."""
    with db() as c:
        cur = {r["key"]: json.loads(r["value"]) for r in c.execute("SELECT * FROM settings")}
        warn = int(data.get("warn", cur["warn"]))
        danger = int(data.get("danger", cur["danger"]))
        if not (1 <= warn < danger <= 100):
            raise ValueError("حد الخطر يجب أن يكون أكبر من حد التحذير (1..100)")
        rate = int(data.get("rate", cur["rate"]))
        timeout = int(data.get("timeout", cur["timeout"]))
        if rate < 1 or timeout < 1:
            raise ValueError("rate و timeout يجب أن يكونا 1 أو أكثر")
        for k, v in {"warn": warn, "danger": danger, "rate": rate, "timeout": timeout}.items():
            if cur.get(k) != v:
                c.execute("INSERT OR REPLACE INTO settings VALUES (?,?)", (k, json.dumps(v)))
                audit(c, actor, "au_th" if k in ("warn", "danger") else "au_setting", k, v)

        for rid, w in (data.get("w") or {}).items():
            w = max(0, min(100, int(w)))
            c.execute("UPDATE rules SET weight=? WHERE id=?", (w, int(rid)))
            audit(c, actor, "au_rule_w", int(rid), w)
        for rid, on in (data.get("on") or {}).items():
            c.execute("UPDATE rules SET enabled=? WHERE id=?", (1 if on else 0, int(rid)))
            audit(c, actor, "au_rule_on" if on else "au_rule_off", int(rid))

        touched = [t for t in LIST_TYPES if t in data]
        for t in touched:
            items = {_clean_domain(x) for x in data[t] if isinstance(x, str)}
            items.discard("")
            c.execute("DELETE FROM domain_lists WHERE list_type=?", (t,))
            c.executemany("INSERT INTO domain_lists VALUES (?,?)", [(t, d) for d in sorted(items)])
        if touched:
            n = {t: c.execute("SELECT COUNT(*) FROM domain_lists WHERE list_type=?", (t,)).fetchone()[0]
                 for t in LIST_TYPES}
            audit(c, actor, "au_lists", n["allow"], n["block"], n["brands"])
    return get_config()


def reset_config(actor="admin"):
    with db() as c:
        for k, v in DEFAULT_SETTINGS.items():
            c.execute("INSERT OR REPLACE INTO settings VALUES (?,?)", (k, json.dumps(v)))
        for rid, w in DEFAULT_WEIGHTS.items():
            c.execute("UPDATE rules SET weight=?, enabled=1 WHERE id=?", (w, rid))
        c.execute("DELETE FROM domain_lists")
        audit(c, actor, "au_reset")
    return get_config()


# ---------------------------------------------------------------- الفحوصات
def add_scan(url, hostname, score, verdict, modules, reasons, duration_ms=0, client_ip=None, ts=None):
    if verdict not in VERDICTS:
        raise ValueError("verdict غير صالح")
    score = int(score)
    if not 0 <= score <= 100:
        raise ValueError("score يجب أن يكون بين 0 و 100")
    url = str(url).strip()
    if not url or len(url) > 2048:
        raise ValueError("الرابط فارغ أو طويل جداً")
    with db() as c:
        cur = c.execute(
            "INSERT INTO scans (url,hostname,score,verdict,modules,reasons,duration_ms,client_ip,created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (url, (hostname or "")[:253], score, verdict,
             json.dumps(modules or {}), json.dumps(reasons or []),
             max(0, int(duration_ms or 0)), client_ip, ts or now_ms()))
        return cur.lastrowid


def _scan_row(r):
    return {"id": r["id"], "url": r["url"], "hostname": r["hostname"], "score": r["score"],
            "verdict": r["verdict"], "m": json.loads(r["modules"] or "{}"),
            "reasons": json.loads(r["reasons"] or "[]"), "ms": r["duration_ms"], "ts": r["created_at"]}


def list_scans(q="", verdict=None, limit=100, offset=0):
    sql, args = "SELECT * FROM scans WHERE 1=1", []
    if q:
        sql += " AND url LIKE ? ESCAPE '\\'"
        args.append("%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%")
    if verdict in VERDICTS:
        sql += " AND verdict=?"
        args.append(verdict)
    sql += " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
    args += [max(1, min(int(limit), 1000)), max(0, int(offset))]
    with db() as c:
        return [_scan_row(r) for r in c.execute(sql, args)]


def delete_scan(scan_id, actor="admin"):
    with db() as c:
        n = c.execute("DELETE FROM scans WHERE id=?", (scan_id,)).rowcount
        if n:
            audit(c, actor, "au_delone")
        return n > 0


def clear_scans(actor="admin"):
    with db() as c:
        c.execute("DELETE FROM scans")
        audit(c, actor, "au_clearlog")


def get_stats():
    with db() as c:
        row = c.execute("SELECT COUNT(*) n, COALESCE(SUM(duration_ms),0) ms FROM scans").fetchone()
        by = {v: 0 for v in VERDICTS}
        for r in c.execute("SELECT verdict, COUNT(*) n FROM scans GROUP BY verdict"):
            by[r["verdict"]] = r["n"]
        top = c.execute("SELECT hostname, COUNT(*) n FROM scans WHERE verdict='DANGER' AND hostname!='' "
                        "GROUP BY hostname ORDER BY n DESC LIMIT 5").fetchall()
    total = row["n"]
    return {"total": total, **by, "ms": row["ms"],
            "avg_ms": round(row["ms"] / total) if total else 0,
            "top_dangerous_hosts": [{"host": r["hostname"], "count": r["n"]} for r in top]}


# ---------------------------------------------------------------- المسؤول والجلسات
def _lock_key(username, ip):
    return f"{username}|{ip}"


def lock_remaining_ms(username, ip):
    with db() as c:
        r = c.execute("SELECT locked_until FROM login_attempts WHERE key=?", (_lock_key(username, ip),)).fetchone()
    return max(0, (r["locked_until"] if r else 0) - now_ms())


def login(username, password, ip="-"):
    """يرجع (token, None) عند النجاح أو (None, {"error":..., ...}) عند الفشل."""
    key = _lock_key(username, ip)
    left = lock_remaining_ms(username, ip)
    if left:
        return None, {"error": "locked", "retry_after_ms": left}
    with db() as c:
        adm = c.execute("SELECT * FROM admins WHERE username=?", (username,)).fetchone()
        ok = bool(adm) and check_password(password, adm["password_hash"])
        if not ok:
            c.execute("INSERT OR IGNORE INTO login_attempts (key) VALUES (?)", (key,))
            c.execute("UPDATE login_attempts SET fails = fails + 1 WHERE key=?", (key,))
            fails = c.execute("SELECT fails FROM login_attempts WHERE key=?", (key,)).fetchone()["fails"]
            audit(c, "unknown", "au_fail", username)
            if fails >= LOCK_MAX_FAILS:
                c.execute("UPDATE login_attempts SET fails=0, locked_until=? WHERE key=?",
                          (now_ms() + LOCK_MINUTES * 60000, key))
                audit(c, "system", "au_lock", LOCK_MAX_FAILS, LOCK_MINUTES)
                return None, {"error": "locked", "retry_after_ms": LOCK_MINUTES * 60000}
            return None, {"error": "bad_password", "attempts_left": LOCK_MAX_FAILS - fails}
        c.execute("DELETE FROM login_attempts WHERE key=?", (key,))
        timeout = json.loads(c.execute("SELECT value FROM settings WHERE key='timeout'").fetchone()[0])
        token = secrets.token_urlsafe(32)
        c.execute("DELETE FROM sessions WHERE expires_at < ?", (now_ms(),))
        c.execute("INSERT INTO sessions VALUES (?,?,?)",
                  (_token_hash(token), adm["id"], now_ms() + timeout * 60000))
        audit(c, username, "au_login")
        return token, None


def validate_session(token):
    """يتحقق من التوكن ويجدّد المهلة (تنتهي الجلسة عند عدم النشاط). يرجع اسم المسؤول أو None."""
    if not token:
        return None
    with db() as c:
        r = c.execute("SELECT s.expires_at, a.username FROM sessions s JOIN admins a ON a.id=s.admin_id "
                      "WHERE s.token_hash=?", (_token_hash(token),)).fetchone()
        if not r or r["expires_at"] < now_ms():
            return None
        timeout = json.loads(c.execute("SELECT value FROM settings WHERE key='timeout'").fetchone()[0])
        c.execute("UPDATE sessions SET expires_at=? WHERE token_hash=?",
                  (now_ms() + timeout * 60000, _token_hash(token)))
        return r["username"]


def logout(token, username="admin"):
    with db() as c:
        c.execute("DELETE FROM sessions WHERE token_hash=?", (_token_hash(token),))
        audit(c, username, "au_logout")


def change_password(username, new_password):
    if len(new_password) < 6:
        raise ValueError("كلمة السر قصيرة (6 أحرف على الأقل)")
    with db() as c:
        c.execute("UPDATE admins SET password_hash=? WHERE username=?", (hash_password(new_password), username))
        c.execute("DELETE FROM sessions")  # إنهاء كل الجلسات بعد تغيير كلمة السر
        audit(c, username, "au_pw")
