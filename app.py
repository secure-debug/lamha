"""
واجهة API لموقع لَمْحَ | LAMH
تشغيل:  python app.py
"""
import csv
import io
import os
import time
from collections import defaultdict, deque
from functools import wraps

from flask import Flask, Response, jsonify, request, send_from_directory

import database as dbm

app = Flask(__name__, static_folder=None)
if os.environ.get("LAMH_BEHIND_PROXY") == "1":
    # خلف وسيط الاستضافة (Render/Railway...): نقرأ عنوان الزائر الحقيقي من X-Forwarded-For
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "docs")
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024  # 64KB كحد أقصى للطلب

# اسمح لموقعك فقط باستدعاء الـ API (مثال: https://example.com). "*" للتجربة فقط.
# النطاقات المسموح لها باستدعاء الـ API، مفصولة بفاصلة. مثال: https://USERNAME.github.io
CORS_ORIGINS = {o.strip().rstrip("/") for o in os.environ.get("LAMH_CORS_ORIGIN", "").split(",") if o.strip()}

_hits = defaultdict(deque)  # حد الفحص لكل دقيقة (في الذاكرة)


@app.after_request
def add_headers(resp):
    origin = request.headers.get("Origin", "")
    if origin and (origin in CORS_ORIGINS or "*" in CORS_ORIGINS):
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Vary"] = "Origin"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/api/<path:_>", methods=["OPTIONS"])
def preflight(_):
    return ("", 204)


def client_ip():
    return request.remote_addr or "-"


def err(msg, code=400, **extra):
    return jsonify({"error": msg, **extra}), code


def admin_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        auth = request.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else ""
        user = dbm.validate_session(token)
        if not user:
            return err("unauthorized", 401)
        request.admin_user, request.admin_token = user, token
        return fn(*a, **kw)
    return wrapper


# ------------------------------------------------------------------ الصفحة الرئيسية
@app.get("/config.js")
def config_js():
    return send_from_directory(STATIC_DIR, "config.js")


@app.get("/")
def index():
    """يقدّم الموقع من نفس الخادم، فلا حاجة لإعداد CORS."""
    return send_from_directory(STATIC_DIR, "index.html")


# ------------------------------------------------------------------ عام
@app.get("/api/health")
def health():
    return {"ok": True}


@app.get("/api/config")
def public_config():
    """الإعدادات التي يحتاجها محرك الفحص في المتصفح (أوزان، حدود، قوائم)."""
    cfg = dbm.get_config()
    return jsonify(cfg)


@app.post("/api/scans")
def create_scan():
    cfg = dbm.get_config()
    q, ip, now = _hits[client_ip()], client_ip(), time.time()
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= cfg["rate"]:
        return err("rate_limited", 429)
    q.append(now)

    d = request.get_json(silent=True) or {}
    try:
        sid = dbm.add_scan(d.get("url"), d.get("hostname"), d.get("score"), d.get("verdict"),
                           d.get("m"), d.get("reasons"), d.get("ms", 0), ip, d.get("ts"))
    except (ValueError, TypeError) as e:
        return err(str(e))
    return jsonify({"id": sid}), 201


# ------------------------------------------------------------------ المسؤول
@app.post("/api/admin/login")
def admin_login():
    d = request.get_json(silent=True) or {}
    token, e = dbm.login(str(d.get("username", "admin")), str(d.get("password", "")), client_ip())
    if e:
        return jsonify(e), 429 if e["error"] == "locked" else 401
    return jsonify({"token": token})


@app.post("/api/admin/logout")
@admin_required
def admin_logout():
    dbm.logout(request.admin_token, request.admin_user)
    return {"ok": True}


@app.put("/api/admin/password")
@admin_required
def admin_password():
    d = request.get_json(silent=True) or {}
    try:
        dbm.change_password(request.admin_user, str(d.get("password", "")))
    except ValueError as e:
        return err(str(e))
    return {"ok": True, "note": "تم إنهاء كل الجلسات، سجّل الدخول من جديد"}


@app.put("/api/config")
@admin_required
def admin_update_config():
    try:
        return jsonify(dbm.update_config(request.get_json(silent=True) or {}, request.admin_user))
    except (ValueError, TypeError) as e:
        return err(str(e))


@app.post("/api/config/reset")
@admin_required
def admin_reset_config():
    return jsonify(dbm.reset_config(request.admin_user))


@app.get("/api/stats")
@admin_required
def stats():
    return jsonify(dbm.get_stats())


@app.get("/api/scans")
@admin_required
def scans():
    return jsonify(dbm.list_scans(request.args.get("q", ""), request.args.get("verdict"),
                                  request.args.get("limit", 100), request.args.get("offset", 0)))


@app.delete("/api/scans/<int:scan_id>")
@admin_required
def scan_delete(scan_id):
    return ({"ok": True}, 200) if dbm.delete_scan(scan_id, request.admin_user) else err("not_found", 404)


@app.delete("/api/scans")
@admin_required
def scans_clear():
    dbm.clear_scans(request.admin_user)
    return {"ok": True}


@app.get("/api/scans/export.csv")
@admin_required
def scans_export():
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "url", "verdict", "score", "duration_ms", "timestamp"])
    for s in dbm.list_scans(limit=1000):
        # حماية من حقن الصيغ في Excel
        u = s["url"] if s["url"][0] not in "=+-@" else "'" + s["url"]
        w.writerow([s["id"], u, s["verdict"], s["score"], s["ms"], s["ts"]])
    return Response("\ufeff" + buf.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=lamh_scans.csv"})


@app.post("/api/audit/export")
@admin_required
def audit_export():
    dbm.log_export(request.admin_user, (request.get_json(silent=True) or {}).get("format", ""))
    return {"ok": True}


@app.get("/api/audit")
@admin_required
def audit_log():
    return jsonify(dbm.list_audit())


def bootstrap():
    """ينشئ الجداول وحساب المسؤول عند أول تشغيل (يعمل مع gunicorn أيضاً)."""
    pw = dbm.init_db()
    if pw and not os.environ.get("LAMH_ADMIN_PASSWORD"):
        print("=" * 50)
        print(" تم إنشاء حساب المسؤول لأول مرة")
        print(f" اسم المستخدم: admin\n كلمة السر:    {pw}")
        print(" احفظها الآن، لن تظهر مرة أخرى.")
        print("=" * 50, flush=True)


bootstrap()

if __name__ == "__main__":
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", 5000)))
