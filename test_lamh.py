import os, sys, tempfile
os.environ["LAMH_DB"] = tempfile.mktemp(suffix=".db")
os.environ["LAMH_ADMIN_PASSWORD"] = "TestPass123"
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import database as d
from app import app
d.init_db()   # أُنشئ أصلاً عند استيراد app
c = app.test_client()
H = lambda t: {"Authorization": "Bearer " + t}

# عام
assert c.get("/api/config").json["warn"] == 31
r = c.post("/api/scans", json={"url":"http://paypa1-login.ru/x","hostname":"paypa1-login.ru","score":88,"verdict":"DANGER","m":{"1":"m1_bad"},"reasons":["r_x"],"ms":120})
assert r.status_code == 201, r.json
c.post("/api/scans", json={"url":"https://google.com","hostname":"google.com","score":0,"verdict":"SAFE","ms":80})
assert c.post("/api/scans", json={"url":"x","score":999,"verdict":"SAFE"}).status_code == 400
assert c.post("/api/scans", json={"url":"x","score":5,"verdict":"HACK"}).status_code == 400

# بدون صلاحية
assert c.get("/api/scans").status_code == 401
assert c.get("/api/stats").status_code == 401

# قفل بعد 5 محاولات
for i in range(4):
    r = c.post("/api/admin/login", json={"password":"bad"}); assert r.status_code == 401
assert r.json["attempts_left"] == 1
r = c.post("/api/admin/login", json={"password":"bad"}); assert r.status_code == 429
assert c.post("/api/admin/login", json={"password":"TestPass123"}).status_code == 429  # ما زال مقفلاً
with d.db() as con: con.execute("UPDATE login_attempts SET locked_until=0")  # محاكاة انتهاء القفل
tok = c.post("/api/admin/login", json={"password":"TestPass123"}).json["token"]

# بيانات المسؤول
assert c.get("/api/stats", headers=H(tok)).json["total"] == 2
assert c.get("/api/stats", headers=H(tok)).json["DANGER"] == 1
assert len(c.get("/api/scans?q=paypa", headers=H(tok)).json) == 1
assert len(c.get("/api/scans?q=%25", headers=H(tok)).json) == 0   # % لا يعمل كـ wildcard
assert len(c.get("/api/scans?verdict=SAFE", headers=H(tok)).json) == 1
csv = c.get("/api/scans/export.csv", headers=H(tok)); assert b"paypa1" in csv.data

# الإعدادات
r = c.put("/api/config", headers=H(tok), json={"warn":40,"danger":70,"w":{"1":30},"on":{"7":0},
        "allow":["https://www.Example.com/path","example.com","gov.sa"],"block":["evil.ru"]})
j = r.json; assert j["warn"]==40 and j["w"]["1"]==30 and j["on"]["7"]==0
assert j["allow"] == ["example.com","gov.sa"], j["allow"]   # تنظيف + إزالة التكرار
assert c.put("/api/config", headers=H(tok), json={"warn":80,"danger":50}).status_code == 400
assert c.post("/api/config/reset", headers=H(tok)).json["warn"] == 31

# حذف
sid = c.get("/api/scans", headers=H(tok)).json[0]["id"]
assert c.delete(f"/api/scans/{sid}", headers=H(tok)).status_code == 200
assert c.delete(f"/api/scans/{sid}", headers=H(tok)).status_code == 404
assert c.delete("/api/scans", headers=H(tok)).status_code == 200
assert c.get("/api/stats", headers=H(tok)).json["total"] == 0

# التدقيق
actions = [a["a"] for a in c.get("/api/audit", headers=H(tok)).json]
for a in ("au_fail","au_lock","au_login","au_lists","au_reset","au_clearlog","au_delone","au_th","au_rule_w","au_rule_off"): assert a in actions, a
assert c.post("/api/audit/export", headers=H(tok), json={"format":"csv"}).status_code == 200
assert c.get("/").status_code in (200, 404)

# كلمة السر
assert c.put("/api/admin/password", headers=H(tok), json={"password":"123"}).status_code == 400
assert c.put("/api/admin/password", headers=H(tok), json={"password":"NewPass456"}).status_code == 200
assert c.get("/api/stats", headers=H(tok)).status_code == 401   # الجلسة القديمة أُنهيت
assert c.post("/api/admin/login", json={"password":"NewPass456"}).status_code == 200

# انتهاء الجلسة
t2 = c.post("/api/admin/login", json={"password":"NewPass456"}).json["token"]
with d.db() as con: con.execute("UPDATE sessions SET expires_at=1")
assert c.get("/api/stats", headers=H(t2)).status_code == 401

# حد الفحص (10/دقيقة)
codes = [c.post("/api/scans", json={"url":"http://a.com","score":1,"verdict":"SAFE"}).status_code for _ in range(12)]
assert 429 in codes
# CORS: النطاق المسموح فقط
import app as A
A.CORS_ORIGINS.add("https://user.github.io")
ok = c.get("/api/health", headers={"Origin": "https://user.github.io"})
assert ok.headers.get("Access-Control-Allow-Origin") == "https://user.github.io"
assert "Access-Control-Allow-Origin" not in c.get("/api/health", headers={"Origin": "https://evil.com"}).headers
pf = c.open("/api/scans", method="OPTIONS", headers={"Origin": "https://user.github.io"})
assert pf.status_code in (200, 204) and "Authorization" in pf.headers["Access-Control-Allow-Headers"]
assert c.get("/config.js").status_code == 200 and c.get("/").status_code == 200
print("كل الاختبارات نجحت ✔")
