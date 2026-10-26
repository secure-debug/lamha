# لَمْحَ | LAMH

كاشف روابط التصيّد. الواجهة (`docs/`) + سيرفر بايثون وقاعدة SQLite (`app.py`, `database.py`).

## البنية
```
المتصفح ──> GitHub Pages (docs/: الواجهة فقط)
                │  fetch + CORS
                ▼
          سيرفر بايثون (app.py + lamh.db)  ← مستضاف خارج GitHub
```
GitHub Pages يستضيف ملفات ثابتة فقط، لذلك قاعدة البيانات والسيرفر يعملان في مكان آخر،
والواجهة تتصل به عبر العنوان المكتوب في `docs/config.js`.

## 1) تشغيل السيرفر
### أ) PythonAnywhere (يحفظ الملفات، مناسب لـ SQLite)
1. ارفع مجلد المشروع إلى `/home/USERNAME/lamh_backend` (أو `git clone` من الـ Console).
2. من Console: `pip install --user flask`
3. تبويب **Web** > Add a new web app > Manual configuration > Flask/Python 3.x.
4. افتح ملف WSGI وانسخ محتوى `pythonanywhere_wsgi.py` وعدّل القيم (كلمة السر، نطاق GitHub).
5. Reload. عنوانك سيكون `https://USERNAME.pythonanywhere.com`. تأكد: `/api/health`.

### ب) Render
`New > Blueprint` ثم المستودع (يقرأ `render.yaml`). القرص الدائم يحتاج خطة مدفوعة،
وبدونه تُمسح القاعدة عند كل إعادة تشغيل. اضبط `LAMH_CORS_ORIGIN`.

### ج) محلياً
```bash
pip install -r requirements.txt
python app.py        # ثم افتح http://127.0.0.1:5000
```

## 2) نشر الواجهة على GitHub Pages
1. عدّل `docs/config.js`:
   ```js
   window.LAMH_API = "https://USERNAME.pythonanywhere.com";
   ```
2. ارفع المشروع إلى GitHub (الأوامر بالأسفل).
3. المستودع > **Settings > Pages** > Source: *Deploy from a branch* > Branch: `main` / مجلد `/docs` > Save.
4. موقعك: `https://GITHUBUSER.github.io/REPO/`
5. اضبط `LAMH_CORS_ORIGIN=https://GITHUBUSER.github.io` على السيرفر (نطاق فقط بلا مسار).

```bash
git init && git add . && git commit -m "LAMH"
git branch -M main
git remote add origin https://github.com/GITHUBUSER/REPO.git
git push -u origin main
```

## متغيرات البيئة
| المتغير | الوظيفة |
|---|---|
| `LAMH_DB` | مسار ملف القاعدة |
| `LAMH_ADMIN_PASSWORD` | كلمة سر المسؤول الأولى (وإلا تُولَّد وتُطبع مرة واحدة) |
| `LAMH_CORS_ORIGIN` | النطاقات المسموحة، مفصولة بفاصلة |
| `LAMH_BEHIND_PROXY` | `1` عند الاستضافة خلف وسيط (لقراءة IP الزائر الحقيقي) |
| `HOST` / `PORT` | للتشغيل المحلي |

## نقاط الـ API
| الطريقة | المسار | الصلاحية |
|---|---|---|
| GET | `/api/health` , `/api/config` | عام |
| POST | `/api/scans` | عام (محدود بعدد الفحوصات/دقيقة) |
| POST | `/api/admin/login` | عام (قفل 5 دقائق بعد 5 محاولات فاشلة) |
| POST / PUT | `/api/admin/logout` , `/api/admin/password` | مسؤول |
| PUT / POST | `/api/config` , `/api/config/reset` | مسؤول |
| GET | `/api/stats` , `/api/scans` , `/api/audit` , `/api/scans/export.csv` | مسؤول |
| DELETE | `/api/scans/<id>` , `/api/scans` | مسؤول |

المسؤول يرسل `Authorization: Bearer <token>`.

## ملاحظات
- لا تضع كلمة السر داخل الكود أو المستودع؛ استخدم متغيرات البيئة. ملف `lamh.db` و`.env` مستثنيان في `.gitignore`.
- توكن المسؤول في الذاكرة فقط، وإعادة تحميل الصفحة تتطلب دخولاً جديداً.
- سجل «آخر فحوصاتي» للزائر محلي في متصفحه.
- إن تعذّر الاتصال بالسيرفر تستمر الواجهة بالإعدادات الافتراضية، لكن الفحوصات لا تُحفظ.

## الاختبار
`python test_lamh.py`
