# مثال لملف WSGI على PythonAnywhere (Web > WSGI configuration file)
# استبدل USERNAME باسم حسابك في PythonAnywhere وحسابك في GitHub.
import os
import sys

path = "/home/USERNAME/lamh_backend"
if path not in sys.path:
    sys.path.insert(0, path)

os.environ["LAMH_DB"] = "/home/USERNAME/lamh.db"
os.environ["LAMH_ADMIN_PASSWORD"] = "ضع-كلمة-سر-قوية-هنا"
os.environ["LAMH_CORS_ORIGIN"] = "https://GITHUBUSER.github.io"
os.environ["LAMH_BEHIND_PROXY"] = "1"

from app import app as application  # noqa
