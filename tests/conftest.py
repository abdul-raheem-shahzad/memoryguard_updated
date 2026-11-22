import os, sys, pathlib, tempfile
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
_tmp = tempfile.mkdtemp()
os.environ["MG_DATABASE_URL"] = f"sqlite:///{_tmp}/test.db"
os.environ["MG_SECRET"] = "test-pepper"
os.environ["MG_ADMIN_KEY"] = "test-admin-key"   # bootstrapped as the first admin key
