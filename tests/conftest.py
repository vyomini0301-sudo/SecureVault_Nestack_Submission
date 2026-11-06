import pytest
from app import create_app
@pytest.fixture
def app(tmp_path):return create_app({"TESTING":True,"DATABASE":str(tmp_path/"t.db"),"BCRYPT_ROUNDS":4,"MAX_FAILED_LOGINS":3,"LOCKOUT_SECONDS":60})
@pytest.fixture
def client(app):return app.test_client()
def reg(c,u):return c.post("/register",json={"username":u,"password":"Password123"})
def log(c,u):return c.post("/login",json={"username":u,"password":"Password123"})
def hdr(r):return {"Authorization":"Bearer "+r.json["session_token"]}
