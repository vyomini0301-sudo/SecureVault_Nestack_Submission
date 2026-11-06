import sqlite3
from conftest import reg,log,hdr
def test_registration_login_and_hash(app,client):
 assert reg(client,"alice").status_code==201
 assert log(client,"alice").status_code==200
 c=sqlite3.connect(app.config["DATABASE"]);h=c.execute("select password_hash from users").fetchone()[0];c.close()
 assert b"Password123" not in h and h.startswith(b"$2")
def test_idor_and_owner_access(client):
 reg(client,"alice");reg(client,"bob");a=hdr(log(client,"alice"));b=hdr(log(client,"bob"))
 r=client.post("/records",json={"title":"secret","body":"private"},headers=a);rid=r.json["id"]
 assert client.get(f"/records/{rid}",headers=a).status_code==200
 assert client.get(f"/records/{rid}",headers=b).status_code==404
def test_role_escalation(client):
 assert client.post("/register",json={"username":"eve","password":"Password123","role":"admin"}).status_code==403
def test_lockout(client):
 reg(client,"bob")
 for _ in range(3):r=client.post("/login",json={"username":"bob","password":"bad"})
 assert r.status_code==429
def test_validation_and_auth(client):
 assert client.post("/records",json={"title":"x","body":"y"}).status_code==401
 reg(client,"alice");h=hdr(log(client,"alice"))
 assert client.post("/records",json={"title":"","body":"x"},headers=h).status_code==400
 assert client.post("/records",json={"title":"x","body":"z"*5001},headers=h).status_code==400
def test_bad_token(client):
 assert client.get("/records/1",headers={"Authorization":"Bearer fake"}).status_code==401
