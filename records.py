from flask import Blueprint,jsonify,g
from database import get_db,audit
from security import require_auth,json_obj
records_bp=Blueprint("records",__name__)
@records_bp.post("/records")
@require_auth
def create():
 x,e=json_obj()
 if e:return e
 t,b=x.get("title"),x.get("body")
 if not isinstance(t,str) or not t.strip() or len(t)>120 or not isinstance(b,str) or not b.strip() or len(b)>5000:return jsonify(error="title (1-120 chars) and body (1-5000 chars) required"),400
 d=get_db();c=d.execute("INSERT INTO records(owner_id,title,body) VALUES(?,?,?)",(g.user["id"],t.strip(),b));d.commit();audit("record_created",g.user["username"],f"id={c.lastrowid}")
 return jsonify(id=c.lastrowid,title=t.strip(),created=True),201
@records_bp.get("/records/<int:rid>")
@require_auth
def read(rid):
 d=get_db()
 if g.user["role"]=="admin":r=d.execute("SELECT id,owner_id,title,body,created_at FROM records WHERE id=?",(rid,)).fetchone()
 else:r=d.execute("SELECT id,owner_id,title,body,created_at FROM records WHERE id=? AND owner_id=?",(rid,g.user["id"])).fetchone()
 if not r:audit("record_access_denied",g.user["username"],f"id={rid}");return jsonify(error="Record not found"),404
 audit("record_read",g.user["username"],f"id={rid}");return jsonify(dict(r)),200
