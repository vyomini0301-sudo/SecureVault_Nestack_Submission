import time
import secrets
import bcrypt

from flask import Blueprint, jsonify, current_app, request
from database import get_db, audit
from security import json_obj, valid_user, valid_pw, token_hash

auth_bp = Blueprint("auth", __name__)


@auth_bp.post("/register")
def register():
    x, e = json_obj()
    if e:
        return e

    if "role" in x:
        return jsonify(error="Role cannot be specified"), 403

    u, p = x.get("username"), x.get("password")

    if not valid_user(u) or not valid_pw(p):
        return jsonify(error="Invalid username or password format"), 400

    d = get_db()
    h = bcrypt.hashpw(
        p.encode(),
        bcrypt.gensalt(rounds=current_app.config["BCRYPT_ROUNDS"])
    )

    try:
        c = d.execute(
            "INSERT INTO users(username,password_hash,role) VALUES(?,?,?)",
            (u, h, "user")
        )
        d.commit()
    except Exception:
        d.rollback()
        return jsonify(error="Unable to register account"), 409

    audit("registration", u, "role=user")
    return jsonify(id=c.lastrowid, username=u, role="user"), 201


@auth_bp.post("/login")
def login():
    x, e = json_obj()
    if e:
        return e

    u, p = x.get("username"), x.get("password")

    if (
        not isinstance(u, str)
        or not isinstance(p, str)
        or len(u) > 50
        or len(p) > 128
    ):
        return jsonify(error="Invalid credentials"), 401

    d = get_db()
    now = time.time()

    a = d.execute(
        "SELECT failures,locked_until FROM login_attempts WHERE username=?",
        (u,)
    ).fetchone()

    if a and a["locked_until"] > now:
        audit("login_locked", u, "attempt during active lockout")
        return jsonify(error="Account temporarily locked"), 429

    user = d.execute(
        "SELECT * FROM users WHERE username=?", (u,)
    ).fetchone()

    try:
        ok = bool(user and bcrypt.checkpw(p.encode(), user["password_hash"]))
    except Exception:
        ok = False

    if not ok:
        n = (a["failures"] if a else 0) + 1

        until = (
            now + current_app.config["LOCKOUT_SECONDS"]
            if n >= current_app.config["MAX_FAILED_LOGINS"]
            else 0
        )

        d.execute(
            """
            INSERT INTO login_attempts VALUES(?,?,?)
            ON CONFLICT(username) DO UPDATE SET
                failures=excluded.failures,
                locked_until=excluded.locked_until
            """,
            (u, n, until)
        )
        d.commit()

        audit("login_failure", u, "credentials rejected")

        return (
            jsonify(
                error="Account temporarily locked"
                if n >= current_app.config["MAX_FAILED_LOGINS"]
                else "Invalid credentials"
            ),
            429 if n >= current_app.config["MAX_FAILED_LOGINS"] else 401
        )

    d.execute("DELETE FROM login_attempts WHERE username=?", (u,))

    t = secrets.token_urlsafe(32)
    exp = now + current_app.config["SESSION_TTL_SECONDS"]

    d.execute(
        "INSERT INTO sessions(user_id,token_hash,expires_at) VALUES(?,?,?)",
        (user["id"], token_hash(t), exp)
    )
    d.commit()

    audit("login_success", u, "session created")

    return jsonify(
        session_token=t,
        token_type="Bearer",
        expires_in=current_app.config["SESSION_TTL_SECONDS"]
    ), 200


@auth_bp.post("/logout")
def logout():
    h = request.headers.get("Authorization", "")

    if not h.startswith("Bearer "):
        audit("logout_failure", None, "missing bearer token")
        return jsonify(error="Authentication required"), 401

    token = h[7:].strip()
    d = get_db()

    session = d.execute(
        """
        SELECT users.username
        FROM sessions
        JOIN users ON users.id = sessions.user_id
        WHERE sessions.token_hash=?
        """,
        (token_hash(token),)
    ).fetchone()

    c = d.execute(
        "DELETE FROM sessions WHERE token_hash=?",
        (token_hash(token),)
    )
    d.commit()

    if c.rowcount:
        audit("logout_success", session["username"], "session revoked")
        return jsonify(message="Logged out"), 200

    audit("logout_failure", None, "invalid session token")
    return jsonify(error="Invalid session"), 401
