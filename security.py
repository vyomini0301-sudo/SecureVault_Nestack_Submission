
import hashlib
import re
import time
from functools import wraps

from flask import g, jsonify, request

from database import get_db


def json_obj():
    if not request.is_json:
        return None, (
            jsonify(error="Content-Type must be application/json"),
            400,
        )

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return None, (
            jsonify(error="JSON body must be an object"),
            400,
        )

    return data, None


def valid_user(value):
    return (
        isinstance(value, str)
        and re.fullmatch(r"[A-Za-z0-9_.-]{3,50}", value)
        is not None
    )


def valid_pw(value):
    return isinstance(value, str) and 8 <= len(value) <= 128


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def require_auth(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        authorization = request.headers.get("Authorization", "")

        if (
            not authorization.startswith("Bearer ")
            or len(authorization) > 500
        ):
            return jsonify(error="Authentication required"), 401

        token = authorization[7:].strip()

        db = get_db()

        user = db.execute(
            """
            SELECT
                u.id,
                u.username,
                u.role,
                s.id AS session_id
            FROM sessions s
            JOIN users u ON u.id = s.user_id
            WHERE s.token_hash = ?
              AND s.expires_at > ?
            """,
            (token_hash(token), time.time()),
        ).fetchone()

        if not user:
            return jsonify(error="Invalid or expired session"), 401

        g.user = user

        return func(*args, **kwargs)

    return wrapper
