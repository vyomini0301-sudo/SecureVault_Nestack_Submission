import time
from flask import request, jsonify, current_app
from database import get_db


def enforce_rate_limit():
    if not current_app.config["RATE_LIMIT_ENABLED"]:
        return None

    now = int(time.time())
    window = current_app.config["RATE_LIMIT_WINDOW_SECONDS"]
    limit = current_app.config["RATE_LIMIT_REQUESTS"]

    window_start = now - (now % window)
    client_ip = request.remote_addr or "unknown"

    db = get_db()

    db.execute(
        """
        INSERT INTO rate_limits(ip, window_start, request_count)
        VALUES(?, ?, 1)
        ON CONFLICT(ip, window_start)
        DO UPDATE SET request_count = request_count + 1
        """,
        (client_ip, window_start)
    )

    count = db.execute(
        "SELECT request_count FROM rate_limits "
        "WHERE ip=? AND window_start=?",
        (client_ip, window_start)
    ).fetchone()["request_count"]

        # Remove records from expired windows when a new window begins
    if count == 1:
        db.execute(
            "DELETE FROM rate_limits WHERE window_start < ?",
            (window_start - window,)
        )

    db.commit()

    if count > limit:
        return jsonify(
            error="Too many requests",
            retry_after=window_start + window - now
        ), 429

    return None
