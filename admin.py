from flask import Blueprint, jsonify, g, request
from database import get_db, audit
from security import require_auth

admin_bp = Blueprint("admin", __name__)

@admin_bp.get("/admin/security-events")
@require_auth
def security_events():
    if g.user["role"] != "admin":
        audit("admin_access_denied", g.user["username"],
              "security-events endpoint")
        return jsonify(error="Administrator access required"), 403

    try:
        limit = min(max(int(request.args.get("limit", 20)), 1), 100)
        offset = max(int(request.args.get("offset", 0)), 0)
    except ValueError:
        return jsonify(error="Invalid pagination parameters"), 400

    db = get_db()

    rows = db.execute(
        "SELECT id, event, username, details, created_at "
        "FROM audit_events ORDER BY id DESC LIMIT ? OFFSET ?",
        (limit, offset)
    ).fetchall()

    audit("admin_security_events_read", g.user["username"],
          f"limit={limit},offset={offset}")

    return jsonify(
        events=[dict(row) for row in rows],
        limit=limit,
        offset=offset
    ), 200
