from database import get_db
from conftest import reg, log, hdr


def setup_users(app, client):
    reg(client, "alice")
    reg(client, "adminuser")

    with app.app_context():
        db = get_db()
        db.execute(
            "UPDATE users SET role='admin' WHERE username=?",
            ("adminuser",)
        )
        db.commit()

    alice_token = hdr(log(client, "alice"))
    admin_token = hdr(log(client, "adminuser"))

    return alice_token, admin_token


def test_admin_events_requires_auth(client):
    response = client.get("/admin/security-events")
    assert response.status_code == 401


def test_admin_events_denies_normal_user(app, client):
    alice_token, _ = setup_users(app, client)

    response = client.get(
        "/admin/security-events",
        headers=alice_token
    )

    assert response.status_code == 403
    assert response.json["error"] == "Administrator access required"


def test_admin_events_allows_admin_and_pagination(app, client):
    _, admin_token = setup_users(app, client)

    response = client.get(
        "/admin/security-events?limit=2&offset=0",
        headers=admin_token
    )

    assert response.status_code == 200
    assert response.json["limit"] == 2
    assert response.json["offset"] == 0
    assert len(response.json["events"]) <= 2

    for event in response.json["events"]:
        assert set(event.keys()) == {
            "id", "event", "username", "details", "created_at"
        }


def test_admin_events_rejects_invalid_pagination(app, client):
    _, admin_token = setup_users(app, client)

    response = client.get(
        "/admin/security-events?limit=abc",
        headers=admin_token
    )

    assert response.status_code == 400
    assert response.json["error"] == "Invalid pagination parameters"
def test_ip_rate_limit_returns_429(tmp_path):
    from app import create_app

    app = create_app({
        "TESTING": True,
        "DATABASE": str(tmp_path / "rate.db"),
        "BCRYPT_ROUNDS": 4,
        "RATE_LIMIT_ENABLED": True,
        "RATE_LIMIT_REQUESTS": 2,
        "RATE_LIMIT_WINDOW_SECONDS": 60
    })

    client = app.test_client()

    first = client.get("/health")
    second = client.get("/health")
    third = client.get("/health")

    assert first.status_code == 200
    assert second.status_code == 200
    assert third.status_code == 429
    assert third.json["error"] == "Too many requests"
    assert "retry_after" in third.json
def test_security_headers(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["Content-Security-Policy"] == "default-src 'none'"
    assert response.headers["Referrer-Policy"] == "no-referrer"
