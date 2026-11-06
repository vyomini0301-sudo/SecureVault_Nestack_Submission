import sqlite3


def get_events(app):
    db = sqlite3.connect(app.config["DATABASE"])
    rows = db.execute(
        "SELECT event, username, details FROM audit_events ORDER BY id"
    ).fetchall()
    db.close()
    return rows


def test_registration_and_successful_login_are_audited(client, app):
    client.post("/register", json={
        "username": "audituser",
        "password": "Password123"
    })

    client.post("/login", json={
        "username": "audituser",
        "password": "Password123"
    })

    events = get_events(app)

    assert ("registration", "audituser", "role=user") in events
    assert ("login_success", "audituser", "session created") in events


def test_failed_login_is_audited(client, app):
    client.post("/register", json={
        "username": "audituser",
        "password": "Password123"
    })

    response = client.post("/login", json={
        "username": "audituser",
        "password": "WrongPassword123"
    })

    assert response.status_code == 401

    events = get_events(app)

    assert (
        "login_failure",
        "audituser",
        "credentials rejected"
    ) in events

def test_account_lockout_is_audited(client, app):
    client.post("/register", json={
        "username": "lockaudit",
        "password": "Password123"
    })

    for _ in range(3):
        response = client.post("/login", json={
            "username": "lockaudit",
            "password": "WrongPassword123"
        })

    assert response.status_code == 429

    events = get_events(app)
    failures = [
        event for event in events
        if event[0] == "login_failure" and event[1] == "lockaudit"
    ]

    assert len(failures) == 3

def test_active_lockout_attempt_is_audited(client, app):
    client.post("/register", json={
        "username": "lockaudit",
        "password": "Password123"
    })

    for _ in range(3):
        client.post("/login", json={
            "username": "lockaudit",
            "password": "WrongPassword123"
        })

    response = client.post("/login", json={
        "username": "lockaudit",
        "password": "Password123"
    })

    assert response.status_code == 429
    events = get_events(app)
    assert ("login_locked", "lockaudit", "attempt during active lockout") in events


def test_logout_success_is_audited(client, app):
    client.post("/register", json={
        "username": "logoutuser",
        "password": "Password123"
    })

    login_response = client.post("/login", json={
        "username": "logoutuser",
        "password": "Password123"
    })
    token = login_response.json["session_token"]

    response = client.post("/logout", headers={
        "Authorization": f"Bearer {token}"
    })

    assert response.status_code == 200
    events = get_events(app)
    assert ("logout_success", "logoutuser", "session revoked") in events


def test_logout_failure_is_audited(client, app):
    response = client.post("/logout")

    assert response.status_code == 401
    events = get_events(app)
    assert ("logout_failure", None, "missing bearer token") in events

def test_audit_events_cannot_be_updated(app, client):
    import pytest
    import sqlite3

    client.post("/register", json={
        "username": "tamperuser",
        "password": "Password123"
    })

    db = sqlite3.connect(app.config["DATABASE"])

    with pytest.raises(sqlite3.IntegrityError):
        db.execute(
            "UPDATE audit_events SET details='modified' WHERE event='registration'"
        )

    db.close()


def test_audit_events_cannot_be_deleted(app, client):
    import pytest
    import sqlite3

    client.post("/register", json={
        "username": "tamperuser",
        "password": "Password123"
    })

    db = sqlite3.connect(app.config["DATABASE"])

    with pytest.raises(sqlite3.IntegrityError):
        db.execute(
            "DELETE FROM audit_events WHERE event='registration'"
        )

    db.close()