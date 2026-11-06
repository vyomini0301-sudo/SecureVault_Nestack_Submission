import sqlite3
from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash BLOB NOT NULL,
    role TEXT NOT NULL DEFAULT 'user'
        CHECK(role IN ('user','admin'))
);

CREATE TABLE IF NOT EXISTS sessions(
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    token_hash TEXT UNIQUE NOT NULL,
    expires_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS records(
    id INTEGER PRIMARY KEY,
    owner_id INTEGER NOT NULL REFERENCES users(id),
    title TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS login_attempts(
    username TEXT PRIMARY KEY,
    failures INTEGER NOT NULL,
    locked_until REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events(
    id INTEGER PRIMARY KEY,
    event TEXT,
    username TEXT,
    details TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER IF NOT EXISTS prevent_audit_event_update
BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit events are append-only');
END;

CREATE TRIGGER IF NOT EXISTS prevent_audit_event_delete
BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit events are append-only');
END;

CREATE TABLE IF NOT EXISTS rate_limits(
    ip TEXT NOT NULL,
    window_start INTEGER NOT NULL,
    request_count INTEGER NOT NULL,
    PRIMARY KEY(ip, window_start)
);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(
            current_app.config["DATABASE"], timeout=10
        )
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


def close_db(e=None):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db(app):
    with app.app_context():
        c = sqlite3.connect(app.config["DATABASE"])
        c.execute("PRAGMA foreign_keys=ON")
        c.executescript(SCHEMA)
        c.close()
    app.teardown_appcontext(close_db)


def audit(event, username=None, details=None):
    d = get_db()
    d.execute(
        "INSERT INTO audit_events(event,username,details) VALUES(?,?,?)",
        (event, username, details)
    )
    d.commit()
