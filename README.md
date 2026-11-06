# SecureVault - Nestack Secure Records API
Python Flask API: authentication, sessions, multi-tenant record authorization, input validation, lockout, audit events, and tests.

## Windows / VS Code setup (PowerShell)
```powershell
py -3.10 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
python app.py
```
If activation is blocked: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, then activate. Or run `.venv\Scripts\python.exe` directly.
API: http://127.0.0.1:5000 ; health: GET `/health`.

## Endpoints
- POST `/register` JSON `{ "username":"alice", "password":"Password123" }` -> 201; role is always user.
- POST `/login` same JSON -> 200 with bearer token; bad credentials 401; locked 429.
- POST `/logout` with Authorization: Bearer token -> revokes token.
- POST `/records` with bearer token JSON `{ "title":"Note", "body":"Private text" }` -> 201.
- GET `/records/<id>` with bearer token -> owner/admin 200; others 404.

## Security decisions / threat model
- Passwords: bcrypt salted hashes; no plaintext. A DB leak exposes hashes, not directly passwords, but weak passwords can be guessed offline.
- Sessions: unpredictable opaque token from `secrets`; SHA-256 digest stored. Every protected request checks digest and expiry. Logout deletes session.
- IDOR: normal user query filters by both record id and authenticated owner id. Admin uses explicit separate query. Unauthorized/missing records return 404.
- Roles: registration rejects role field and assigns user server-side; no public role-change route. Admin provisioning must be trusted/out-of-band.
- Validation: JSON object, field types, nonempty values and length limits checked. Safe errors do not reveal stack traces.
- SQL injection: all SQL uses parameter placeholders.
- Brute force: failures tracked per username; after configured threshold returns 429 for lockout duration; successful login resets count.
- Audit events: login success/failure, record create/read/denial. Never log passwords, raw tokens, or record bodies.

| Threat | Mitigation | Residual risk |
|---|---|---|
| Database leak | bcrypt hashes | Weak passwords may be cracked offline |
| Token DB leak | token digests only | DB tampering/disruption possible |
| IDOR | owner predicate | Admin compromise is high impact |
| SQL injection | bound parameters | Future unsafe query could regress |
| Brute force | per-account lockout | Lockout can be abused for denial of service |
| Role escalation | server-set roles | trusted admin/database compromise |
| Malformed input | validation and length bounds | production needs more limits |

## Tests
Run `python -m pytest -v`. Tests cover hashing, login, IDOR, escalation, lockout, validation, and invalid tokens.

## Production limitations
Use HTTPS, strong environment secrets, rate limiting, monitoring, encrypted backups, and managed secret storage. Consider lockout DoS, session rotation, concurrent transactions, pagination, and more complete schema validation before production.

