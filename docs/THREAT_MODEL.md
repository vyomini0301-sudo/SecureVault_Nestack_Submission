# SecureVault Threat Model

## 1. Document Information

- **Project:** SecureVault
- **Framework:** Flask
- **Database:** SQLite
- **Methodology:** STRIDE
- **Status:** Implemented security controls with automated validation

## 2. System Overview

SecureVault is a secure record management API supporting registration,
authentication, session management, record creation and retrieval,
role-based authorization, and security audit logging.

### Main Components

1. Client: Sends HTTP requests to the Flask API.
2. Flask application: Handles authentication, authorization,
   validation, rate limiting, and record operations.
3. SQLite database: Stores users, password hashes, sessions,
   records, login attempts, rate limits, and audit events.

## 3. Security Assets

| Asset | Security Requirement |
|---|---|
| User credentials | Confidentiality |
| Session tokens | Confidentiality and integrity |
| Records | Confidentiality and integrity |
| User roles | Integrity |
| Audit events | Integrity and accountability |
| Authentication state | Integrity |

## 4. Trust Boundaries

- Client to Flask API: Untrusted input and authentication boundary.
- Flask API to SQLite: Application-controlled database boundary.
- User to administrator: Privilege boundary.
- Authenticated session to expired or revoked session: Session boundary.

## 5. STRIDE Threat Analysis

| Threat | Example | Existing Mitigation | Residual Risk |
|---|---|---|---|
| Spoofing | Attacker impersonates a user | bcrypt password hashing, session tokens, login lockout | Credential theft and phishing remain possible |
| Tampering | Attacker modifies another user's record | Ownership checks, parameterized SQL, input validation | Database compromise remains possible |
| Repudiation | User denies performing an action | Audit logging and append-only SQLite triggers | Privileged database access can bypass trigger protections |
| Information Disclosure | Unauthorized user reads private records | Authentication, ownership checks, no-store header | Network interception without TLS |
| Denial of Service | Repeated requests exhaust resources | Account lockout and IP-based rate limiting | Shared-IP quotas, fixed-window bursts, resource exhaustion |
| Elevation of Privilege | User attempts administrator access | Registration role restriction, RBAC, administrator endpoint authorization | Administrator provisioning requires controlled access |

## 6. Implemented Security Controls

- bcrypt password hashing.
- SHA-256 hashed session token storage.
- Session expiration and logout revocation.
- Authentication middleware.
- Role-based access control.
- Record ownership enforcement.
- Parameterized SQL queries.
- Input and JSON validation.
- Account lockout.
- IP-based request rate limiting.
- Security audit events.
- Append-only audit protection using SQLite triggers.
- HTTP security headers.
- Automated regression tests.
- Configurable security parameters with validation.

## 7. Security Testing Evidence

Automated regression tests cover:

- Registration and login.
- Password hash verification.
- Unauthorized record access and IDOR prevention.
- Role escalation prevention.
- Account lockout and active lockout attempts.
- Invalid session token rejection.
- Administrator access control and pagination.
- IP-based request rate limiting.
- HTTP security headers.
- Registration, login, failed login, and lockout audit events.
- Successful and failed logout audit events.
- Audit event persistence.
- Audit event UPDATE and DELETE prevention.
- Configuration value validation.

**Automated regression result: 25 tests passed.**

## 8. Identified Security Gaps

- Audit logs are append-only through SQLite triggers but are not cryptographically tamper-evident.
- Production HTTPS and TLS configuration have not been verified.
- Production deployment hardening is incomplete.
- STRIDE coverage is not exhaustive; additional threat-specific testing is recommended.
- Database-level access remains a privileged trust boundary.

## 9. Security Objectives

1. Protect confidentiality of user records.
2. Prevent unauthorized access and privilege escalation.
3. Improve resistance to abuse and excessive requests.
4. Improve security event visibility and accountability.
5. Validate implemented controls through automated testing.
6. Document residual risks and security assumptions.

## 10. Conclusion

SecureVault implements foundational authentication, authorization,
session management, input validation, rate limiting, and audit
logging controls.

The threat model identifies potential attack scenarios,
documents implemented mitigations, and records remaining risks.

The implemented controls reduce identified risks but do not
eliminate all STRIDE threats. Production deployment security,
HTTPS configuration, privileged database access, and further
security testing remain areas for review.

## 11. Implemented Security Engineering Enhancements

### 11.1 IP-Based Request Rate Limiting

A configurable fixed-window IP-based rate limiter has been
implemented using SQLite.

- Applied globally through Flask before-request middleware.
- Configurable request limit and time window.
- Returns HTTP 429 when the configured limit is exceeded.
- Includes a retry_after value in the response.
- Expired rate-limit window records are periodically cleaned up.
- Can be enabled or disabled through environment configuration.

### 11.2 Administrator Security Event API

An administrator-only endpoint has been implemented:

`GET /admin/security-events`

Security controls include:

- Authentication required.
- Administrator role verification.
- Non-administrator requests receive HTTP 403.
- Pagination using limit and offset.
- Maximum page size restricted to 100 events.
- Invalid pagination parameters are rejected.
- Security-event access is recorded in the audit log.
- Unauthorized administrator endpoint access is audited.
- Only selected audit-event fields are returned.

## 12. Updated Security Validation Evidence

The automated regression test suite contains **25 passing tests**.

| Security Control | Validation Test |
|---|---|
| Registration and password hashing | `test_registration_login_and_hash` |
| Record ownership and IDOR prevention | `test_idor_and_owner_access` |
| Role escalation prevention | `test_role_escalation` |
| Account lockout | `test_lockout` |
| Authentication and input validation | `test_validation_and_auth` |
| Invalid session token rejection | `test_bad_token` |
| Administrator authentication | `test_admin_events_requires_auth` |
| Administrator role enforcement | `test_admin_events_denies_normal_user` |
| Administrator event retrieval and pagination | `test_admin_events_allows_admin_and_pagination` |
| Invalid pagination rejection | `test_admin_events_rejects_invalid_pagination` |
| IP-based request rate limiting | `test_ip_rate_limit_returns_429` |
| HTTP security headers | `test_security_headers` |
| Registration and successful login audit | `test_registration_and_successful_login_are_audited` |
| Failed login audit | `test_failed_login_is_audited` |
| Account lockout audit | `test_account_lockout_is_audited` |
| Active lockout attempt audit | `test_active_lockout_attempt_is_audited` |
| Successful logout audit | `test_logout_success_is_audited` |
| Failed logout audit | `test_logout_failure_is_audited` |
| Audit UPDATE prevention | `test_audit_events_cannot_be_updated` |
| Audit DELETE prevention | `test_audit_events_cannot_be_deleted` |
| Positive configuration value | `test_positive_int_accepts_valid_value` |
| Zero configuration rejection | `test_positive_int_rejects_zero` |
| Negative configuration rejection | `test_positive_int_rejects_negative` |
| Maximum configuration enforcement | `test_positive_int_rejects_value_above_maximum` |
| Invalid integer configuration rejection | `test_positive_int_rejects_invalid_integer` |

**Latest regression result: 25 passed.**

## 13. Updated Residual Risks and Limitations

The following risks remain:

- Audit events are not protected by cryptographic tamper-evident mechanisms.
- Production HTTPS and TLS configuration have not been verified.
- SQLite rate limiting is intended for a local or single-instance deployment and does not coordinate limits across multiple application instances.
- Fixed-window rate limiting may permit bursts around window boundaries.
- Users sharing an IP address also share the IP-based request quota.
- Reverse-proxy trust configuration requires review before deployment behind a proxy.
- Administrator provisioning requires controlled database-level access.
- Production deployment hardening and security review remain incomplete.

## 14. Security Assessment Status

SecureVault has progressed from its initial threat assessment
to implemented and tested security enhancements.

The administrator security-event API, IP-based request rate
limiting, HTTP security headers, authentication audit logging,
configuration validation, and append-only audit protection
have been implemented.

The automated regression suite currently contains **25 passing tests**.

The implemented controls reduce identified risks but do not
eliminate all STRIDE threats. Production deployment security,
HTTPS configuration, privileged database access, and further
security testing remain areas for review.

## 15. HTTP Security Headers

SecureVault applies HTTP security headers through Flask
after-request middleware.

| Header | Value | Purpose |
|---|---|---|
| X-Content-Type-Options | nosniff | Prevents MIME type sniffing |
| X-Frame-Options | DENY | Prevents framing of responses |
| Cache-Control | no-store | Prevents storage of sensitive responses |
| Content-Security-Policy | default-src 'none' | Restricts browser resource loading |
| Referrer-Policy | no-referrer | Prevents referrer information leakage |

### Automated Validation

- **Test:** `test_security_headers`
- **Endpoint:** `GET /health`
- **Result:** All five configured headers verified.
- **Full regression suite:** 25 tests passed.

These headers do not replace HTTPS/TLS. The CSP is API-oriented
and should be reviewed if browser-rendered frontend content
is introduced.

## 16. Audit Logging and Append-Only Protection

SecureVault records authentication and security-related events
to the SQLite `audit_events` table.

### 16.1 Audited Events

| Event | Description |
|---|---|
| registration | User account creation |
| login_success | Successful authentication |
| login_failure | Rejected credentials |
| login_locked | Login attempt during active lockout |
| logout_success | Session revocation |
| logout_failure | Failed logout attempt |
| admin_access_denied | Unauthorized administrator endpoint access |
| admin_security_events_read | Administrator security-event access |

### 16.2 Append-Only Enforcement

SQLite triggers prevent UPDATE and DELETE operations on
`audit_events` through normal SQL operations.

- `prevent_audit_event_update`
- `prevent_audit_event_delete`

Automated tests verify both protections.

### 16.3 Limitations

Append-only triggers provide protection against ordinary
modification and deletion attempts but are not cryptographic
tamper-proofing.

A privileged database operator may remove triggers or modify
the database file. Stronger protection would require external
log storage, cryptographic integrity verification, or a
separate trusted logging system.
