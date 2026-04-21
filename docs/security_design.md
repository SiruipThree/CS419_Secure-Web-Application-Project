# Security Design Document

**CS 419: Secure Web Application Project — Spring 2026**

---

## 1. Executive Summary

This document describes the security design of a **Secure Document Sharing System** built for CS 419 (Spring 2026). The application allows users to register, upload encrypted documents, share them with specific users under controlled roles, and maintain a full audit trail of all actions.

**Security goals:**
- Protect document confidentiality at rest (Fernet AES-128-CBC + HMAC-SHA256) and in transit (TLS/HTTPS).
- Enforce strict access control through a two-layer model: system roles (admin, user, guest) and document roles (owner, editor, viewer).
- Resist common web attacks including XSS, CSRF, path traversal, command injection, and brute-force login.
- Maintain comprehensive audit logging of all authentication, authorization, and data access events.

**Architecture.** The system is a Python/Flask server-rendered web application using file-based JSON storage (no external database). Sessions are managed entirely server-side with `secrets.token_urlsafe(32)` tokens. Passwords are hashed with bcrypt (cost factor 12). All seven required HTTP security headers are applied to every response.

**Threat model.** Sixteen threats are identified using the STRIDE framework, covering spoofing, tampering, information disclosure, denial of service, and privilege escalation. Each threat is mapped to implemented mitigations and residual risks.

**Testing.** The automated test suite includes 73 passing tests covering registration, login, lockout, rate limiting, RBAC, document upload/download/share/delete, session lifecycle, and audit logging.

**Known limitations.** Residual risks include EICAR-only malware scanning, single-key encryption without rotation, JSON file storage concurrency constraints, and CSP `'unsafe-inline'`. Each limitation is documented with a proposed future improvement.

---

## 2. Architecture Overview

### 2.1 System Purpose and Scope

The Secure Document Sharing System is a web application that enables users to upload, encrypt, share, and collaboratively manage confidential documents under strict access controls. The system is designed to protect document confidentiality at rest and in transit, enforce role-based and document-level authorization, maintain a complete audit trail of all security-relevant events, and resist common web application attacks.

The primary assets protected by the system are:

- **Uploaded documents** — encrypted at rest using symmetric encryption (Fernet) before being written to disk; never stored in plaintext on the server.
- **User credentials** — passwords are hashed with bcrypt (cost factor 12) and are never stored or transmitted in plaintext.
- **Session tokens** — generated with cryptographically secure random values and managed entirely on the server side.
- **Encryption keys** — the Fernet master key (`secret.key`) is stored outside the data directory and is required to decrypt every document.
- **Audit logs** — immutable-append records of authentication attempts, data access events, authorization failures, and administrative actions.

### 2.2 High-Level Runtime Architecture

The system follows a traditional server-rendered web application architecture with three logical tiers: **(1) Client tier** — the browser sends HTTPS requests and receives server-rendered HTML; the session token is stored in an HttpOnly/Secure cookie. **(2) Application tier** — the Flask web application, composed of nine backend modules (described in Section 2.3). **(3) Persistence tier** — file-based JSON storage (`data/users.json`, `sessions.json`, `documents.json`, `shares.json`, `audit.json`, `rate_limits.json`), encrypted document payloads in `data/documents/*.bin`, structured log files in `logs/`, and the Fernet encryption key in `secret.key`.

**Request lifecycle.** Every incoming HTTP request passes through the following middleware chain defined in `app.py` before reaching any route handler:

1. **HTTPS enforcement** (`require_https`) — In non-development environments, all HTTP requests are redirected to HTTPS with a 301 status code. The check respects the `X-Forwarded-Proto` header for reverse-proxy deployments.
2. **Session resolution** (`load_current_user`) — The server reads the session cookie, validates the token against `sessions.json`, checks expiration, and populates `g.current_user` with the authenticated identity or an anonymous placeholder.
3. **CSRF validation** (`enforce_csrf`) — For all state-changing HTTP methods (POST, PUT, PATCH, DELETE), the server verifies that the submitted `csrf_token` form field matches the token stored in the server-side session. Mismatches are logged and rejected with 403.
4. **Security headers** (`set_headers`) — Every response receives a full set of defensive HTTP headers (CSP, X-Frame-Options, X-Content-Type-Options, HSTS, etc.) via `apply_security_headers()`.

### 2.3 Core Component Descriptions

The application logic is organized into the following backend modules, each with a single clearly-defined responsibility:

| Module | Responsibility |
|---|---|
| `app.py` | Application factory (`create_app()`), request middleware chain, route definitions, decorator-based authentication (`require_auth`) and authorization (`require_role`). Serves as the sole entry point and orchestrator — it delegates all domain logic to the modules below. |
| `config.py` | Centralized configuration via a single `Config` class. All security-sensitive settings (session timeout, cookie flags, lockout thresholds, upload limits, file paths, TLS settings) are driven by environment variables with safe development defaults. In production, missing `SECRET_KEY` causes an immediate startup failure. |
| `secure_app/auth.py` | `UserAuth` class encapsulating registration, login, password change, account lockout/unlock, and role management. Passwords are hashed with bcrypt (cost factor 12). Login enforces per-account lockout after a configurable number of failed attempts and per-IP rate limiting. All authentication events (success, failure, lockout, registration) are logged. |
| `secure_app/sessions.py` | Server-side session lifecycle — creation, validation, timeout sliding-window renewal, explicit invalidation (logout), and concurrent-session eviction. Tokens are generated with `secrets.token_urlsafe(32)`. Each session includes a CSRF token. Session events (create, destroy, expire) are logged. |
| `secure_app/access_control.py` | Defines three system roles (admin, user, guest) with a permission matrix and three document roles (owner, editor, viewer). Provides pure predicate functions (`can_create_content()`, `can_download_document()`, `can_delete_document()`, etc.) that are consumed by `app.py` decorators and route handlers. No I/O or side effects. |
| `secure_app/documents.py` | Complete document lifecycle — upload with encryption, versioning, download with decryption, sharing, inline editing (for text files), preview generation (text, image, PDF, DOCX), return-to-owner workflow, and permanent deletion with encrypted payload cleanup. Every mutation is recorded in both the access log and the structured audit trail (`audit.json`). |
| `secure_app/security.py` | Input validation and output sanitization library — username/email/password/URL validators, file upload validation (extension whitelist, MIME-type check, magic-byte signature verification, EICAR malware scan), path traversal prevention via `safe_file_path()`, XSS-safe text escaping, and the `apply_security_headers()` function. |
| `secure_app/storage.py` | Low-level JSON persistence layer — `load_json()`, `save_json()` with atomic writes via temporary files, and `bootstrap_storage()` which creates required directories and seed files on first run. |
| `secure_app/logging_utils.py` | `SecurityLogger` and `AccessLogger` classes wrapping Python's `logging` module. Each produces structured JSON log entries with timestamp, event type, user ID, IP address, user agent, and event-specific details. Log files are configured at application startup. |

### 2.4 Trust Boundaries

The system has five distinct trust boundaries:

**Boundary 1 — Network perimeter.** All client-server communication is intended to travel over TLS. In non-development mode, the application redirects HTTP to HTTPS and sets the HSTS header. The session cookie carries `Secure`, `HttpOnly`, and `SameSite=Strict` flags, preventing it from being transmitted over plaintext or accessed by client-side scripts.

**Boundary 2 — Authenticated vs. unauthenticated.** The `load_current_user` middleware resolves every request into either an authenticated identity or an anonymous placeholder. The `require_auth` decorator enforces this boundary at the route level.

**Boundary 3 — System role authorization.** The RBAC permission matrix in `access_control.py` distinguishes three system roles. The `require_role` decorator checks system-level permissions before any route logic executes. Failed checks are logged as `AUTHORIZATION_DENIED` events.

**Boundary 4 — Document role authorization.** Even after passing system-level checks, every document operation goes through a second authorization layer. Functions like `authorize_document_access()`, `authorize_document_download()`, and `authorize_document_delete()` resolve the user's document-level role (owner, editor, or viewer) from the shares store and compare it against the required permission for the action.

**Boundary 5 — Application-to-persistence.** The application treats the file system as a trusted but integrity-critical store. JSON files are written atomically (write to temp file, then rename) to prevent corruption. Document payloads are always encrypted before being written. Path traversal is blocked by `safe_file_path()`, which resolves and validates every file path against the storage base directory.

### 2.5 Technology Stack Justification

| Technology | Purpose | Justification |
|---|---|---|
| **Python 3 / Flask** | Web framework | Flask is one of the two recommended frameworks in the course specification. Its minimalist design gives full visibility into the security middleware pipeline — every security control (session handling, CSRF protection, security headers) is explicitly implemented rather than hidden in framework internals, which strengthens both auditability and learning value. |
| **bcrypt (cost factor 12)** | Password hashing | bcrypt is explicitly required by the project specification. Cost factor 12 is the specified minimum. The algorithm's built-in salt and adaptive cost make it resistant to GPU-accelerated brute-force attacks. |
| **cryptography / Fernet** | Data-at-rest encryption | Fernet provides authenticated symmetric encryption (AES-128-CBC + HMAC-SHA256) in a single high-level API. It is listed as a recommended library in the course specification. Fernet guarantees that any tampering with the ciphertext is detected at decryption time. |
| **JSON file storage** | Persistence | The course specification explicitly states "NO DATABASE REQUIRED" and recommends structured JSON file storage. This removes the need for a separate database server, simplifies deployment, and keeps the project self-contained. The trade-off is that JSON file I/O does not support concurrent writes or transactions — acceptable for a teaching project but not suitable for production workloads. |
| **Server-side sessions** | Session management | Rather than using Flask's default client-side signed cookies, sessions are stored entirely on the server in `sessions.json`. This ensures that session data (including CSRF tokens) cannot be inspected or replayed by the client, and allows the server to enforce single-session-per-user, explicit invalidation, and sliding-window timeouts. |
| **Jinja2 auto-escaping** | XSS prevention | Flask's default Jinja2 template engine auto-escapes all template variables, which provides a strong baseline defense against reflected and stored XSS. The application additionally performs server-side input sanitization via `html.escape()` in `security.py`. |
| **Python `secrets` module** | Token generation | `secrets.token_urlsafe(32)` is used for both session tokens and CSRF tokens. This module is designed for cryptographic use and draws from the operating system's CSPRNG. |

---

## 3. Data Flow

This section traces the four primary data flows through the system, highlighting where each security control is applied.

### 3.1 User Registration and Authentication

**Registration flow.** Browser → `POST /register` (username, email, password, confirm) → (1) `validate_username()`, (2) `validate_email()`, (3) `validate_password_strength()`, (4) check duplicate user/email, (5) `bcrypt.hashpw(cost=12)`, (6) save to `users.json`, (7) log `USER_REGISTERED`, (8) invalidate prior sessions, (9) `create_session()` (token + CSRF), (10) write `sessions.json`, (11) log `SESSION_CREATED` → 302 + Set-Cookie (HttpOnly, Secure, SameSite=Strict).

Key security controls:
- **Input validation**: Username must match `^[A-Za-z0-9_]{3,20}$`; email must match a standard pattern; password must be ≥ 12 characters with uppercase, lowercase, digit, and special character.
- **Duplicate detection**: Both username and email are checked for uniqueness before insertion.
- **Password hashing**: bcrypt with cost factor 12; the plaintext password is never written to disk.
- **Automatic session creation**: A new server-side session is created immediately after registration, avoiding a separate login step.
- **Event logging**: `USER_REGISTERED` and `SESSION_CREATED` events are logged with IP and timestamp.

**Login flow.** Browser → `POST /login` (identifier, password) → (1) `_check_rate_limit(IP)` (≤10/min), (2) find user by name or email, (3) check `locked_until`, (4) `bcrypt.checkpw()`. On success: reset `failed_attempts`, log `LOGIN_SUCCESS`. On failure: increment `failed_attempts`; if ≥5 → lock 15 min, log `LOGIN_FAILED`/`ACCOUNT_LOCKED`. Then (5) `invalidate_user_sessions()`, (6) `create_session()`, (7) log `SESSION_CREATED` → 302 + Set-Cookie.

Key security controls:
- **Per-IP rate limiting**: At most 10 login attempts per IP address per minute, tracked in `rate_limits.json`. Exceeding the limit triggers a `SUSPICIOUS_ACTIVITY` log event.
- **Account lockout**: After 5 consecutive failed password attempts, the account is locked for 15 minutes. Both thresholds are config-driven.
- **Concurrent session eviction**: On successful login, all existing sessions for the same user are invalidated before a new session is created, preventing session fixation and unauthorized parallel access.
- **Generic error messages**: The login endpoint returns "Invalid credentials" for both unknown users and wrong passwords, preventing username enumeration.

### 3.2 Document Upload and Encryption

Browser → `POST /upload` (title, type, file) → `require_auth` + `require_role(can_create_content)` → `store_encrypted_document()`: (1) `validate_document_title()`, (2) `validate_uploaded_file()` (extension whitelist → MIME check → magic-byte signature → EICAR scan), (3) `Fernet.encrypt(plaintext)`, (4) write encrypted `.bin`, (5) SHA-256 hash of plaintext, (6) append to `documents.json`, (7) append audit event, (8) log `DOCUMENT_UPLOAD` → 200 success.

Key security controls:
- **Authorization gate**: Only authenticated users with `create_content` permission (admin or user roles; not guest) can upload.
- **Four-layer file validation**: Extension whitelist → MIME type check → magic-byte signature verification → EICAR malware signature scan. Any failure is logged as `UPLOAD_VALIDATION_FAILED`.
- **Encryption before storage**: The file's plaintext bytes are encrypted with Fernet (AES-128-CBC + HMAC-SHA256) before being written to disk. The plaintext never touches the file system.
- **Integrity hash**: A SHA-256 digest of the plaintext is stored in document metadata, enabling tamper detection at download time.
- **Atomic JSON writes**: `save_json()` writes to a temporary file first, then atomically renames it, preventing data corruption on crash.

### 3.3 Document Sharing and Access Control

Browser → `POST /share` (recipient, access_role) → `require_auth` → `authorize_document_access()`: (1) `get_document_role()` from `shares.json`, (2) `authorize_document_share_management()` (owner/admin only) → `share_document_with_user()`: (3) validate role in {viewer, editor}, (4) check not self-share, (5) check recipient exists, (6) upsert `shares.json`, (7) log `DOCUMENT_SHARED`, (8) append audit event → 200 success.

**Return-to-owner flow.** When a user holds the `editor` document role and shares the document back to its owner, the system treats this as a "return" rather than a standard share: the editor's own role is downgraded from `editor` to `viewer`, and a `DOCUMENT_RETURNED_TO_OWNER` audit event is recorded. This prevents an editor from retaining edit privileges after handing back ownership control.

**Two-layer authorization model.** Every document access request is authorized in two stages:

1. **System role check** — the `require_role` decorator verifies the user's system-level permission (e.g., `can_view_shared_content`).
2. **Document role check** — functions in `documents.py` resolve the user's document-specific role from `shares.json` and verify it against the required level for the operation (view, edit, download, delete, manage shares).

This ensures that even an authenticated user with a valid session cannot access a document unless they have been explicitly granted a document-level role.

### 3.4 Document Download and Decryption

Browser → `GET /download` → `require_auth` → `decrypt_document()`: (1) `authorize_document_download()` (system + doc role), (2) `get_document_revision()` (resolve from history), (3) `safe_file_path()` (path traversal check), (4) read encrypted `.bin`, (5) `Fernet.decrypt()` (AES + HMAC verify), (6) log `DOCUMENT_DOWNLOAD`, (7) append audit event → 200 binary (Content-Disposition: attachment).

Key security controls:
- **Download authorization**: `can_download_document()` requires the user to be authenticated and hold any document role (owner, editor, or viewer). Unauthenticated users and users without a share entry are rejected with 403.
- **Version-aware decryption**: Each document version has its own encrypted `.bin` file. The requested version is resolved from the document's `version_history`, preventing an attacker from guessing storage file names.
- **Path traversal prevention**: Before reading any file from disk, `safe_file_path()` resolves the absolute path and verifies it falls within the `DOCUMENT_STORAGE_DIR` boundary.
- **Authenticated decryption**: Fernet decryption includes HMAC verification — if the ciphertext has been tampered with, decryption raises an `InvalidToken` exception rather than returning corrupted data.
- **Audit trail**: Every successful download is recorded in both `access.log` (structured JSON) and `audit.json` with the document ID, filename, version number, and the user's document role.

---

## 4. Threat Model

### 4.1 Asset Identification

The following table classifies the system's protected assets by sensitivity and maps each to the storage location and primary defense mechanism:

| Asset | Sensitivity | Storage Location | Primary Defense |
|---|---|---|---|
| User passwords | Critical | `data/users.json` (bcrypt hashes only) | bcrypt cost-12 hashing; plaintext never stored |
| Fernet encryption key | Critical | `secret.key` (file on disk) | File-system permissions; outside data directory |
| Uploaded documents | High | `data/documents/*.bin` (encrypted) | Fernet AES-128-CBC + HMAC-SHA256 at rest |
| Session tokens | High | `data/sessions.json` (server-side) | `secrets.token_urlsafe(32)`; HttpOnly/Secure cookie |
| CSRF tokens | High | `data/sessions.json` (server-side) | Per-session random token; validated on every state-changing request |
| Document metadata | Medium | `data/documents.json` | Two-layer authorization (system role + document role) |
| Share rules | Medium | `data/shares.json` | Owner/admin-only share management |
| Audit trail | Medium | `data/audit.json`, `logs/security.log` | Append-only writes; admin-visible only |
| User profile data | Medium | `data/users.json` | Authentication + system role checks |
| Rate-limit counters | Low | `data/rate_limits.json` | Application-internal; auto-expires |

### 4.2 Threat Enumeration

This section enumerates threats using the STRIDE model and maps each to the relevant system component:

| ID | STRIDE Category | Threat | Target Component |
|---|---|---|---|
| T1 | Spoofing | Brute-force login to guess credentials | `auth.py` — login endpoint |
| T2 | Spoofing | Credential stuffing with leaked passwords | `auth.py` — login endpoint |
| T3 | Spoofing | Session hijacking via token theft | `sessions.py` — cookie transport |
| T4 | Tampering | Modify encrypted document on disk | `documents/` — `.bin` payloads |
| T5 | Tampering | Tamper with JSON metadata files | `data/*.json` files |
| T6 | Tampering | CSRF attack on state-changing endpoints | `app.py` — POST routes |
| T7 | Repudiation | User denies performing a document action | `audit.json` — audit trail |
| T8 | Info. Disclosure | Path traversal to read arbitrary files | `documents.py` — download routes |
| T9 | Info. Disclosure | XSS to steal session cookie | Templates — rendered HTML |
| T10 | Info. Disclosure | Direct access to encrypted `.bin` files | File-system / web server |
| T11 | Info. Disclosure | Username enumeration via login errors | `auth.py` — error messages |
| T12 | Denial of Service | Flood login endpoint to lock accounts | `auth.py` — lockout mechanism |
| T13 | Denial of Service | Upload oversized files to exhaust disk | `app.py` — upload endpoint |
| T14 | Elev. of Privilege | Horizontal privilege escalation (access another user's document) | `documents.py` — authorization |
| T15 | Elev. of Privilege | Vertical privilege escalation (user → admin) | `access_control.py` — role checks |
| T16 | Tampering | Malicious file upload (malware, script) | `security.py` — upload validation |

### 4.3 Vulnerability Assessment and Implemented Mitigations

| Threat ID | Implemented Mitigation | Residual Risk |
|---|---|---|
| T1 | Account lockout after 5 failures (15 min); per-IP rate limit (10/min); bcrypt cost-12 | Distributed brute-force across many IPs could bypass per-IP limits |
| T2 | Same as T1; additionally, password complexity requires ≥ 12 chars, mixed case, digit, special char | Users reusing passwords from other breaches cannot be detected without external breach-database checks |
| T3 | HttpOnly + Secure + SameSite=Strict cookie flags; server-side session storage; HTTPS enforcement; 30-min sliding timeout | If TLS is not properly terminated (e.g., misconfigured reverse proxy), the Secure flag alone does not prevent interception |
| T4 | Fernet authenticated encryption (HMAC-SHA256); tampered ciphertext causes `InvalidToken` exception on decryption | If the Fernet key file (`secret.key`) is compromised, all documents can be decrypted |
| T5 | Atomic JSON writes (temp file + rename); application is the sole writer; no user-facing API exposes raw JSON paths | A local attacker with file-system access could modify JSON files directly |
| T6 | Per-session CSRF token validated on every POST/PUT/PATCH/DELETE; SameSite=Strict cookie | Subdomains could theoretically bypass SameSite in certain browser configurations |
| T7 | Comprehensive audit trail in `audit.json` with timestamp, user ID, event type, and details for every document and auth action | Audit trail is append-only at the application level but not cryptographically signed; a root-level attacker could modify `audit.json` |
| T8 | `safe_file_path()` resolves absolute path and verifies it is within the base directory; `secure_filename()` strips path components | Covered — no known residual risk for file-system path traversal |
| T9 | Jinja2 auto-escaping on all template variables; server-side `html.escape()` in `security.py`; CSP header restricts script sources | CSP currently allows `'unsafe-inline'` for scripts, which weakens XSS protection |
| T10 | Documents stored as randomly-named `.bin` files; no static file serving for `data/` directory; download requires authentication + authorization | If the web server is misconfigured to serve the `data/` directory, encrypted files would be downloadable (but still encrypted) |
| T11 | Login returns generic "Invalid credentials" for both unknown users and wrong passwords | Timing side-channel: bcrypt is not called for unknown users, potentially allowing timing-based enumeration |
| T12 | Per-IP rate limiting caps login attempts at 10/min; account lockout is time-bounded (15 min) | An attacker could intentionally lock out a target user by submitting 5 wrong passwords for their username |
| T13 | `MAX_CONTENT_LENGTH` limits upload size (default 16 MB); file type whitelist restricts allowed formats | No per-user storage quota; a malicious user could upload many valid files to fill disk |
| T14 | `authorize_document_access()` checks document role for every operation; shares are explicit (no wildcard grants to regular users) | Covered — each document operation individually verifies the user's document-level role |
| T15 | System roles are stored server-side in `users.json`; role changes require admin privilege and are audit-logged as `USER_ROLE_CHANGED` | Admin self-role-change is blocked in the UI, but the authorization model trusts the admin role absolutely |
| T16 | Four-layer validation: extension whitelist, MIME type, magic-byte signature, EICAR scan; all failures logged | EICAR scan only detects the test signature, not real malware; known limitation documented in Section 8 |

### 4.4 Attack Scenarios

**Scenario 1 — Credential brute-force attack.**
An attacker uses an automated tool to try common passwords against a known username. After 5 failed attempts, the account is locked for 15 minutes. If the attacker rotates across multiple IPs, per-IP rate limiting caps each source to 10 attempts per minute. The `ACCOUNT_LOCKED` and `SUSPICIOUS_ACTIVITY` log events alert the administrator to the ongoing attack.

**Scenario 2 — Session hijacking via XSS.**
An attacker attempts to inject a `<script>` tag into a document title. Jinja2 auto-escaping neutralizes the tag in the rendered HTML. Even if a bypass were found, the session cookie's `HttpOnly` flag prevents JavaScript from reading the token. The CSP header further restricts script execution to `'self'` sources.

**Scenario 3 — Unauthorized document access (horizontal privilege escalation).**
A logged-in user tries to access `/documents/<other_user_doc_id>/download`. The `authorize_document_download()` function resolves the user's document role from `shares.json`. Since no share entry exists for this user-document pair, the function returns no role, and the download is rejected with 403. A `DOCUMENT_DOWNLOAD_DENIED` event is logged.

**Scenario 4 — Malicious file upload.**
An attacker uploads a file named `report.pdf` that is actually a script. The magic-byte signature check detects that the file content does not start with `%PDF-`, and the upload is rejected. If the file contains the EICAR test signature, the malware scan also triggers. Both failures are logged as `UPLOAD_VALIDATION_FAILED`.

**Scenario 5 — Path traversal via document download.**
An attacker crafts a request with a manipulated document ID hoping to traverse to `../../etc/passwd`. The `safe_file_path()` function calls `secure_filename()` to strip path separators, then resolves the absolute path and verifies it falls within `DOCUMENT_STORAGE_DIR`. The traversal attempt fails, and no file outside the storage directory is served.

### 4.5 Risk Prioritization

| Priority | Threat IDs | Rationale |
|---|---|---|
| **Critical** | T4, T8, T14 | Direct compromise of document confidentiality or integrity |
| **High** | T1, T2, T3, T15, T16 | Credential theft or privilege escalation enabling further attacks |
| **Medium** | T6, T9, T11, T12 | Attacks requiring specific conditions or yielding limited impact |
| **Low** | T5, T7, T10, T13 | Require local/physical access or cause limited operational impact |

---

## 5. Security Controls

Each subsection below covers the control's purpose, implementation, testing evidence, and known limitations.

### 5.1 User Authentication

| Control | Implementation | Testing | Limitations |
|---|---|---|---|
| **Registration validation** | Username: regex `^[A-Za-z0-9_]{3,20}$`; email: `^[^@\s]+@[^@\s]+\.[^@\s]+$`; password: ≥12 chars with upper, lower, digit, special (`!@#$%^&*`); duplicate username/email check against `users.json`. Failures logged as `VALIDATION_FAILED`. | `test_authentication.py`: valid registration, duplicate username/email rejection, weak password rejection, password mismatch. | Email regex is not RFC 5322-compliant; acceptable for teaching scope. |
| **Password hashing** | `bcrypt.hashpw()` with `gensalt(rounds=12)`. Plaintext never written to disk or logged. `change_password()` also uses bcrypt cost 12. | Test verifies hash prefix `$2b$12$` and round-trip `bcrypt.checkpw()`. | bcrypt truncates at 72 bytes; irrelevant for realistic passwords with 12-char minimum. |
| **Account lockout** | Config-driven: `MAX_LOGIN_ATTEMPTS=5`, `ACCOUNT_LOCKOUT_MINUTES=15`. Failed attempts increment counter; when threshold reached, `locked_until` is set. Admin can manually lock/unlock. Events: `ACCOUNT_LOCKED`, `ACCOUNT_LOCKED_BY_ADMIN`. | `test_authentication.py`: locks after configured failures; rejects login while locked; unlocks after timeout. Test config uses threshold=3. | Attacker can intentionally lock out a target user; mitigated by time-bounded lockout (15 min) and admin unlock. |
| **Rate limiting** | `MAX_LOGIN_ATTEMPTS_PER_IP_PER_MINUTE=10` (config-driven). `_check_rate_limit()` tracks per-IP timestamps in `rate_limits.json`. Exceeding limit rejects immediately; logs `SUSPICIOUS_ACTIVITY`. | `test_authentication.py`: rejected after exceeding per-IP limit (test config uses limit=3). | Per-IP only; distributed attackers can bypass. Defense-in-depth layer alongside lockout and password complexity. |

### 5.2 Access Control

**System RBAC.** Three roles in `access_control.py` with a permission matrix (`SYSTEM_PERMISSION_MATRIX`): **admin** (create, edit, delete, view all, manage users, view shared), **user** (create, edit, delete, view shared), **guest** (view shared only). `require_role()` decorator checks permissions before route logic; failures log `AUTHORIZATION_DENIED` (403). Unknown roles default to `guest`. Tested in `test_access_control.py`: admin panel access, user 403 on admin, guest upload blocked, role change audit-logged. Limitation: no separation of duties within admin; acceptable for teaching scope.

**Document role authorization.** Three document roles: `owner`, `editor`, `viewer`. `get_document_role()` resolves from `shares.json`; owner assigned implicitly to creator. Permission enforcement: view/preview (any role), edit (owner/editor), delete (owner only), manage shares (owner/admin), download (any role). Editor-to-owner return downgrades editor to viewer. Failures log `DOCUMENT_ACCESS_DENIED`, `DOCUMENT_DOWNLOAD_DENIED`, `DOCUMENT_DELETE_DENIED`, or `DOCUMENT_SHARE_DENIED`. Tested in `test_documents.py` and `test_access_control.py`: owner downloads, viewer downloads, unshared user 403, return-to-owner downgrade. Limitation: flat JSON without row-level locking; mitigated by atomic writes.

### 5.3 Input Validation and Injection Prevention

| Control | Implementation | Testing | Limitations |
|---|---|---|---|
| **XSS prevention** | Jinja2 auto-escaping on all template variables; server-side `html.escape()` via `sanitize_text()`/`sanitize_output()` in `security.py`; CSP restricts script-src to `'self'`. | Manual: inject `<script>alert(1)</script>` as title → rendered as escaped text. CSP header verified. | CSP includes `'unsafe-inline'` for script/style; future improvement: CSP nonces. |
| **Command injection** | No `os.system()`, `subprocess`, `eval`, or `exec` in codebase. All file ops use `pathlib.Path`/`open()`. `secure_filename()` strips special chars. | Code review: grep for shell functions — none found. | None identified. |
| **Path traversal** | `safe_file_path()`: `secure_filename()` → join with base dir → `.resolve()` → verify within base via `.relative_to()` → raises `ValueError` on failure. All document I/O passes through this. | Unit test: `../../etc/passwd` raises `ValueError`. Code review confirms all paths checked. | None identified. |
| **File upload validation** | Four layers: (1) extension whitelist (`pdf`,`txt`,`docx`,`png`,`jpg`,`jpeg`), (2) MIME type check, (3) magic-byte signature (`%PDF-`, `\xff\xd8\xff`, `\x89PNG`, `PK`+`word/`, UTF-8), (4) EICAR malware scan. Empty files rejected. Failures logged as `UPLOAD_VALIDATION_FAILED`. | `test_documents.py`: valid upload, type mismatch rejected, empty rejected, EICAR rejected. | EICAR-only malware scan; placeholder for ClamAV integration (see Section 8). |

### 5.4 Encryption

| Control | Implementation | Testing | Limitations |
|---|---|---|---|
| **Transport (TLS)** | `require_https` middleware redirects HTTP→HTTPS (301) when `FORCE_HTTPS=1`. Supports self-signed cert via `TLS_CERT_FILE`/`TLS_KEY_FILE`. HSTS: `max-age=31536000; includeSubDomains`. | Manual: verify HTTPS connection and HSTS header. | HTTPS not enforced in dev mode; self-signed cert triggers browser warnings. Production would use CA-signed cert. |
| **Data-at-rest** | Fernet (AES-128-CBC + HMAC-SHA256). Key auto-generated on first use, stored in `secret.key`. `_store_revision_payload()` encrypts before disk write; `load_document_plaintext()` decrypts with HMAC verification. SHA-256 plaintext hash in metadata for integrity. | `test_documents.py`: upload/download round-trip; stored `.bin` not human-readable. | Single Fernet key for all docs; no key rotation. Key stored outside `data/` with FS permissions. Rotation documented as future improvement (Section 8). |

### 5.5 Session Management

| Control | Implementation | Testing | Limitations |
|---|---|---|---|
| **Token generation** | `secrets.token_urlsafe(32)` (256-bit CSPRNG). Same for CSRF tokens. Stored server-side in `sessions.json`; only token value sent as cookie. | Code review confirms sole use of `secrets`; `test_sessions.py` verifies unique tokens. | None — draws from OS CSPRNG. |
| **Cookie flags** | `HttpOnly=True`, `Secure=True` (non-dev), `SameSite='Strict'`, `max_age=1800` (30 min). Set in `_set_session_cookie()`. | Manual: inspect `Set-Cookie` header; `test_sessions.py` verifies cookie name. | `Secure=False` in dev mode (intentional); auto-enabled when `ENV != "development"`. |
| **Timeout & invalidation** | Sliding-window: each request extends `expires_at`. Expired sessions destroyed with `SESSION_DESTROYED (expired)` log. Logout: `invalidate_session()` removes from `sessions.json`. Concurrent eviction: all prior sessions invalidated on new login. | `test_sessions.py`: session created on login, destroyed on logout, expired sessions rejected. | JSON file under high concurrency could cause inconsistency; mitigated by atomic writes. |

### 5.6 Security Headers

`apply_security_headers()` in `security.py` is called via `@app.after_request` on every response. The seven headers set are: **CSP** (`default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'`), **X-Frame-Options** (`DENY`), **X-Content-Type-Options** (`nosniff`), **X-XSS-Protection** (`1; mode=block`), **Referrer-Policy** (`strict-origin-when-cross-origin`), **Permissions-Policy** (`geolocation=(), microphone=(), camera=()`), and **HSTS** (`max-age=31536000; includeSubDomains`, HTTPS-only). Verified via `curl -I` and `securityheaders.com`. Limitation: `'unsafe-inline'` in CSP weakens XSS protection; future improvement would adopt CSP nonces.

### 5.7 Logging and Monitoring

Two dedicated loggers in `logging_utils.py`: **SecurityLogger** (`logs/security.log`) and **AccessLogger** (`logs/access.log`). Each entry is structured JSON with `timestamp` (ISO 8601), `event_type`, `user_id`, `ip_address`, `user_agent`, `details`, and `severity`. Document events are also appended to `data/audit.json` for the admin dashboard.

**29 event types are logged**, covering all security-relevant operations. Representative examples:

| Category | Events (examples) |
|---|---|
| Authentication | `LOGIN_SUCCESS`, `LOGIN_FAILED`, `ACCOUNT_LOCKED`, `USER_REGISTERED`, `PASSWORD_CHANGE` |
| Authorization | `AUTHORIZATION_DENIED`, `DOCUMENT_ACCESS_DENIED`, `DOCUMENT_DOWNLOAD_DENIED`, `DOCUMENT_SHARE_DENIED` |
| Session lifecycle | `SESSION_CREATED`, `SESSION_DESTROYED` (logout/expired/concurrent) |
| Data access | `DOCUMENT_UPLOAD`, `DOCUMENT_DOWNLOAD`, `DOCUMENT_PREVIEW`, `DOCUMENT_EDIT`, `DOCUMENT_SHARED`, `DOCUMENT_DELETE` |
| Validation & security | `CSRF_VALIDATION_FAILED`, `UPLOAD_VALIDATION_FAILED`, `SUSPICIOUS_ACTIVITY` |

**Testing.** `test_sessions.py` verifies session events; `test_documents.py` verifies audit events; `test_authentication.py` verifies login/lockout events. Code review confirms every auth, authz, and data-access path includes a logging call. **Limitation:** logs are not cryptographically signed; a root-level attacker could modify them. For teaching scope, file-based logging is appropriate; production would use centralized SIEM.

---

## 6. Data Protection

### 6.1 Data Classification

All data handled by the system is classified into four sensitivity tiers. The classification drives the storage method, access controls, and retention policy applied to each data category.

| Tier | Classification | Data | Storage | Access |
|---|---|---|---|---|
| 1 | **Critical** | Fernet encryption key | `secret.key` on disk | Application process only |
| 2 | **Critical** | User password hashes | `data/users.json` | Never exposed to any user; only compared server-side via `bcrypt.checkpw()` |
| 3 | **High** | Uploaded documents | `data/documents/*.bin` (encrypted) | Authenticated users with explicit document role (owner/editor/viewer) |
| 4 | **High** | Session + CSRF tokens | `data/sessions.json` | Server-side only; session token sent as HttpOnly cookie |
| 5 | **Medium** | Document metadata | `data/documents.json` | Authenticated users with a document role; admin sees all |
| 6 | **Medium** | Share rules | `data/shares.json` | Owner or admin can view/modify |
| 7 | **Medium** | Audit trail | `data/audit.json`, `logs/*.log` | Admin dashboard for audit.json; log files via server access |
| 8 | **Low** | Rate-limit counters | `data/rate_limits.json` | Application-internal; auto-expires after 60 seconds |

### 6.2 Encryption Methods

| Data Category | State | Encryption Method | Details |
|---|---|---|---|
| Documents | At rest | Fernet (AES-128-CBC + HMAC-SHA256) | Every document version is individually encrypted before being written to disk as a `.bin` file. The HMAC ensures ciphertext integrity. |
| Documents | In transit | TLS (HTTPS) | HTTPS is enforced in non-development mode. HSTS header prevents protocol downgrade. |
| Passwords | At rest | bcrypt (cost factor 12) | One-way hash; not reversible. Salt is built into the bcrypt output. |
| Session tokens | In transit | TLS + HttpOnly/Secure cookie | Token is never exposed to client-side JavaScript. |
| JSON metadata files | At rest | Not encrypted | Metadata files (`documents.json`, `shares.json`, etc.) are stored as plaintext JSON. They contain no document content — only references, titles, and share rules. |

### 6.3 Key Management

**Key generation.** The Fernet encryption key is generated automatically on first application startup via `Fernet.generate_key()`, which produces a 256-bit key (128-bit AES key + 128-bit HMAC key, base64-encoded). The key is written to `secret.key` in the project root.

**Key storage.** The key file resides outside the `data/` directory to reduce the risk of accidental exposure through data-directory backups or misconfigured static file serving. File-system permissions should restrict read access to the application process user only.

**Key usage.** A single Fernet key is used for all document encryption and decryption operations. The `_load_cipher()` function in `documents.py` reads the key file once per operation and instantiates a `Fernet` object.

**Key rotation.** The current implementation does not support automated key rotation. To rotate the key, an administrator would need to:
1. Decrypt all existing documents with the old key.
2. Generate a new Fernet key.
3. Re-encrypt all documents with the new key.
4. Replace the key file.

This is documented as a known limitation in Section 8.

**SECRET_KEY (Flask).** The Flask `SECRET_KEY` is separate from the Fernet encryption key. It is used internally by Flask for cookie signing. In development mode, a random key is generated on each startup via `os.urandom(32).hex()`. In production, the application refuses to start without an explicitly configured `SECRET_KEY` environment variable.

### 6.4 Secure Deletion Procedures

**Document deletion.** When a document is permanently deleted via `permanently_delete_document()`:
1. The document metadata record is removed from `documents.json`.
2. All associated share rules are removed from `shares.json`.
3. The encrypted `.bin` file for every version in the document's `version_history` is deleted from disk via `Path.unlink()`.
4. A `DOCUMENT_DELETE` event is recorded in both `access.log` and `audit.json`.

**Session destruction.** When a session is invalidated (logout, expiry, or concurrent eviction):
1. The session record is removed from `sessions.json`.
2. The session cookie is cleared from the client via `delete_cookie()`.
3. A `SESSION_DESTROYED` event is logged with the reason (logout, expired, concurrent_login, user_missing).

**Limitations of secure deletion.** Standard file deletion (`Path.unlink()`) removes the directory entry but does not overwrite the underlying disk blocks. On SSDs with wear leveling, data may persist in flash cells. For the teaching project context, standard deletion is acceptable. A production system handling classified documents would use secure erase utilities or encrypted volumes where key destruction renders all content unrecoverable.

---

## 7. Testing Methodology and Evidence

### 7.1 Automated Test Suite

The project includes a comprehensive `pytest`-based test suite in the `tests/` directory. The tests use Flask's test client to exercise the application without requiring a running server.

**Test configuration.** `tests/conftest.py` creates a temporary directory for each test session, overriding all file paths (`DATA_DIR`, `LOG_DIR`, `ENCRYPTION_KEY_FILE`, etc.) to ensure test isolation. Security thresholds are lowered for faster testing (e.g., `MAX_LOGIN_ATTEMPTS=3` instead of 5).

**Current test results:** 73 tests passed (0 failures, 0 errors).

### 7.2 Test Coverage by Security Requirement

| Security Requirement | Test File | Key Test Cases |
|---|---|---|
| Registration validation | `test_authentication.py` | Valid registration; duplicate username; duplicate email; weak password; password mismatch |
| Password hashing | `test_authentication.py` | Stored hash uses bcrypt prefix `$2b$12$`; hash validates against original password |
| Account lockout | `test_authentication.py` | Account locks after configured failures; locked account rejected; unlocks after timeout |
| Rate limiting | `test_authentication.py` | Login rejected after exceeding per-IP limit |
| System role RBAC | `test_access_control.py` | Admin accesses admin panel; user gets 403 on admin panel; guest cannot upload |
| Admin user management | `test_access_control.py` | Admin changes user role; admin locks/unlocks user |
| Document upload | `test_documents.py` | Valid upload succeeds; invalid type rejected; empty file rejected |
| Document download | `test_documents.py` | Owner downloads; shared viewer downloads; unshared user gets 403 |
| Document sharing | `test_documents.py` | Share with valid user; share error for nonexistent user |
| Document deletion | `test_documents.py` | Owner deletes; shared user cannot delete |
| Return-to-owner | `test_documents.py` | Editor returned to owner; editor downgraded to viewer |
| Document preview audit | `test_documents.py` | Preview generates DOCUMENT_PREVIEW audit event |
| Session creation/destruction | `test_sessions.py` | Login creates session; logout destroys session; session events logged |
| Upload validation logging | `test_documents.py` | Upload failures logged as UPLOAD_VALIDATION_FAILED |

### 7.3 Manual Verification Checklist

In addition to automated tests, the following manual checks have been performed:

- [ ] Register with a password shorter than 12 characters → rejected with clear error message
- [ ] Register with a duplicate username → rejected
- [ ] Log in with wrong password 5 times → account locked
- [ ] Log in while locked → "Account locked" message with remaining time
- [ ] Upload a file with mismatched extension and content → rejected
- [ ] Attempt to access `/admin` as a regular user → 403 page
- [ ] Attempt to download a document without a share → 403
- [ ] Inspect `Set-Cookie` header → HttpOnly, SameSite=Strict present
- [ ] Inspect response headers → CSP, X-Frame-Options, X-Content-Type-Options present
- [ ] Submit a document title containing `<script>alert(1)</script>` → rendered as escaped text
- [ ] Log out and attempt to access `/dashboard` → redirected to login
- [ ] Upload a file containing the EICAR test string → rejected with malware warning

### 7.4 Requirement-to-Test Mapping

The following table maps each course specification requirement to the test evidence that validates it:

| Course Requirement | Validation Evidence |
|---|---|
| Username: 3-20 chars, alphanumeric + underscore | `test_authentication.py` — registration validation tests |
| Password: min 12 chars, complexity rules | `test_authentication.py` — weak password rejection |
| bcrypt cost ≥ 12 | `test_authentication.py` — hash prefix verification |
| Account lockout after 5 failures, 15 min | `test_authentication.py` — lockout tests (config-driven) |
| Rate limiting: 10 per IP per min | `test_authentication.py` — rate limit tests (config-driven) |
| 3 system roles (admin, user, guest) | `test_access_control.py` — role-based access tests |
| Permission matrix | `test_access_control.py` — admin/user/guest permission tests |
| Document roles (owner, editor, viewer) | `test_documents.py` — share and access tests |
| XSS prevention | Manual test — script injection in title |
| Path traversal prevention | `security.py` — `safe_file_path()` implementation + code review |
| File upload validation | `test_documents.py` — type mismatch and empty file tests |
| Data-at-rest encryption | `test_documents.py` — upload/download round-trip |
| HTTPS enforcement | `app.py` — `require_https` middleware + manual test |
| Session token: `secrets.token_urlsafe(32)` | Code review of `sessions.py` |
| Cookie: HttpOnly, Secure, SameSite=Strict | Manual header inspection |
| Session timeout (30 min) | `test_sessions.py` + manual test |
| All 7 security headers | Manual `curl -I` + code review of `apply_security_headers()` |
| Log authentication attempts | `test_authentication.py` — login event logging |
| Log authorization failures | `test_access_control.py` — 403 event logging |
| Log data access (CRUD) | `test_documents.py` — upload/download/preview/delete audit |
| Log session creation/destruction | `test_sessions.py` — session event logging |

---

## 8. Known Limitations and Future Improvements

### 8.1 Known Limitations

| ID | Area | Limitation | Impact |
|---|---|---|---|
| L1 | Malware scanning | Only the EICAR test signature is detected; no real antivirus engine is integrated | Truly malicious files could pass upload validation if they do not contain the EICAR string |
| L2 | Key management | A single Fernet key encrypts all documents; no automated key rotation | Compromise of `secret.key` exposes all documents |
| L3 | Persistence | JSON file storage does not support concurrent writes, transactions, or row-level locking | Data corruption is possible under high concurrency (mitigated by atomic writes) |
| L4 | CSP policy | `script-src` and `style-src` include `'unsafe-inline'` | Weakens XSS protection compared to a strict nonce-based CSP |
| L5 | Username enumeration | Timing side-channel: bcrypt is not called for unknown users | An attacker measuring response times could distinguish "user exists" from "user not found" |
| L6 | Account lockout abuse | An attacker can intentionally lock any account by submitting 5 wrong passwords | Denial of service for the targeted user (time-bounded to 15 minutes) |
| L7 | Deletion | Standard `Path.unlink()` does not overwrite disk blocks | Deleted document ciphertext may be recoverable with forensic tools |
| L8 | Audit integrity | Log files and `audit.json` are not cryptographically signed | A root-level attacker could modify audit records |
| L9 | Storage quotas | No per-user upload quota | A malicious user could upload many valid files to exhaust disk space |
| L10 | Version history | Document versioning tracks revisions but old encrypted payloads are only cleaned up on full document deletion, not on individual version prune | Disk usage grows with each revision |

### 8.2 Proposed Future Improvements

| Priority | Improvement | Addresses |
|---|---|---|
| High | Integrate ClamAV or a cloud-based antivirus API for real malware detection | L1 |
| High | Implement key rotation: support multiple Fernet keys with versioned key IDs stored per document | L2 |
| High | Replace JSON file storage with SQLite or PostgreSQL for concurrent access and transaction support | L3 |
| Medium | Adopt CSP nonces for inline scripts/styles and remove `'unsafe-inline'` | L4 |
| Medium | Add constant-time response for login (call bcrypt even for unknown users) to eliminate timing side-channel | L5 |
| Medium | Implement CAPTCHA or proof-of-work challenge after N failed attempts to mitigate account lockout abuse | L6 |
| Medium | Implement per-user storage quotas and enforce them at upload time | L9 |
| Low | Use secure erase (`shred` or encrypted volume key destruction) for document deletion | L7 |
| Low | Forward logs to a centralized SIEM and add cryptographic chaining (hash chain) for tamper evidence | L8 |
| Low | Add version pruning with encrypted payload cleanup to manage disk growth | L10 |

---

## 9. Conclusion

This document has presented the security architecture, threat model, and defense-in-depth controls implemented in the Secure Document Sharing System for CS 419.

The system protects document confidentiality through Fernet authenticated encryption at rest and TLS in transit. User credentials are secured with bcrypt (cost factor 12), and sessions are managed entirely server-side with cryptographically random tokens and strict cookie flags. A two-layer authorization model — combining system-level RBAC (admin, user, guest) with document-level roles (owner, editor, viewer) — ensures that every data access operation is explicitly authorized. Input validation spans four layers for file uploads and includes XSS prevention, command injection prevention, and path traversal protection. All seven required HTTP security headers are applied to every response. Comprehensive logging captures 29 event types across authentication, authorization, session lifecycle, and document operations.

The threat model identifies 16 threats mapped to the STRIDE framework, with implemented mitigations for each. Residual risks — including the EICAR-only malware scan, single encryption key without rotation, JSON file storage limitations, and CSP `'unsafe-inline'` — are honestly documented as known limitations with proposed future improvements.

The automated test suite provides 73 passing tests covering authentication, access control, document operations, session management, and audit logging. Manual verification has confirmed the effectiveness of security headers, XSS escaping, cookie flags, and upload validation.

Within the scope of a teaching project using file-based JSON storage and no external database, the system demonstrates a comprehensive, layered security posture that satisfies all requirements defined in the CS 419 course specification.
