# TrustVault REST API Reference

TrustVault exposes a secure RESTful API with strict server-side validation, centralized authorization, and automatic tamper-evident audit logging for every security-relevant request.

Interactive OpenAPI documentation is available locally at: `http://127.0.0.1:8000/docs`

---

## Global Security Invariants

1. **Authentication**: All protected endpoints require a valid session token sent via:
   - Header: `Authorization: Bearer <token>`
   - OR Cookie: `tv_session=<token>`
2. **Deny-by-Default**: Every request without valid authentication is rejected with `HTTP 401 Unauthorized`.
3. **Admin Privilege Boundary**: Users with role `ADMIN` do **not** automatically possess read, download, or edit access to private document contents unless they are the document owner or have been granted explicit document permission.
4. **Immediate Revocation**: Document permissions are checked live in the database on every access attempt; cached tokens or signed URLs do not survive revocation.
5. **No Information Leakage**: Queries to document lists, search filters, and counts filter out unshared documents entirely.

---

## Authentication Endpoints (`/api/auth`)

### 1. User Login
- **Endpoint**: `POST /api/auth/login`
- **Authentication**: None (Public)
- **Rate Limit**: 5 attempts per 60 seconds per IP; account locks for 15 minutes after 5 consecutive failed passwords.
- **Request Body**:
  ```json
  {
    "username": "owner_alice",
    "password": "Alice@TrustVault2026!"
  }
  ```
- **Responses**:
  - `200 OK`: Returns session token and user profile; sets HTTP-only `tv_session` cookie.
  - `401 Unauthorized`: Invalid credentials (no user enumeration).
  - `403 Forbidden`: Account temporarily locked or deactivated.
  - `429 Too Many Requests`: IP rate limit exceeded.
- **Audit Event**: `AUTH_LOGIN_SUCCESS` or `AUTH_LOGIN_FAILED`

### 2. User Logout
- **Endpoint**: `POST /api/auth/logout`
- **Authentication**: Required (`ADMIN`, `OWNER`, `VIEWER`)
- **Responses**:
  - `200 OK`: Session immediately removed from database and cookie cleared.
- **Audit Event**: `AUTH_LOGOUT`

### 3. Get Current User Profile
- **Endpoint**: `GET /api/auth/me`
- **Authentication**: Required (`ADMIN`, `OWNER`, `VIEWER`)
- **Responses**:
  - `200 OK`: `{"id": 1, "username": "owner_alice", "email": "...", "role": "OWNER", "is_active": true}`

### 4. List Active Users
- **Endpoint**: `GET /api/auth/users`
- **Authentication**: Required (`ADMIN`, `OWNER`, `VIEWER`)
- **Purpose**: Provides target user list for permission sharing.

### 5. Register New User
- **Endpoint**: `POST /api/auth/register`
- **Authentication**: Required (`ADMIN` role strictly enforced)
- **Request Body**:
  ```json
  {
    "username": "david",
    "email": "david@trustvault.local",
    "password": "SecurePassword2026!",
    "role": "VIEWER"
  }
  ```
- **Responses**:
  - `200 OK`: User registered successfully.
  - `400 Bad Request`: Username or email already taken.
  - `403 Forbidden`: Caller lacks `ADMIN` role.
- **Audit Event**: `USER_REGISTERED`

---

## Document Management Endpoints (`/api/documents`)

### 1. Upload Document
- **Endpoint**: `POST /api/documents/upload`
- **Authentication**: Required (`OWNER` or `ADMIN`; `VIEWER` is blocked with HTTP 403)
- **Payload**: `multipart/form-data`
  - `file`: Binary file stream
  - `title`: String (1 - 255 chars)
  - `category`: String (e.g., 'Finance', 'Legal', 'Engineering', 'HR', 'General')
  - `description`: String (optional)
- **Validation**:
  - Extension whitelist: `.pdf`, `.docx`, `.xlsx`, `.png`, `.jpg`, `.jpeg`, `.txt`, `.csv`
  - Magic bytes binary signature matching
  - Size check: Max 20 MB
  - Sanitization of original filename (prevents `../` path traversal)
- **Responses**:
  - `200 OK`: File stored in private vault under UUID; metadata recorded.
  - `400 Bad Request`: Disallowed extension or spoofed magic bytes.
  - `403 Forbidden`: User has `VIEWER` role.
  - `413 Payload Too Large`: File exceeds 20 MB.
- **Audit Event**: `DOC_UPLOAD`

### 2. List Documents
- **Endpoint**: `GET /api/documents`
- **Authentication**: Required
- **Query Parameters**:
  - `search`: Filter text in title/description
  - `category`: Category filter
  - `date_from`, `date_to`: ISO dates
- **Security**: Strictly queries documents where `d.owner_id = user.id` OR explicit permission exists. Zero leakage of unshared files.
- **Responses**:
  - `200 OK`: Array of accessible `DocumentResponse` objects.

### 3. View Document Details
- **Endpoint**: `GET /api/documents/{id}`
- **Authentication**: Required (Checks document ownership or `READ`/`EDIT` permission)
- **Responses**:
  - `200 OK`: Full document metadata + caller's permission level.
  - `403 Forbidden`: Access denied (including for `ADMIN` without permission).
  - `404 Not Found`: Document does not exist.
- **Audit Event**: `DOC_VIEW` (or `ACCESS_DENIED`)

### 4. Download Document File
- **Endpoint**: `GET /api/documents/{id}/download`
- **Authentication**: Required (Checks document ownership or `READ`/`EDIT` permission)
- **Security Headers**:
  - `Content-Disposition: attachment; filename="..."`
  - `X-Content-Type-Options: nosniff`
- **Responses**:
  - `200 OK`: Binary file stream.
  - `403 Forbidden`: Access denied.
- **Audit Event**: `DOC_DOWNLOAD`

### 5. Preview Document File
- **Endpoint**: `GET /api/documents/{id}/preview`
- **Authentication**: Required (Checks document ownership or `READ`/`EDIT` permission)
- **Security Headers**:
  - `Content-Security-Policy: default-src 'none'; sandbox`
- **Responses**:
  - `200 OK`: Safe inline stream.
  - `403 Forbidden`: Access denied.
- **Audit Event**: `DOC_PREVIEW`

### 6. Edit Document Metadata
- **Endpoint**: `PUT /api/documents/{id}`
- **Authentication**: Required (Checks document ownership or explicit `EDIT` permission)
- **Request Body**:
  ```json
  {
    "title": "Updated Document Title",
    "category": "Legal",
    "description": "Updated summary"
  }
  ```
- **Responses**:
  - `200 OK`: Document metadata updated.
  - `403 Forbidden`: Caller has only `READ` access or no permission.
- **Audit Event**: `DOC_EDIT`

### 7. Delete Document
- **Endpoint**: `DELETE /api/documents/{id}`
- **Authentication**: Strictly Document Owner (`OWNER` of this document)
- **Responses**:
  - `200 OK`: File removed from private storage vault; row deleted.
  - `403 Forbidden`: Caller is not the document owner.
- **Audit Event**: `DOC_DELETE`

---

## Document Permissions Endpoints (`/api/documents/{id}/permissions`)

### 1. List Document Permissions
- **Endpoint**: `GET /api/documents/{id}/permissions`
- **Authentication**: Strictly Document Owner
- **Responses**:
  - `200 OK`: Array of granted permissions `[{id, user_id, username, permission_level, granted_at}]`
  - `403 Forbidden`: Caller is not document owner.

### 2. Grant or Update Permission
- **Endpoint**: `POST /api/documents/{id}/permissions`
- **Authentication**: Strictly Document Owner
- **Request Body**:
  ```json
  {
    "target_username": "viewer_bob",
    "permission_level": "READ"
  }
  ```
- **Responses**:
  - `200 OK`: Permission granted or updated immediately.
  - `403 Forbidden`: Caller is not document owner.
  - `404 Not Found`: Target user does not exist.
- **Audit Event**: `PERM_GRANT`

### 3. Revoke Permission
- **Endpoint**: `DELETE /api/documents/{id}/permissions/{target_user_id}`
- **Authentication**: Strictly Document Owner
- **Responses**:
  - `200 OK`: Access revoked immediately upon commit. Subsequent requests by target user are rejected.
  - `403 Forbidden`: Caller is not document owner.
- **Audit Event**: `PERM_REVOKE`

---

## Audit & Verification Endpoints (`/api/audit`)

### 1. Query Audit Events
- **Endpoint**: `GET /api/audit/events`
- **Authentication**: Strictly `ADMIN` role
- **Query Parameters**: `limit` (1-200), `offset`, `actor`, `action`, `outcome`
- **Responses**:
  - `200 OK`: Array of chained audit event objects including `prev_hash` and `record_hash`.

### 2. Verify Cryptographic Hash Chain
- **Endpoint**: `GET /api/audit/verify`
- **Authentication**: Strictly `ADMIN` role
- **Execution**: Computes SHA-256 for all blocks from Genesis to Head; checks sequential ID continuity and hash linkage.
- **Responses**:
  - `200 OK`:
    ```json
    {
      "is_valid": true,
      "total_events": 25,
      "broken_event_id": null,
      "error_message": null,
      "verification_time_ms": 0.32
    }
    ```

### 3. Adversarial Tamper Demonstration
- **Endpoint**: `POST /api/audit/tamper-test`
- **Authentication**: Strictly `ADMIN` role
- **Purpose**: Modifies block #2 payload to prove live cryptographic alarm detection.

### 4. Restore Ledger
- **Endpoint**: `POST /api/audit/repair`
- **Authentication**: Strictly `ADMIN` role
- **Purpose**: Restores clean cryptographic ledger state.

---

## Admin Management Endpoints (`/api/admin`)

### 1. System Metrics & Telemetry
- **Endpoint**: `GET /api/admin/metrics`
- **Authentication**: Strictly `ADMIN` role
- **Responses**:
  - `200 OK`: Total users, total documents, total audit logs, 24h failed logins, 24h denied attempts, recent alerts.

### 2. List All Users & Account Health
- **Endpoint**: `GET /api/admin/users`
- **Authentication**: Strictly `ADMIN` role

### 3. Toggle User Account Status
- **Endpoint**: `POST /api/admin/users/{user_id}/toggle-status`
- **Authentication**: Strictly `ADMIN` role
- **Behavior**: Disabling a user terminates all active sessions in the database immediately.
