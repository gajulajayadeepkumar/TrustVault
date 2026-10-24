# TrustVault: Security Threat Model & Risk Analysis (THREATS.md)

This threat model outlines potential attack vectors against TrustVault, evaluated using the STRIDE methodology, their impact, implementation mitigations, corresponding automated tests, and residual risk acceptance.

---

## Threat Matrix & Mitigation Summary

| Threat ID | Threat Category | Threat Description & Attack Path | Impact | Status | Mitigating Implementation | Automated Test Coverage |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **THREAT-01** | BOLA / IDOR | Attacker modifies `document_id` in GET/PUT/DELETE requests to access or modify other users' unshared documents. | High | **Mitigated** | Centralized `verify_document_access()` checks ownership and explicit permissions for every document ID. | `test_authorization.py::test_idor_unshared_document_access_blocked` |
| **THREAT-02** | Privilege Escalation (Admin) | Administrator attempts to inspect confidential document contents or download files without permission. | High | **Mitigated** | Strict separation: Admin role grants access to audit/user management ONLY. Document content retrieval strictly requires ownership or explicit permission. | `test_authorization.py::test_admin_cannot_access_unshared_document_contents` |
| **THREAT-03** | Unauthorized Modification | User with `READ` permission (or `VIEWER` role) attempts to update document metadata or delete document. | Medium | **Mitigated** | Centralized authorization requires `EDIT` permission or `OWNER` status for mutations. Denied with HTTP 403. | `test_authorization.py::test_viewer_cannot_edit_or_delete_document` |
| **THREAT-04** | Information Leakage via Search/Listing | Attacker queries documents endpoint or search filters to enumerate document titles, counts, or metadata of other users. | Medium | **Mitigated** | All SQL queries for search, listing, and counts join on explicit permissions or owner ID. Unauthorized documents are completely invisible. | `test_documents.py::test_search_and_listing_leakage_prevented` |
| **THREAT-05** | Path Traversal in Upload/Download | Attacker uploads filename containing `../../../../etc/passwd` or `..\Windows\System32` to overwrite or leak server files. | Critical | **Mitigated** | Uploaded files are stored strictly using generated UUID4 filenames inside isolated `storage_vault/`. Original filenames are sanitized using basename regex. | `test_documents.py::test_path_traversal_attack_blocked` |
| **THREAT-06** | File Extension & MIME Spoofing | Attacker uploads malicious executable (e.g. `.exe` or `.php`) disguised as `.pdf` or with spoofed `Content-Type: application/pdf`. | High | **Mitigated** | Server checks both file extension whitelist AND inspects binary magic bytes (e.g., `%PDF-`, `\x89PNG`, `PK\x03\x04`). Unmatched signatures are rejected with HTTP 400. | `test_documents.py::test_mime_magic_bytes_spoofing_rejected` |
| **THREAT-07** | Stale Permissions / Delayed Revocation | Attacker accesses a document using cached session or previously generated download link after permission is revoked. | High | **Mitigated** | Permission checks are executed against the database on every single request. No long-lived download URLs are issued. Immediate denial upon revocation. | `test_permissions.py::test_immediate_revocation_enforced` |
| **THREAT-08** | Audit Log Tampering | Rogue administrator or attacker modifies database audit rows to conceal unauthorized access. | High | **Mitigated** | Cryptographic SHA-256 hash chaining (`prev_hash + entry -> record_hash`). Any record alteration, row deletion, or insertion breaks the chain and is detected. | `test_audit_tamper.py::test_tamper_detection_altered_entry`, `test_audit_tamper.py::test_tamper_detection_deleted_entry` |
| **THREAT-09** | Brute Force & Credential Stuffing | Attacker submits automated login attempts against accounts. | Medium | **Mitigated** | IP and user sliding window rate limiter locks after 5 consecutive failures for 15 minutes; failed events logged in audit ledger. | `test_auth.py::test_login_rate_limiting` |
| **THREAT-10** | Session Hijacking / Fixation | Attacker steals session token or predicts token generation. | High | **Mitigated** | CSPRNG tokens (`secrets.token_urlsafe(32)`), strict session timeouts (2 hours), immediate invalidation on logout, constant-time token comparison. | `test_auth.py::test_session_invalidation_and_token_entropy` |
| **THREAT-11** | Mass Assignment | Attacker injects extra JSON fields (e.g., `role: "ADMIN"`, `owner_id: 1`) during profile update or document upload. | High | **Mitigated** | Strict Pydantic models with `extra="forbid"` enforce allowed fields on every endpoint. | `test_auth.py::test_mass_assignment_protection` |
| **THREAT-12** | Database Compromise / Full Root Access | Attacker gains root filesystem or database shell and modifies both records and recomputes the entire hash chain. | Critical | **Partially Mitigated / Accepted** | Hash chaining prevents silent, undetected row modification. Recomputing an entire chain requires full DB rewrite. Complete protection requires external append-only HSM or cloud WORM storage. | Documented in README & THREATS.md |
| **THREAT-13** | Offline Data Exfiltration | Permitted user downloads legitimate copy to local disk; later has access revoked. | High | **Accepted Limitation** | Cryptographic reality: Once bytes are transferred to client hardware, physical deletion on remote endpoints cannot be enforced by web application software. | Documented in README & Architecture |

---

## Detailed Threat Mitigations

### 1. In-Depth: Centralized Authorization (THREAT-01, THREAT-02, THREAT-03)
Rather than dispersing `if user.role == ...` checks across various endpoints, TrustVault centralizes all document access checks in `app/authorization.py`:
- `check_document_access(db, user, document_id, required_permission)`
- Flow:
  1. Retrieve document metadata from database. If not found, return HTTP 404 (or generic 404 to prevent ID enumeration).
  2. If `user.id == document.owner_id`: Grant access (full owner rights).
  3. Query `document_permissions` table for `(document_id, user_id)`.
  4. If permission is found:
     - If `required_permission == "READ"` and permission is `READ` or `EDIT`: Grant access.
     - If `required_permission == "EDIT"` and permission is `EDIT`: Grant access.
     - Otherwise: Deny access (HTTP 403) and log `ACCESS_DENIED` in audit ledger.
  5. If no permission found: Deny access (HTTP 403) and log `ACCESS_DENIED`.
  6. Note: Even if `user.role == "ADMIN"`, the flow strictly adheres to steps 2-5 for document content access.

### 2. In-Depth: Cryptographic Audit Trail (THREAT-08)
- Every transaction produces an audit event with `prev_hash` equal to the preceding record's `record_hash`.
- The genesis entry has `prev_hash = "GENESIS_HASH_TRUSTVAULT_ROOT"`.
- The verification utility iterates from ID 1 to $N$, validating that:
  1. `record[i].prev_hash == record[i-1].record_hash`
  2. `record[i].record_hash == SHA256(canonical_string(record[i]))`
  3. Sequential IDs have no missing gaps.
- Any discrepancy raises a `TAMPER_DETECTED` alarm identifying the exact corrupted record ID.
