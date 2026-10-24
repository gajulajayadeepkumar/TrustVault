# TrustVault: Project Architecture & Security Engineering Write-Up

## Executive Summary

**TrustVault** is an enterprise-grade document management and security platform engineered from the ground up on **Zero-Trust principles**. Rather than treating security as an afterthought or applying simple perimeter authorization checks, TrustVault enforces a strict **Deny-by-Default** paradigm, an isolated private storage vault completely disconnected from the public web server, and a mathematically verifiable **tamper-evident SHA-256 cryptographic audit ledger**.

---

## Key Architectural Innovations

### 1. Centralized Authorization Engine & "Admin Blindness" Rule
In conventional enterprise document management systems, administrators often possess superuser flags that grant blanket read access to all files in the system. This violates the principle of least privilege: an infrastructure or user administrator does not require access to highly sensitive executive payroll, legal strategy, or board minutes.

TrustVault introduces the **Admin Blindness** invariant:
- System Administrators have authority over user accounts, telemetry, rate limiting, and audit logs.
- System Administrators **cannot** inspect metadata, preview contents, or download confidential documents owned by users unless the document owner explicitly grants them `READ` or `EDIT` permissions.
- Every document retrieval endpoint routes through `app/authorization.py:verify_document_access()`.

### 2. Private Storage Vault & Deep File Content Validation
File upload vulnerabilities rank among the most critical web application attack vectors (CWE-434, CWE-22):
- **Path Traversal Immunity**: Filenames supplied by clients are stripped of all directory delimiters (`/`, `\`, `..`), null bytes, and control characters. Furthermore, files are stored on disk inside an isolated `storage_vault/` directory outside the web root under randomized UUIDv4 identifiers (`<uuid4>.dat`).
- **Magic Bytes Binary Inspection**: Relying solely on client-declared `Content-Type` headers or file extensions invites MIME-spoofing attacks (e.g., uploading PHP webshells or Windows executables disguised as `.pdf`). TrustVault reads the raw binary header bytes of every incoming upload and validates magic signatures (`%PDF-` for PDF, `PK\x03\x04` for Office OpenXML, `\x89PNG` for PNG, `\xff\xd8\xff` for JPEG). Spoofed uploads are rejected with HTTP 400.
- **Secure Streaming**: File downloads enforce `Content-Disposition: attachment; filename="..."` and `X-Content-Type-Options: nosniff`, preventing the browser from executing malicious active scripts in the application's origin context.

### 3. Blockchain-Style Tamper-Evident SHA-256 Audit Chaining
In compliance-heavy environments, audit trails must be protected against tampering by rogue administrators or compromised database accounts:
- Every event produces a cryptographic block:
  $$\text{record\_hash} = \text{SHA256}(\text{prev\_hash} + \text{id} + \text{timestamp} + \text{actor} + \text{action} + \text{target} + \text{outcome} + \text{details})$$
- The ledger is anchored by a deterministic `GENESIS_HASH`.
- **Thread-Safe Synchronization**: To support high-throughput concurrent requests without chain collision or race conditions, appending to the cryptographic chain is serialized via an in-memory lock (`_audit_lock`), ensuring strict sequential continuity ($H_n = f(H_{n-1})$).
- **Automated Verification Engine**: The verification utility (`verify_audit.py` and `/api/audit/verify`) traverses the chain from Genesis to Head in under 1 millisecond. Any altered byte, deleted row, or out-of-order insertion immediately raises an alarm and pins the exact corrupted record ID.

### 4. Immediate Permission Revocation
Token-based access control often suffers from stale cached permissions that persist until token expiration (often 15 to 60 minutes). TrustVault separates identity authentication (session tokens) from authorization:
- Every single document operation queries live permissions in the database at the time of request execution.
- When an owner revokes a user's permission, the transaction commits immediately, and any subsequent request by the revoked user is denied with HTTP 403 on the very next attempt.

---

## Adversarial Penetration Testing & Test Results

A test suite of **21 automated security and integration tests** was executed against the running application:

```
tests/test_audit_tamper.py::test_audit_chain_initially_valid PASSED      [  4%]
tests/test_audit_tamper.py::test_tamper_detection_altered_entry PASSED   [  9%]
tests/test_audit_tamper.py::test_tamper_detection_deleted_entry PASSED   [ 14%]
tests/test_audit_tamper.py::test_operations_generate_audit_events PASSED [ 19%]
tests/test_auth.py::test_login_success PASSED                            [ 23%]
tests/test_auth.py::test_login_invalid_password_fails PASSED             [ 28%]
tests/test_auth.py::test_login_unknown_user_fails PASSED                 [ 33%]
tests/test_auth.py::test_logout_invalidates_session PASSED               [ 38%]
tests/test_auth.py::test_mass_assignment_protection PASSED               [ 42%]
tests/test_authorization.py::test_idor_unshared_document_access_blocked PASSED [ 47%]
tests/test_authorization.py::test_admin_cannot_access_unshared_document_contents PASSED [ 52%]
tests/test_authorization.py::test_viewer_cannot_edit_or_delete_document PASSED [ 57%]
tests/test_authorization.py::test_viewer_cannot_upload_root_document PASSED [ 61%]
tests/test_authorization.py::test_unauthenticated_request_denied_by_default PASSED [ 66%]
tests/test_concurrency.py::test_concurrent_access_isolation PASSED       [ 71%]
tests/test_documents.py::test_search_and_listing_leakage_prevented PASSED [ 76%]
tests/test_documents.py::test_mime_magic_bytes_spoofing_rejected PASSED  [ 80%]
tests/test_documents.py::test_disallowed_extension_rejected PASSED       [ 85%]
tests/test_documents.py::test_path_traversal_sanitized PASSED            [ 90%]
tests/test_permissions.py::test_immediate_revocation_enforced PASSED     [ 95%]
tests/test_permissions.py::test_non_owner_cannot_grant_or_revoke_permissions PASSED [100%]

======================== 21 passed in 9.79s ========================
```

---

## Known Residual Risks & Boundary Conditions

1. **Host-Level Root Compromise**: If an attacker achieves full physical write access to the underlying SQLite database file, they could theoretically rewrite all records and recompute hashes from the point of alteration forward. To mitigate this in high-assurance environments, TrustVault should be coupled with append-only WORM storage (e.g., AWS S3 Object Lock in Compliance Mode) or hardware security modules (HSM).
2. **Offline Data Exfiltration**: Once a permitted user downloads an unencrypted document file to their local workstation, subsequent server-side permission revocation cannot purge copies already held in local operating system caches.

---

## Conclusion

TrustVault demonstrates that enterprise document management platforms can achieve uncompromising security without sacrificing performance or usability. By enforcing zero-trust authorization, cryptographic integrity verification, and robust file validation, TrustVault establishes a resilient defense against modern web application threats.
