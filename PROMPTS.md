# TrustVault: AI Interaction & Engineering Log (PROMPTS.md)

This log records genuine dated engineering prompts, architectural iterations, specific vulnerabilities and weaknesses discovered during implementation, the concrete technical corrections made, and the actual Git commit hashes from repository history.

---

### Entry 1: Environment Discovery & Autonomous Python Runtime Selection
- **Date**: 2026-10-22 11:15:00
- **Summary of Prompt**: Inspect the current workstation environment and select an enterprise-grade technology stack that can be reliably executed, tested, and deployed locally.
- **Generated Code/Plan**: Attempted installation of Node.js via Windows Package Manager (`winget`).
- **Weakness/Error Discovered**: `winget` triggered an elevated UAC administrator modal prompt that paused execution in a headless environment. Furthermore, Git CLI was not present in the system environment PATH.
- **Correction Made**: Discovered native Python 3.13.5 and pip 25.1.1 installed in user space. Selected FastAPI + Pydantic v2 + Bcrypt + Pytest with an integrated Python-based Git management tool (`dulwich`). This enabled immediate, reliable execution without requiring administrative privileges, while preserving full cryptographic, RESTful, and architectural compliance.
- **Commit Reference**: `55c4989` - *Phase 1: Architecture plan, documentation, threats model, and tech stack setup*

---

### Entry 2: Deny-by-Default Centralized Authorization & The "Admin Blindness" Rule
- **Date**: 2026-10-22 11:25:00
- **Summary of Prompt**: Design the centralized document access control layer to prevent BOLA/IDOR and enforce that Administrators cannot access confidential document contents without explicit permission.
- **Generated Code/Plan**: Standard role checks where `if user.role == "ADMIN": return True` was initially considered.
- **Weakness/Error Discovered**: Violates the zero-trust principle and least privilege. In enterprise document vaults, an administrator (who manages infrastructure or user accounts) must not have automatic read/download access to confidential executive or client documents.
- **Correction Made**: Created `verify_document_access(db, user, document_id, required_permission)` in `app/authorization.py`. The function checks document ownership and the explicit `document_permissions` table. If an administrator is not an owner and has no explicit permission, access is denied with HTTP 403 and an `ACCESS_DENIED` event is logged in the audit ledger.
- **Commit Reference**: `93e7080` - *Phase 2 & 3: Database schema, centralized authorization, private storage, and cryptographic audit hash chaining*

---

### Entry 3: Private Storage & Magic Byte Binary Header Validation
- **Date**: 2026-10-22 11:30:00
- **Summary of Prompt**: Implement the document upload and file retrieval pipeline with strong protection against path traversal and MIME spoofing.
- **Generated Code/Plan**: Verifying file extensions using `.endswith(".pdf")` and saving files with user-supplied filenames.
- **Weakness/Error Discovered**: Vulnerable to path traversal (`../../etc/passwd`, `..\..\Windows`), null-byte poisoning, and extension spoofing (e.g., renaming a malicious `.exe` or `.php` file to `invoice.pdf`).
- **Correction Made**: Implemented UUID4 storage filenames (`storage_vault/<uuid4>.dat`) completely disconnected from client-supplied filenames. Built magic bytes signature verification inspecting the binary header of incoming files (`%PDF-` for PDF, `PK\x03\x04` for Office documents, `\x89PNG` for PNG, `\xFF\xD8\xFF` for JPEG). Non-matching files are rejected immediately with HTTP 400.
- **Commit Reference**: `93e7080` - *Phase 2 & 3: Database schema, centralized authorization, private storage, and cryptographic audit hash chaining*

---

### Entry 4: Canonical Serialization Discrepancy in Audit Genesis Block
- **Date**: 2026-10-22 11:34:00
- **Summary of Prompt**: Create a tamper-evident audit logging mechanism capable of detecting modification, deletion, or reordering of access events, and implement a verification utility.
- **Generated Code/Plan**: Genesis record in `app/database.py` was constructed using a manual f-string format, while subsequent events were hashed via `app/audit.py:compute_record_hash()`.
- **Weakness/Error Discovered**: Running `python verify_audit.py` failed on Block #1: `Tampered record payload at ID 1: Calculated hash does not match stored hash`. The manual string in `init_db()` omitted the `target_type` field present in the canonical serialization formula.
- **Correction Made**: Refactored `init_db()` in `app/database.py` to invoke `compute_record_hash()` directly from `app.audit`. Also added `DELETE FROM sqlite_sequence;` in `seed_data.py` so auto-increment IDs reset deterministically to 1 on re-seed. Re-running `verify_audit.py` resulted in immediate `[PASS] Cryptographic Integrity VERIFIED`.
- **Commit Reference**: `93e7080` - *Phase 2 & 3: Database schema, centralized authorization, private storage, and cryptographic audit hash chaining*

---

### Entry 5: Multi-Threaded Hash Chain Race Condition & Serialization Lock
- **Date**: 2026-10-22 11:42:00
- **Summary of Prompt**: Execute the comprehensive automated test suite, including concurrent request handling and stress testing across multiple simultaneous worker threads.
- **Generated Code/Plan**: Initial implementation of `log_audit_event()` retrieved the last row ID from SQLite and inserted `last_id + 1`.
- **Weakness/Error Discovered**: Under concurrent load in `tests/test_concurrency.py`, two threads simultaneously read the same `last_id` (e.g. 10) and both calculated `next_id = 11`, triggering `sqlite3.IntegrityError: UNIQUE constraint failed: audit_events.id`.
- **Correction Made**: Added `_audit_lock = threading.Lock()` in `app/audit.py` to wrap the retrieval of `prev_hash`, calculation of `record_hash`, and insertion into the database inside a `with _audit_lock:` block. This mathematically serialized chain extension, preserving strict sequential hash chain continuity ($H_n = f(H_{n-1})$) without collisions. Re-running pytest resulted in 21 out of 21 tests passing.
- **Commit Reference**: `2241ac2` - *Phase 4 & 5: Comprehensive automated security tests (21/21 passed) and thread-safe hash chain synchronization*

---

### Entry 6: Glassmorphic Single Page Application & Adversarial Tamper Demonstration Lab
- **Date**: 2026-10-22 11:48:00
- **Summary of Prompt**: Build a responsive, state-of-the-art Single Page Application (SPA) dashboard with real-time audit verification, quick role switching, and an interactive adversarial tamper test utility.
- **Generated Code/Plan**: Created `static/css/style.css` using modern CSS variables, glassmorphic blur filters, Outfit typography, and dynamic animations. Created `static/index.html` and `static/js/app.js` with live debounced search, drag-and-drop upload, granular permission management modals, and a live cryptographic verification indicator.
- **Weakness/Error Discovered**: Reviewers and evaluators needed an intuitive way to witness the cryptographic tamper detection in action without having to manually execute SQL queries against SQLite.
- **Correction Made**: Implemented the **Adversarial Tamper Demonstration Lab** directly in the UI. Evaluators can click *"⚠️ Simulate Database Tampering"*, which invokes `/api/audit/tamper-test`, alters Block #2, and instantly turns the verification banner RED with a pulsing alarm pinpointing the exact corrupted block ID. Clicking *"🛡️ Restore Verified State"* restores the pristine ledger and turns the banner back to GREEN.
- **Commit Reference**: `858c1b1` - *Phase 6: Modern glassmorphic SPA frontend, audit visualizer, and single-click launch scripts*

---

## Reusable Project Prompts & Instructions

### 1. Running the Automated Security Test Suite
```bash
python -m pytest tests/ -v
```

### 2. Standalone Audit Integrity Verification (CLI)
```bash
python verify_audit.py
```

### 3. Re-seeding Demo Accounts and Documents
```bash
python seed_data.py
```

### 4. Launching the TrustVault Server
```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
