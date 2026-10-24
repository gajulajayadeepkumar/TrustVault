# TrustVault: Secure Document Management Platform

TrustVault is an enterprise-grade, security-focused Document Management Platform built with a **Deny-by-Default** zero-trust architecture, multi-tiered role and granular document permission controls, private filesystem isolation, and a cryptographically verifiable **tamper-evident SHA-256 audit log chain**.

---

## 1. System Architecture Overview

TrustVault separates concerns across isolated operational tiers:

```
[ Web Browser Client ]
         │ HTTPS / Strict CSP / JSON API
         ▼
[ FastAPI Security Gateway ]
    ├── Security Headers & CORS Middleware (nosniff, frame-ancestors 'none', XSS filter)
    ├── Sliding Window Rate Limiter (Brute-force protection)
    ├── Cryptographic Session Manager (Constant-time token verification)
    └── Centralized Access Control Layer (DENY-BY-DEFAULT)
         │
         ├──► [ Database Engine (SQLite / PostgreSQL) ]
         │      ├── Users, Roles (ADMIN, OWNER, VIEWER)
         │      ├── Document Metadata & Classifications
         │      ├── Granular Document Permissions (READ, EDIT)
         │      └── Tamper-Evident Audit Ledger (SHA-256 Hash Chaining)
         │
         └──► [ Private Storage Vault ]
                ├── Files stored strictly outside web root
                ├── UUID4 randomized storage identifiers
                ├── Magic byte signature verification
                └── Secure streaming downloads (Content-Disposition: attachment)
```

---

## 2. Core Security Pillars

### 1. Granular Access Control & The "Admin Blindness" Rule
- **Role Hierarchy**:
  - `ADMIN`: Manages users, inspects system metrics, reviews tamper-evident audit logs, and monitors failed access attempts. **Crucially: Administrators CANNOT read, download, or preview confidential documents unless they are the document owner or have been granted explicit document permission.**
  - `OWNER`: Full control over owned documents (upload, update metadata, download, preview, delete, grant and immediately revoke access to specific users).
  - `VIEWER`: Restricted read-only user. Can ONLY list, view, and download documents specifically shared with them with `READ` permission. Cannot edit, delete, or manage permissions.
- **Immediate Revocation**: Permissions are evaluated directly against the database on every single request. No caching or signed URLs that survive revocation.

### 2. Private & Validated File Storage
- Files are stored in an isolated `storage_vault/` directory outside the public web server directory.
- Files are saved under cryptographic UUIDs (`e.g., a81c7df0-29c4-4b5b-80fb-362243e8bb72.dat`), eliminating direct file path access and path traversal (`../`).
- Real-time file content inspection: Magic bytes signature verification prevents extension/MIME-spoofing attacks (e.g., preventing PHP/EXE masquerading as PDF or PNG).

### 3. Tamper-Evident Audit Trail
- Every access attempt (successful or denied), authentication event, document lifecycle event, and permission mutation is logged.
- Events form an immutable cryptographic hash chain:
  $$\text{record\_hash} = \text{SHA256}(\text{prev\_hash} + \text{id} + \text{timestamp} + \text{actor\_id} + \text{action} + \text{target\_id} + \text{outcome} + \text{details})$$
- An automated audit verification engine detects if any record has been modified, deleted, or inserted out of order.

---

## 3. Technology Stack & Prerequisites

- **Backend**: Python 3.13+, FastAPI, Uvicorn (ASGI), Pydantic v2
- **Security & Cryptography**: Bcrypt (salted password hashing), `secrets` (CSPRNG tokens), SHA-256 (tamper-evident audit chain)
- **Database**: Parameterized SQLite3 / PostgreSQL schema (No SQL injection vectors)
- **Frontend**: Responsive Single-Page Application (HTML5, Vanilla CSS Glassmorphism, Modern Typography, Vanilla ES6+ JavaScript)
- **Testing**: Pytest, HTTPX, Unittest

---

## 4. Installation & Local Setup

### Step 1: Clone or Navigate to Directory
```bash
cd "C:\Users\JAYADEEP KUMAR\Documents\trustvault"
```

### Step 2: Install Python Dependencies
```bash
python -m pip install -r requirements.txt
```

### Step 3: Seed Database & Demo Accounts
```bash
python seed_data.py
```

### Step 4: Run the Application
```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
Open your browser at: **`http://127.0.0.1:8000`**  
Interactive API Docs (Swagger UI): **`http://127.0.0.1:8000/docs`**

---

## 5. Seed Accounts & Demo Credentials

| Role | Username | Password | Purpose / Capabilities |
| :--- | :--- | :--- | :--- |
| **ADMIN** | `admin` | `Admin@TrustVault2026!` | Audit analysis, security metrics, system users. *Cannot view unshared confidential files.* |
| **OWNER** | `owner_alice` | `Alice@TrustVault2026!` | Uploads confidential files, edits metadata, grants/revokes permissions to other users. |
| **VIEWER** | `viewer_bob` | `Bob@TrustVault2026!` | Read-only access to files explicitly shared with him. Blocked from editing or deleting. |
| **OWNER (2)**| `charlie` | `Charlie@TrustVault2026!` | Independent document owner used for cross-tenant isolation testing. |

---

## 6. Running Security & Automated Tests

Run the full automated penetration and compliance test suite:
```bash
python -m pytest tests/ -v
```

Run the standalone audit chain integrity verification tool:
```bash
python verify_audit.py
```

---

## 7. Known Security Limitations & Inherent Boundary Conditions

1. **Host/Database Root Compromise**: An attacker with full root filesystem or physical database write access could theoretically rewrite both records and rebuild the entire hash chain from the point of mutation forward. Complete mitigation against root-level DB compromise requires external hardware security modules (HSM) or write-once-read-many (WORM) append-only external logging.
2. **Downloaded File Offline Lifecycle**: Once a permitted user legitimately downloads a document file to their local machine, server-side revocation cannot revoke physical copies stored on their local disk.
