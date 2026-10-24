# TrustVault: 5-Minute Video Demonstration Script

This script provides an exact, scene-by-scene demonstration workflow for evaluators and presenters. It showcases TrustVault's three distinct user roles, granular access controls, the zero-trust "Admin Blindness" privacy rule, immediate permission revocation, and the live cryptographic audit tamper detection center.

---

## Preparation (Before Recording)
1. Open PowerShell and navigate to `C:\Users\JAYADEEP KUMAR\Documents\trustvault`.
2. Run `python seed_data.py` to ensure fresh demo accounts and documents.
3. Start the application:
   ```bash
   python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
   ```
4. Open your browser to: **`http://127.0.0.1:8000`**

---

## Scene 1: Introduction & Architecture (0:00 – 0:50)

- **Visual**: Browser displaying the TrustVault landing page at `http://127.0.0.1:8000`.
- **Narration**:
  > *"Welcome to TrustVault, an enterprise-grade document security platform built on zero-trust principles. Unlike traditional CRUD document repositories where administrators have unrestricted superuser access, TrustVault enforces strict Deny-by-Default authorization, private file vaulting outside the web root, and a mathematically verifiable SHA-256 cryptographic audit chain.*
  >
  > *Notice the top bar: we have provided a 1-click Quick Demo Switcher allowing us to instantly toggle between our three primary roles: System Admin, Document Owner Alice, and Restricted Viewer Bob."*

---

## Scene 2: Document Owner Workflow — Upload & Privacy (0:50 – 1:50)

- **Visual**: Click the **"👤 Alice (Owner)"** button in the top demo switcher.
- **Actions**:
  1. The UI instantly signs in as `owner_alice`.
  2. Alice sees her documents: `Q3 Executive Financial Audit Report` (Private) and `Enterprise Security & Access Policy 2026`.
  3. Click **"📤 Secure Upload"** tab.
  4. Drag or select a sample file, name it *"Board Strategy 2027"*, select category *"Legal"*, and click *"Encrypt & Store in Private Vault"*.
  5. Show the toast notification and return to the vault.
- **Narration**:
  > *"Here as Alice, a document owner, we have full lifecycle control over our files. When Alice uploads a document, TrustVault inspects the binary magic bytes header to prevent MIME-spoofing, generates a cryptographic SHA-256 checksum, assigns a random UUID, and stores the file safely outside the public web root.*
  >
  > *Now, let's look at the permissions modal for our Enterprise Security Policy. Alice has shared this document with Viewer Bob with READ access."*

---

## Scene 3: Viewer Bob — Strict Privilege Boundaries & Immediate Revocation (1:50 – 3:00)

- **Visual**: Click the **"👁️ Bob (Viewer)"** button in the top demo switcher.
- **Actions**:
  1. Bob's view loads: Notice that Bob **only** sees the `Enterprise Security Policy` shared with him.
  2. Alice's confidential `Q3 Financial Report` and `Board Strategy` are completely invisible.
  3. Try searching for *"Financial"* or *"Board"* in the search box: **0 results returned**.
  4. Click the **"📤 Secure Upload"** tab: Show the warning banner stating Bob is a `VIEWER` and uploads are blocked.
  5. Click *"👁️ Preview"* on the Security Policy and then click *"⬇️ Download"* to show that authorized access works.
  6. Switch back to **"👤 Alice (Owner)"**:
     - Click *"👥 Permissions"* on the Security Policy.
     - Click *"Revoke Access"* next to `viewer_bob`.
  7. Switch immediately back to **"👁️ Bob (Viewer)"**:
     - Attempt to download or view the Security Policy: **Access Denied (HTTP 403)** immediately!
- **Narration**:
  > *"Now we switch to Bob. Notice the zero information leakage: Bob cannot see, search for, or enumerate documents that have not been shared with him.*
  >
  > *When Alice revokes Bob's permission, the revocation commits to the database instantly. There are no stale permissions or cached tokens. When Bob attempts to download the file again, his request is blocked immediately."*

---

## Scene 4: The "Admin Blindness" Privacy Principle (3:00 – 3:55)

- **Visual**: Click the **"👑 Admin"** button in the top demo switcher.
- **Actions**:
  1. Show the **"⚙️ Admin Console"** tab:
     - Real-time telemetry cards: Total documents, total users, failed login attempts, blocked unauthorized access attempts.
     - System user table with the ability to disable/enable accounts.
  2. Switch to the **"📄 Documents Vault"** tab:
     - Point out the purple banner: *"Zero-Trust Admin Privacy Rule Enforced"*.
     - Point out that Admin **cannot** see or download Alice's private `Q3 Financial Report`.
  3. If Admin attempts to directly access Alice's document via ID (e.g. `/api/documents/1`), the centralized authorization engine rejects the request with HTTP 403!
- **Narration**:
  > *"In traditional systems, administrators can read all confidential documents. In TrustVault, we enforce the Admin Blindness Rule. As an administrator, I can inspect telemetry, manage accounts, and view security alerts, but I cannot read or download confidential documents owned by users unless explicitly permitted. Privacy is preserved by design."*

---

## Scene 5: Cryptographic Audit Trail & Adversarial Tamper Demonstration (3:55 – 5:00)

- **Visual**: Click the **"🛡️ Tamper-Evident Ledger"** tab as Admin.
- **Actions**:
  1. Click **"⚡ Re-Verify SHA-256 Ledger"**:
     - Show the green **"VERIFIED"** banner and point out the verification duration (e.g. `0.28 ms`).
     - Scroll through the audit table showing each sequential block's `Prev Hash` and `Record Hash`.
  2. Now perform the live adversarial attack:
     - Click the red button: **"⚠️ Simulate Database Tampering"**.
     - Watch the banner instantly turn RED with a pulsing alarm: **"ALERT: TAMPERING DETECTED AT BLOCK #2"**.
     - Point out the failure message: *"Tampered record payload at ID 2: Calculated hash does not match stored hash."*
     - Show the highlighted corrupted row in the table.
  3. Click **"🛡️ Restore Verified State"**:
     - The ledger restores and re-verifies back to green **"VERIFIED"**!
  4. Finally, switch to the terminal and run:
     ```bash
     python verify_audit.py
     python -m pytest tests/ -v
     ```
     - Show the CLI verification utility passing and all 21 automated security tests passing.
- **Narration**:
  > *"Every event in TrustVault forms an immutable cryptographic hash chain where each block's hash depends on the preceding block. If an attacker or rogue administrator modifies even a single character in the database, our verification engine detects the discrepancy in less than a millisecond.*
  >
  > *With 21 comprehensive automated penetration tests passing, TrustVault delivers a truly robust, zero-trust document security platform. Thank you!"*
