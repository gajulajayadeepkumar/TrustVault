"""
Verification of TrustVault Public Deployment on Cloudflare Edge HTTPS URL
Tests:
1. Public Health Check
2. Public SPA HTML Delivery
3. Public Login for all 3 Roles (Admin, Owner Alice, Viewer Bob)
4. Public Document Retrieval & Admin Blindness over HTTPS
5. Public Permission Revocation over HTTPS
6. Public Cryptographic Audit Chain Verification over HTTPS
"""
import sys
import json
import httpx

PUBLIC_URL = "https://vermont-panel-resolution-influenced.trycloudflare.com"

def verify_public_url():
    print("=" * 75)
    print(" VERIFYING LIVE PUBLIC DEPLOYMENT OVER INTERNET (HTTPS)")
    print(f" Target Public URL: {PUBLIC_URL}")
    print("=" * 75)

    client = httpx.Client(base_url=PUBLIC_URL, timeout=20.0, follow_redirects=True)
    tests = []

    def check(name, condition, msg):
        status = "[PASS]" if condition else "[FAIL]"
        print(f" {status} {name}: {msg}")
        tests.append({"name": name, "passed": condition, "msg": msg})

    try:
        # 1. Health check over public HTTPS
        r_health = client.get("/health")
        check("Public HTTPS Health Check", r_health.status_code == 200 and r_health.json().get("status") == "HEALTHY", f"Status {r_health.status_code}: {r_health.text}")

        # 2. Frontend SPA delivery over public HTTPS
        r_root = client.get("/")
        check("Public Frontend SPA Delivery", r_root.status_code == 200 and "TrustVault" in r_root.text, f"Status {r_root.status_code}, Length: {len(r_root.text)} bytes")

        # 3. Role 1: Admin login over public HTTPS
        r_admin = client.post("/api/auth/login", json={"username": "admin", "password": "Admin@TrustVault2026!"})
        admin_ok = r_admin.status_code == 200 and r_admin.json().get("user", {}).get("role") == "ADMIN"
        admin_token = r_admin.json().get("token") if admin_ok else None
        check("Public Auth: ADMIN Role", admin_ok, f"Status {r_admin.status_code}, Role: {r_admin.json().get('user', {}).get('role')}")

        # 4. Role 2: Owner login over public HTTPS
        r_alice = client.post("/api/auth/login", json={"username": "owner_alice", "password": "Alice@TrustVault2026!"})
        alice_ok = r_alice.status_code == 200 and r_alice.json().get("user", {}).get("role") == "OWNER"
        alice_token = r_alice.json().get("token") if alice_ok else None
        check("Public Auth: OWNER Role (Alice)", alice_ok, f"Status {r_alice.status_code}, Role: {r_alice.json().get('user', {}).get('role')}")

        # 5. Role 3: Viewer login over public HTTPS
        r_bob = client.post("/api/auth/login", json={"username": "viewer_bob", "password": "Bob@TrustVault2026!"})
        bob_ok = r_bob.status_code == 200 and r_bob.json().get("user", {}).get("role") == "VIEWER"
        bob_token = r_bob.json().get("token") if bob_ok else None
        check("Public Auth: VIEWER Role (Bob)", bob_ok, f"Status {r_bob.status_code}, Role: {r_bob.json().get('user', {}).get('role')}")

        admin_headers = {"Authorization": f"Bearer {admin_token}"}
        alice_headers = {"Authorization": f"Bearer {alice_token}"}
        bob_headers = {"Authorization": f"Bearer {bob_token}"}

        # 6. Admin Blindness over public HTTPS
        r_admin_doc = client.get("/api/documents/1", headers=admin_headers)
        admin_blindness_ok = r_admin_doc.status_code == 403 and "ADMIN role does not bypass confidential document privacy" in r_admin_doc.json().get("detail", "")
        check("Public Zero-Trust: Admin Blindness", admin_blindness_ok, f"Status {r_admin_doc.status_code} - Admin denied access to private doc")

        # 7. Document authorization & Cross-user isolation over public HTTPS
        r_bob_doc1 = client.get("/api/documents/1", headers=bob_headers)
        check("Public BOLA/IDOR Prevention", r_bob_doc1.status_code == 403, f"Status {r_bob_doc1.status_code} - Unshared document blocked")

        # 8. Immediate Revocation over public HTTPS
        # Alice grants Bob READ on Doc 1
        r_grant = client.post("/api/documents/1/permissions", json={"target_username": "viewer_bob", "permission_level": "READ"}, headers=alice_headers)
        # Bob downloads Doc 1
        r_bob_dl = client.get("/api/documents/1/download", headers=bob_headers)
        # Alice revokes Bob
        bob_user_id = client.get("/api/auth/me", headers=bob_headers).json()["id"]
        r_revoke = client.delete(f"/api/documents/1/permissions/{bob_user_id}", headers=alice_headers)
        # Bob downloads again -> must be 403
        r_bob_dl2 = client.get("/api/documents/1/download", headers=bob_headers)
        revocation_ok = (r_grant.status_code == 200 and r_bob_dl.status_code == 200 and r_revoke.status_code == 200 and r_bob_dl2.status_code == 403)
        check("Public Immediate Revocation Enforcement", revocation_ok, f"Granted (200) -> Downloaded (200) -> Revoked (200) -> Blocked ({r_bob_dl2.status_code})")

        # 9. Audit trail verification over public HTTPS
        r_audit_verify = client.get("/api/audit/verify", headers=admin_headers)
        audit_data = r_audit_verify.json()
        audit_ok = r_audit_verify.status_code == 200 and audit_data.get("is_valid") is True
        check("Public Cryptographic Audit Verification", audit_ok, f"Status {r_audit_verify.status_code}: {audit_data.get('total_events')} blocks verified in {audit_data.get('verification_time_ms')} ms")

        print("-" * 75)
        passed_count = sum(1 for t in tests if t["passed"])
        print(f" PUBLIC DEPLOYMENT AUDIT: {passed_count}/{len(tests)} Tests Passed ({(passed_count/len(tests))*100:.1f}%)")
        print("=" * 75)

        if passed_count == len(tests):
            print(" SUCCESS: Live public application verified over internet with HTTPS encryption.")
            return 0
        else:
            print(" FAILURE: One or more public verification tests failed.")
            return 1
    except Exception as e:
        print(f"Exception connecting to public URL: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(verify_public_url())
