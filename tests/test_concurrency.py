import pytest
import concurrent.futures
from fastapi.testclient import TestClient
from tests.conftest import get_auth_headers

def test_concurrent_access_isolation(client: TestClient):
    """
    Verifies that concurrent requests by different users maintain strict isolation
    and do not leak session state or permission elevation across threads.
    """
    alice_headers = get_auth_headers(client, "owner_alice", "Alice@TrustVault2026!")
    bob_headers = get_auth_headers(client, "viewer_bob", "Bob@TrustVault2026!")
    charlie_headers = get_auth_headers(client, "charlie", "Charlie@TrustVault2026!")

    def make_alice_req():
        # Alice should succeed on Doc 1
        resp = client.get("/api/documents/1", headers=alice_headers)
        return ("alice", resp.status_code)

    def make_bob_req():
        # Bob must be denied on Doc 1
        resp = client.get("/api/documents/1", headers=bob_headers)
        return ("bob", resp.status_code)

    def make_charlie_req():
        # Charlie should succeed on Doc 3 (his own)
        resp = client.get("/api/documents/3", headers=charlie_headers)
        return ("charlie", resp.status_code)

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for _ in range(5):
            futures.append(executor.submit(make_alice_req))
            futures.append(executor.submit(make_bob_req))
            futures.append(executor.submit(make_charlie_req))

        results = [f.result() for f in futures]

    for user, status_code in results:
        if user == "alice":
            assert status_code == 200, "Alice should have access to her own document"
        elif user == "bob":
            assert status_code == 403, "Bob must NEVER be granted access to Alice's unshared document"
        elif user == "charlie":
            assert status_code == 200, "Charlie should have access to his own document"
