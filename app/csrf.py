import hmac
import hashlib
import time
import secrets
from typing import Optional
from fastapi import Request, HTTPException, status
from app.config import SECRET_KEY

CSRF_TOKEN_MAX_AGE = 7200  # 2 Hours

def generate_csrf_token() -> str:
    """Generates a signed, timestamped CSRF token."""
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(16)
    message = f"{nonce}:{timestamp}"
    sig = hmac.new(SECRET_KEY.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{nonce}:{timestamp}:{sig}"

def verify_csrf_token(token: Optional[str], max_age_seconds: int = CSRF_TOKEN_MAX_AGE) -> bool:
    """Validates the cryptographic signature and freshness of a CSRF token."""
    if not token or not isinstance(token, str):
        return False
    try:
        parts = token.strip().split(":")
        if len(parts) != 3:
            return False
        nonce, ts_str, sig = parts
        timestamp = int(ts_str)
        # Check token expiration
        if time.time() - timestamp > max_age_seconds or time.time() < timestamp - 60:
            return False
        message = f"{nonce}:{ts_str}"
        expected_sig = hmac.new(SECRET_KEY.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, expected_sig)
    except Exception:
        return False

def check_csrf(request: Request, submitted_token: Optional[str] = None, enforce_on_cookie: bool = True) -> bool:
    """
    Enforces CSRF protection:
    - If a CSRF token is submitted (via payload or X-CSRF-Token header), it must be cryptographically valid.
    - If submitted as an HTML form, a valid CSRF token is strictly required.
    - If relying on an ambient session cookie (for state-changing actions), a valid CSRF token is required.
    - Pure API clients sending Bearer auth or unauthenticated JSON requests pass safely.
    """
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return True

    content_type = request.headers.get("content-type", "").lower()
    is_form = "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type

    # Extract submitted token from argument or header
    token = submitted_token or request.headers.get("X-CSRF-Token")

    if token:
        return verify_csrf_token(token)

    if is_form:
        return False

    if enforce_on_cookie and "tv_session" in request.cookies:
        return False

    return True
