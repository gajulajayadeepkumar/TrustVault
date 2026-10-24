import time
import secrets
import hashlib
from collections import defaultdict
from typing import Tuple, Optional
import bcrypt

# In-memory sliding window rate limiter: ip -> list of request timestamps
_rate_limit_records = defaultdict(list)

def hash_password(password: str) -> str:
    """Hashes a password using bcrypt with automatic cryptographic salt."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plain password against bcrypt hash in constant time."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False

def generate_session_token() -> str:
    """Generates a high-entropy CSPRNG session token."""
    return secrets.token_urlsafe(48)

def hash_session_token(token: str) -> str:
    """Hashes a session token with SHA-256 before database storage to prevent token theft from DB dumps."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def secure_compare(val1: str, val2: str) -> bool:
    """Performs constant-time comparison to prevent timing side-channel attacks."""
    return secrets.compare_digest(val1.encode("utf-8"), val2.encode("utf-8"))

def check_rate_limit(key: str, max_requests: int, window_seconds: int) -> Tuple[bool, int]:
    """
    Sliding window rate limiter.
    Returns (is_allowed, remaining_requests).
    """
    now = time.time()
    cutoff = now - window_seconds
    timestamps = _rate_limit_records[key]
    
    # Prune old timestamps
    _rate_limit_records[key] = [t for t in timestamps if t > cutoff]
    
    current_count = len(_rate_limit_records[key])
    if current_count >= max_requests:
        return False, 0
    
    _rate_limit_records[key].append(now)
    return True, max_requests - current_count - 1

def reset_rate_limit(key: str):
    """Resets the rate limit counter for a specific key (e.g., upon successful login)."""
    if key in _rate_limit_records:
        del _rate_limit_records[key]

def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Validates password complexity requirements:
    - At least 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special symbol
    """
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if len(password) > 128:
        return False, "Password must not exceed 128 characters."
    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter (A-Z)."
    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter (a-z)."
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number (0-9)."
    if not any(not c.isalnum() for c in password):
        return False, "Password must contain at least one special character (e.g., !@#$%^&*)."
    return True, ""
