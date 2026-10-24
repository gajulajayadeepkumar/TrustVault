import re
import sqlite3
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from app.database import get_db
from app.models import UserLoginRequest, UserRegisterRequest, UserResponse
from app.security import (
    hash_password,
    verify_password,
    generate_session_token,
    hash_session_token,
    check_rate_limit,
    reset_rate_limit,
    validate_password_strength
)
from app.csrf import generate_csrf_token, check_csrf
from app.auth import get_current_user, require_admin
from app.audit import log_audit_event
from app.config import (
    SESSION_EXPIRE_SECONDS,
    MAX_LOGIN_ATTEMPTS,
    LOCKOUT_DURATION_SECONDS,
    RATE_LIMIT_LOGIN_MAX,
    RATE_LIMIT_LOGIN_WINDOW
)

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"

@router.get("/csrf-token")
def get_csrf_token(response: Response):
    """Issues a cryptographically signed CSRF token for web forms and requests."""
    token = generate_csrf_token()
    response.set_cookie(
        key="tv_csrf",
        value=token,
        max_age=SESSION_EXPIRE_SECONDS,
        httponly=False,  # Allows frontend JavaScript to read and attach to headers/forms
        samesite="lax",
        secure=False
    )
    return {"csrf_token": token}

@router.post("/login")
def login(
    payload: UserLoginRequest,
    request: Request,
    response: Response,
    db: sqlite3.Connection = Depends(get_db)
):
    client_ip = get_client_ip(request)
    
    # CSRF check for browser form requests
    if not check_csrf(request, payload.csrf_token, enforce_on_cookie=False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing CSRF token."
        )

    identifier = (payload.email or payload.username or "").strip()
    if not identifier:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email address or username is required."
        )

    # 1. IP-level Rate Limiting
    rate_ok, _ = check_rate_limit(f"login_ip_{client_ip}", RATE_LIMIT_LOGIN_MAX, RATE_LIMIT_LOGIN_WINDOW)
    if not rate_ok:
        log_audit_event(
            conn=db,
            action_type="AUTH_RATE_LIMITED",
            target_type="AUTH",
            target_id=identifier,
            outcome="DENIED",
            details=f"Rate limit exceeded for IP {client_ip} attempting login as '{identifier}'",
            ip_address=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login requests from this IP. Please wait a minute before retrying."
        )
        
    cursor = db.cursor()
    # Support signing in by either email (case-insensitive) or username
    cursor.execute("""
        SELECT * FROM users 
        WHERE LOWER(email) = LOWER(?) OR username = ?
    """, (identifier, identifier))
    user = cursor.fetchone()
    now_utc = datetime.now(timezone.utc)
    
    # Check if account is currently locked
    if user and user["locked_until"]:
        try:
            locked_dt = datetime.fromisoformat(user["locked_until"])
            if locked_dt > now_utc:
                remaining_secs = int((locked_dt - now_utc).total_seconds())
                log_audit_event(
                    conn=db,
                    action_type="AUTH_ACCOUNT_LOCKED",
                    target_type="USER",
                    target_id=str(user["id"]),
                    outcome="DENIED",
                    details=f"Login attempt on locked account '{identifier}' ({remaining_secs}s remaining)",
                    actor_id=user["id"],
                    actor_username=user["username"],
                    ip_address=client_ip
                )
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Account temporarily locked due to multiple failed logins. Try again in {remaining_secs} seconds."
                )
        except ValueError:
            pass

    # Verify credentials
    is_valid = False
    if user:
        is_valid = verify_password(payload.password, user["password_hash"])
        
    if not is_valid or not user:
        # Increment failed login attempts if user exists
        if user:
            new_attempts = user["failed_login_attempts"] + 1
            locked_until_val = None
            if new_attempts >= MAX_LOGIN_ATTEMPTS:
                locked_until_val = (now_utc + timedelta(seconds=LOCKOUT_DURATION_SECONDS)).isoformat()
                
            cursor.execute("""
                UPDATE users 
                SET failed_login_attempts = ?, locked_until = ? 
                WHERE id = ?
            """, (new_attempts, locked_until_val, user["id"]))
            db.commit()
            
        log_audit_event(
            conn=db,
            action_type="AUTH_LOGIN_FAILED",
            target_type="AUTH",
            target_id=identifier,
            outcome="DENIED",
            details=f"Invalid credentials provided for identifier '{identifier}'",
            actor_username=identifier,
            ip_address=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password."
        )

    # Check if user account is active
    if not user["is_active"]:
        log_audit_event(
            conn=db,
            action_type="AUTH_LOGIN_DISABLED",
            target_type="USER",
            target_id=str(user["id"]),
            outcome="DENIED",
            details=f"Login attempt on disabled account '{user['username']}'",
            actor_id=user["id"],
            actor_username=user["username"],
            ip_address=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account has been deactivated. Contact an administrator."
        )

    # Success: Reset failed attempts & IP rate counter
    cursor.execute("""
        UPDATE users 
        SET failed_login_attempts = 0, locked_until = NULL 
        WHERE id = ?
    """, (user["id"],))
    reset_rate_limit(f"login_ip_{client_ip}")

    # Generate Session Token
    raw_token = generate_session_token()
    token_hash = hash_session_token(raw_token)
    expires_at = (now_utc + timedelta(seconds=SESSION_EXPIRE_SECONDS)).isoformat()
    user_agent = request.headers.get("User-Agent", "UNKNOWN")[:255]

    cursor.execute("""
        INSERT INTO sessions (user_id, token_hash, ip_address, user_agent, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (user["id"], token_hash, client_ip, user_agent, now_utc.isoformat(), expires_at))
    db.commit()

    # Log successful authentication
    log_audit_event(
        conn=db,
        action_type="AUTH_LOGIN_SUCCESS",
        target_type="USER",
        target_id=str(user["id"]),
        outcome="SUCCESS",
        details=f"User '{user['username']}' ({user['email']}) logged in successfully (Role: {user['role']})",
        actor_id=user["id"],
        actor_username=user["username"],
        ip_address=client_ip
    )

    # Set secure HTTP-only Cookie
    response.set_cookie(
        key="tv_session",
        value=raw_token,
        max_age=SESSION_EXPIRE_SECONDS,
        httponly=True,
        samesite="lax",
        secure=False  # Set to True on production HTTPS
    )

    full_name = user["full_name"] if "full_name" in user.keys() and user["full_name"] else user["username"]

    return {
        "status": "success",
        "token": raw_token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "full_name": full_name,
            "email": user["email"],
            "role": user["role"]
        }
    }

@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db)
):
    client_ip = get_client_ip(request)
    cursor = db.cursor()
    cursor.execute("DELETE FROM sessions WHERE id = ?", (current_user["session_id"],))
    db.commit()
    
    response.delete_cookie("tv_session")
    
    log_audit_event(
        conn=db,
        action_type="AUTH_LOGOUT",
        target_type="USER",
        target_id=str(current_user["id"]),
        outcome="SUCCESS",
        details=f"User '{current_user['username']}' logged out",
        actor_id=current_user["id"],
        actor_username=current_user["username"],
        ip_address=client_ip
    )
    return {"status": "success", "message": "Successfully logged out."}

@router.get("/me")
def get_me(current_user: Dict[str, Any] = Depends(get_current_user)):
    return {
        "id": current_user["id"],
        "username": current_user["username"],
        "full_name": current_user.get("full_name", current_user["username"]),
        "email": current_user["email"],
        "role": current_user["role"],
        "is_active": current_user["is_active"]
    }

@router.get("/users")
def list_system_users(
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db)
):
    """Returns active users for the permission-sharing dropdown."""
    cursor = db.cursor()
    cursor.execute("SELECT id, username, full_name, role FROM users WHERE is_active = 1 ORDER BY username ASC")
    users = cursor.fetchall()
    return [
        {
            "id": u["id"],
            "username": u["username"],
            "full_name": u["full_name"] if "full_name" in u.keys() and u["full_name"] else u["username"],
            "role": u["role"]
        }
        for u in users
    ]

@router.post("/register")
def register_user(
    payload: UserRegisterRequest,
    request: Request,
    response: Response,
    db: sqlite3.Connection = Depends(get_db)
):
    """
    Public user registration endpoint.
    Strictly forbids self-registration as ADMIN and assigns safe role (VIEWER or OWNER).
    Validates email format, password complexity, duplicate emails, and matching passwords.
    """
    client_ip = get_client_ip(request)
    
    # CSRF check
    if not check_csrf(request, payload.csrf_token, enforce_on_cookie=False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or missing CSRF token."
        )

    # 1. Validate full name / username
    full_name = (payload.full_name or "").strip()
    username = (payload.username or "").strip()
    if not full_name and not username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Full name is required."
        )
    if not full_name:
        full_name = username

    email = str(payload.email).strip().lower()
    email_regex = re.compile(r"^[\w\.\+\-]+@[a-zA-Z0-9\.\-]+\.[a-zA-Z0-9\-]+$")
    if not email_regex.match(email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please provide a valid email address."
        )

    # 2. Check Password Confirmation
    if payload.confirm_password is not None and payload.confirm_password != payload.password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passwords do not match."
        )

    # 3. Validate Password Strength
    pw_ok, pw_err = validate_password_strength(payload.password)
    if not pw_ok:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=pw_err
        )

    # 4. Strictly Prevent Self-Registration as Administrator
    requested_role = (payload.role or "VIEWER").strip().upper()
    if requested_role == "ADMIN":
        log_audit_event(
            conn=db,
            action_type="AUTH_ROLE_ELEVATION_ATTEMPT",
            target_type="SECURITY",
            target_id=email,
            outcome="DENIED",
            details=f"Unauthorized self-registration attempt as ADMIN from IP {client_ip} ({email})",
            ip_address=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator accounts cannot be self-registered and require pre-provisioned administrative authority."
        )

    if requested_role not in ("OWNER", "VIEWER"):
        requested_role = "VIEWER"

    cursor = db.cursor()

    # 5. Check Duplicate Email
    cursor.execute("SELECT id FROM users WHERE LOWER(email) = LOWER(?)", (email,))
    if cursor.fetchone():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists. Please sign in or use a different email."
        )

    # 6. Generate or Verify Unique Username
    if not username:
        base_username = re.sub(r"[^a-zA-Z0-9_\-\.]", "_", email.split("@")[0])[:40]
        if len(base_username) < 3:
            base_username = f"user_{base_username}"
        username = base_username
        suffix = 1
        while True:
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            if not cursor.fetchone():
                break
            username = f"{base_username}_{suffix}"
            suffix += 1
    else:
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This username is already taken. Please choose another username."
            )

    # 7. Secure Password Hashing
    pw_hash = hash_password(payload.password)
    now_utc = datetime.now(timezone.utc).isoformat()

    cursor.execute("""
        INSERT INTO users (username, full_name, email, password_hash, role, is_active, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, 1, ?, ?)
    """, (username, full_name, email, pw_hash, requested_role, now_utc, now_utc))
    new_user_id = cursor.lastrowid
    db.commit()

    # 8. Audit Event Logging
    log_audit_event(
        conn=db,
        action_type="USER_REGISTERED",
        target_type="USER",
        target_id=str(new_user_id),
        outcome="SUCCESS",
        details=f"New user registered: '{username}' ({email}) with role '{requested_role}'",
        actor_id=new_user_id,
        actor_username=username,
        ip_address=client_ip
    )

    # 9. Create Active Session
    raw_token = generate_session_token()
    token_hash = hash_session_token(raw_token)
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=SESSION_EXPIRE_SECONDS)).isoformat()
    user_agent = request.headers.get("User-Agent", "UNKNOWN")[:255]

    cursor.execute("""
        INSERT INTO sessions (user_id, token_hash, ip_address, user_agent, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (new_user_id, token_hash, client_ip, user_agent, now_utc, expires_at))
    db.commit()

    response.set_cookie(
        key="tv_session",
        value=raw_token,
        max_age=SESSION_EXPIRE_SECONDS,
        httponly=True,
        samesite="lax",
        secure=False
    )

    return {
        "status": "success",
        "message": "Account created successfully.",
        "token": raw_token,
        "user": {
            "id": new_user_id,
            "username": username,
            "full_name": full_name,
            "email": email,
            "role": requested_role
        }
    }
