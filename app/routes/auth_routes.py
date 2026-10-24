from datetime import datetime, timezone, timedelta
import sqlite3
from typing import Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from app.database import get_db
from app.models import UserLoginRequest, UserRegisterRequest, UserResponse
from app.security import (
    hash_password,
    verify_password,
    generate_session_token,
    hash_session_token,
    check_rate_limit,
    reset_rate_limit
)
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

@router.post("/login")
def login(
    payload: UserLoginRequest,
    request: Request,
    response: Response,
    db: sqlite3.Connection = Depends(get_db)
):
    client_ip = get_client_ip(request)
    
    # 1. IP-level Rate Limiting
    rate_ok, _ = check_rate_limit(f"login_ip_{client_ip}", RATE_LIMIT_LOGIN_MAX, RATE_LIMIT_LOGIN_WINDOW)
    if not rate_ok:
        log_audit_event(
            conn=db,
            action_type="AUTH_RATE_LIMITED",
            target_type="AUTH",
            target_id=payload.username,
            outcome="DENIED",
            details=f"Rate limit exceeded for IP {client_ip} attempting login as '{payload.username}'",
            ip_address=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login requests from this IP. Please wait a minute before retrying."
        )
        
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (payload.username,))
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
                    details=f"Login attempt on locked account '{payload.username}' ({remaining_secs}s remaining)",
                    actor_id=user["id"],
                    actor_username=payload.username,
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
            target_id=payload.username,
            outcome="DENIED",
            details=f"Invalid credentials provided for username '{payload.username}'",
            actor_username=payload.username,
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
            details=f"Login attempt on disabled account '{payload.username}'",
            actor_id=user["id"],
            actor_username=payload.username,
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
        details=f"User '{user['username']}' logged in successfully (Role: {user['role']})",
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
        secure=False  # Set to True in production HTTPS
    )

    return {
        "status": "success",
        "token": raw_token,
        "user": {
            "id": user["id"],
            "username": user["username"],
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
    cursor.execute("SELECT id, username, role FROM users WHERE is_active = 1 ORDER BY username ASC")
    users = cursor.fetchall()
    return [{"id": u["id"], "username": u["username"], "role": u["role"]} for u in users]

@router.post("/register")
def register_user(
    payload: UserRegisterRequest,
    request: Request,
    admin_user: Dict[str, Any] = Depends(require_admin),
    db: sqlite3.Connection = Depends(get_db)
):
    """Admin-only endpoint to register a new user with a specific role."""
    client_ip = get_client_ip(request)
    cursor = db.cursor()
    cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", (payload.username, payload.email))
    if cursor.fetchone():
        raise HTTPException(status_code=400, detail="Username or email already exists.")
        
    pw_hash = hash_password(payload.password)
    now_utc = datetime.now(timezone.utc).isoformat()
    
    cursor.execute("""
        INSERT INTO users (username, email, password_hash, role, is_active, created_at)
        VALUES (?, ?, ?, ?, 1, ?)
    """, (payload.username, payload.email, pw_hash, payload.role, now_utc))
    new_user_id = cursor.lastrowid
    db.commit()
    
    log_audit_event(
        conn=db,
        action_type="USER_REGISTERED",
        target_type="USER",
        target_id=str(new_user_id),
        outcome="SUCCESS",
        details=f"Admin '{admin_user['username']}' registered new user '{payload.username}' with role '{payload.role}'",
        actor_id=admin_user["id"],
        actor_username=admin_user["username"],
        ip_address=client_ip
    )
    return {"status": "success", "user_id": new_user_id, "username": payload.username, "role": payload.role}
