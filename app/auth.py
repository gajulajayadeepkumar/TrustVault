from datetime import datetime, timezone
import sqlite3
from typing import Optional, Dict, Any
from fastapi import Request, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from app.database import get_db
from app.security import hash_session_token

bearer_scheme = HTTPBearer(auto_error=False)

def get_current_user_optional(
    request: Request,
    auth: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
    db: sqlite3.Connection = Depends(get_db)
) -> Optional[Dict[str, Any]]:
    """Extracts and validates session token from Authorization Header or Cookie."""
    token = None
    if auth and auth.credentials:
        token = auth.credentials
    elif "tv_session" in request.cookies:
        token = request.cookies.get("tv_session")
        
    if not token:
        return None
        
    token_hash = hash_session_token(token)
    now_utc = datetime.now(timezone.utc).isoformat()
    
    cursor = db.cursor()
    cursor.execute("""
        SELECT u.id, u.username, u.email, u.role, u.is_active, s.expires_at, s.id as session_id
        FROM sessions s
        JOIN users u ON s.user_id = u.id
        WHERE s.token_hash = ?
    """, (token_hash,))
    row = cursor.fetchone()
    
    if not row:
        return None
        
    # Check session expiration
    if row["expires_at"] <= now_utc:
        # Prune expired session
        cursor.execute("DELETE FROM sessions WHERE id = ?;", (row["session_id"],))
        db.commit()
        return None
        
    # Check if user was disabled
    if not row["is_active"]:
        return None
        
    return {
        "id": row["id"],
        "username": row["username"],
        "email": row["email"],
        "role": row["role"],
        "is_active": bool(row["is_active"]),
        "session_id": row["session_id"]
    }

def get_current_user(
    user: Optional[Dict[str, Any]] = Depends(get_current_user_optional)
) -> Dict[str, Any]:
    """Dependency that strictly enforces authentication. Denies by default."""
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please log in.",
            headers={"WWW-Authenticate": "Bearer"}
        )
    return user

def require_admin(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """Enforces that the user has the ADMIN role."""
    if user["role"] != "ADMIN":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative privileges required."
        )
    return user
