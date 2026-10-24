from datetime import datetime, timezone, timedelta
import sqlite3
from typing import Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException, Request, status
from app.database import get_db
from app.auth import require_admin
from app.audit import log_audit_event

router = APIRouter(prefix="/api/admin", tags=["Admin Dashboard"])

def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"

@router.get("/metrics")
def get_system_metrics(
    admin_user: Dict[str, Any] = Depends(require_admin),
    db: sqlite3.Connection = Depends(get_db)
):
    """Returns administrative metrics and system health indicators."""
    cursor = db.cursor()
    
    # Total counts
    cursor.execute("SELECT COUNT(*) FROM users;")
    total_users = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM documents;")
    total_docs = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM audit_events;")
    total_audit_events = cursor.fetchone()[0]
    
    # 24-hour window
    yesterday = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    
    cursor.execute("""
        SELECT COUNT(*) FROM audit_events 
        WHERE timestamp >= ? AND action_type IN ('AUTH_LOGIN_FAILED', 'AUTH_RATE_LIMITED')
    """, (yesterday,))
    failed_logins_24h = cursor.fetchone()[0]
    
    cursor.execute("""
        SELECT COUNT(*) FROM audit_events 
        WHERE timestamp >= ? AND outcome = 'DENIED'
    """, (yesterday,))
    access_denied_24h = cursor.fetchone()[0]
    
    # Recent security alerts
    cursor.execute("""
        SELECT id, timestamp, actor_username, action_type, target_type, outcome, details, ip_address
        FROM audit_events
        WHERE outcome IN ('DENIED', 'FAILURE')
        ORDER BY id DESC LIMIT 10
    """)
    alerts = cursor.fetchall()
    
    return {
        "total_users": total_users,
        "total_documents": total_docs,
        "total_audit_events": total_audit_events,
        "failed_logins_24h": failed_logins_24h,
        "access_denied_24h": access_denied_24h,
        "recent_alerts": [
            {
                "id": a["id"],
                "timestamp": a["timestamp"],
                "actor": a["actor_username"],
                "action": a["action_type"],
                "target": a["target_type"],
                "outcome": a["outcome"],
                "details": a["details"],
                "ip": a["ip_address"]
            }
            for a in alerts
        ]
    }

@router.get("/users")
def get_all_users(
    admin_user: Dict[str, Any] = Depends(require_admin),
    db: sqlite3.Connection = Depends(get_db)
):
    """Admin-only list of all user accounts and status."""
    cursor = db.cursor()
    cursor.execute("""
        SELECT id, username, full_name, email, role, is_active, failed_login_attempts, locked_until, created_at
        FROM users
        ORDER BY id ASC
    """)
    users = cursor.fetchall()
    return [
        {
            "id": u["id"],
            "username": u["username"],
            "full_name": u["full_name"] if "full_name" in u.keys() and u["full_name"] else u["username"],
            "email": u["email"],
            "role": u["role"],
            "is_active": bool(u["is_active"]),
            "failed_attempts": u["failed_login_attempts"],
            "locked_until": u["locked_until"],
            "created_at": u["created_at"]
        }
        for u in users
    ]

@router.post("/users/{target_user_id}/toggle-status")
def toggle_user_status(
    target_user_id: int,
    request: Request,
    admin_user: Dict[str, Any] = Depends(require_admin),
    db: sqlite3.Connection = Depends(get_db)
):
    """Enables or disables a user account. Disabling immediately terminates active sessions."""
    client_ip = get_client_ip(request)
    if target_user_id == admin_user["id"]:
        raise HTTPException(status_code=400, detail="Cannot disable your own administrative account.")
        
    cursor = db.cursor()
    cursor.execute("SELECT id, username, is_active FROM users WHERE id = ?", (target_user_id,))
    target = cursor.fetchone()
    if not target:
        raise HTTPException(status_code=404, detail="User not found.")
        
    new_status = 0 if target["is_active"] else 1
    cursor.execute("UPDATE users SET is_active = ?, failed_login_attempts = 0, locked_until = NULL WHERE id = ?", (new_status, target_user_id))
    
    # If disabling, immediately revoke all active sessions
    if new_status == 0:
        cursor.execute("DELETE FROM sessions WHERE user_id = ?", (target_user_id,))
        
    db.commit()
    
    action_str = "ENABLED" if new_status else "DISABLED"
    log_audit_event(
        conn=db,
        action_type=f"USER_{action_str}",
        target_type="USER",
        target_id=str(target_user_id),
        outcome="SUCCESS",
        details=f"Admin '{admin_user['username']}' {action_str.lower()} account '{target['username']}'",
        actor_id=admin_user["id"],
        actor_username=admin_user["username"],
        ip_address=client_ip
    )
    
    return {"status": "success", "user_id": target_user_id, "is_active": bool(new_status)}
