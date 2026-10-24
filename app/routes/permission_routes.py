from datetime import datetime, timezone
import sqlite3
from typing import Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException, Request, status
from app.database import get_db
from app.models import PermissionGrantRequest, DocumentPermissionItem
from app.auth import get_current_user
from app.authorization import verify_can_manage_permissions
from app.audit import log_audit_event

router = APIRouter(prefix="/api/documents", tags=["Permissions"])

def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"

@router.get("/{document_id}/permissions", response_model=List[DocumentPermissionItem])
def list_document_permissions(
    document_id: int,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db)
):
    client_ip = get_client_ip(request)
    doc = verify_can_manage_permissions(db, current_user, document_id, client_ip)
    
    cursor = db.cursor()
    cursor.execute("""
        SELECT dp.id, dp.user_id, u.username, dp.permission_level, dp.granted_by, dp.granted_at
        FROM document_permissions dp
        JOIN users u ON dp.user_id = u.id
        WHERE dp.document_id = ?
        ORDER BY u.username ASC
    """, (document_id,))
    rows = cursor.fetchall()
    
    return [
        DocumentPermissionItem(
            id=r["id"],
            user_id=r["user_id"],
            username=r["username"],
            permission_level=r["permission_level"],
            granted_by=r["granted_by"],
            granted_at=r["granted_at"]
        )
        for r in rows
    ]

@router.post("/{document_id}/permissions")
def grant_permission(
    document_id: int,
    payload: PermissionGrantRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db)
):
    client_ip = get_client_ip(request)
    doc = verify_can_manage_permissions(db, current_user, document_id, client_ip)
    
    cursor = db.cursor()
    # Find target user
    cursor.execute("SELECT id, username, is_active FROM users WHERE username = ?", (payload.target_username,))
    target_user = cursor.fetchone()
    if not target_user:
        raise HTTPException(status_code=404, detail=f"User '{payload.target_username}' not found.")
        
    if target_user["id"] == current_user["id"]:
        raise HTTPException(status_code=400, detail="Cannot grant permissions to yourself; you are already the owner.")
        
    now_utc = datetime.now(timezone.utc).isoformat()
    
    # Upsert permission
    cursor.execute("""
        INSERT INTO document_permissions (document_id, user_id, permission_level, granted_by, granted_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(document_id, user_id) 
        DO UPDATE SET permission_level = excluded.permission_level,
                      granted_by = excluded.granted_by,
                      granted_at = excluded.granted_at
    """, (document_id, target_user["id"], payload.permission_level, current_user["id"], now_utc))
    db.commit()
    
    log_audit_event(
        conn=db,
        action_type="PERM_GRANT",
        target_type="PERMISSION",
        target_id=str(document_id),
        outcome="SUCCESS",
        details=f"Owner '{current_user['username']}' granted '{payload.permission_level}' on '{doc['title']}' to '{payload.target_username}'",
        actor_id=current_user["id"],
        actor_username=current_user["username"],
        ip_address=client_ip
    )
    
    return {
        "status": "success",
        "message": f"Successfully granted {payload.permission_level} access to {payload.target_username}."
    }

@router.delete("/{document_id}/permissions/{target_user_id}")
def revoke_permission(
    document_id: int,
    target_user_id: int,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db)
):
    client_ip = get_client_ip(request)
    doc = verify_can_manage_permissions(db, current_user, document_id, client_ip)
    
    cursor = db.cursor()
    cursor.execute("SELECT username FROM users WHERE id = ?", (target_user_id,))
    target_user = cursor.fetchone()
    target_name = target_user["username"] if target_user else f"ID:{target_user_id}"
    
    cursor.execute("""
        DELETE FROM document_permissions 
        WHERE document_id = ? AND user_id = ?
    """, (document_id, target_user_id))
    rows_affected = cursor.rowcount
    db.commit()
    
    if rows_affected == 0:
        raise HTTPException(status_code=404, detail="Permission not found for this user on this document.")
        
    log_audit_event(
        conn=db,
        action_type="PERM_REVOKE",
        target_type="PERMISSION",
        target_id=str(document_id),
        outcome="SUCCESS",
        details=f"Owner '{current_user['username']}' immediately revoked access for '{target_name}' on '{doc['title']}'",
        actor_id=current_user["id"],
        actor_username=current_user["username"],
        ip_address=client_ip
    )
    
    return {
        "status": "success",
        "message": f"Access immediately revoked for {target_name}. Subsequent requests will be denied."
    }
