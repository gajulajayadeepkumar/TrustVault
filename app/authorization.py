import sqlite3
from typing import Dict, Any, Tuple
from fastapi import HTTPException, status
from app.audit import log_audit_event

def get_document_or_404(db: sqlite3.Connection, document_id: int) -> sqlite3.Row:
    """Fetches a document by ID or raises 404."""
    cursor = db.cursor()
    cursor.execute("""
        SELECT d.*, u.username as owner_username 
        FROM documents d
        JOIN users u ON d.owner_id = u.id
        WHERE d.id = ?
    """, (document_id,))
    doc = cursor.fetchone()
    if not doc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Document with ID {document_id} was not found."
        )
    return doc

def verify_document_access(
    db: sqlite3.Connection,
    user: Dict[str, Any],
    document_id: int,
    required_level: str = "READ",
    client_ip: str = "UNKNOWN"
) -> Tuple[sqlite3.Row, str]:
    """
    Centralized Authorization Enforcement Engine (Zero Trust / Deny-by-Default).
    
    CRITICAL SECURITY INVARIANTS:
    1. Administrators do NOT automatically gain read/download access to confidential documents.
    2. Document owners have full rights (READ, EDIT, DELETE, SHARE).
    3. Permitted users have rights bounded strictly by their granted level ('READ' or 'EDIT').
    4. Deletion is restricted to the document OWNER.
    5. Access denials are immediately audited.
    
    Returns: (document_row, effective_permission_level)
    """
    doc = get_document_or_404(db, document_id)
    user_id = user["id"]
    username = user["username"]
    
    # 1. Check if user is the Document Owner
    if doc["owner_id"] == user_id:
        return doc, "OWNER"
        
    # 2. Deletion is strictly reserved for the Document Owner
    if required_level == "DELETE":
        log_audit_event(
            conn=db,
            action_type="DOCUMENT_DELETE_DENIED",
            target_type="DOCUMENT",
            target_id=str(document_id),
            outcome="DENIED",
            details=f"User '{username}' attempted to delete document '{doc['title']}' owned by '{doc['owner_username']}'.",
            actor_id=user_id,
            actor_username=username,
            ip_address=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the document owner has permission to delete this document."
        )

    # 3. Check live document permissions table (enforces immediate revocation)
    cursor = db.cursor()
    cursor.execute("""
        SELECT permission_level 
        FROM document_permissions 
        WHERE document_id = ? AND user_id = ?
    """, (document_id, user_id))
    perm_row = cursor.fetchone()
    
    if not perm_row:
        # Access Denied: User has no permission on this document
        # Note: Even if user is ADMIN, access is denied unless explicitly shared.
        admin_note = " (ADMIN role does not bypass confidential document privacy)" if user["role"] == "ADMIN" else ""
        log_audit_event(
            conn=db,
            action_type="ACCESS_DENIED",
            target_type="DOCUMENT",
            target_id=str(document_id),
            outcome="DENIED",
            details=f"Unauthorized {required_level} attempt on document '{doc['title']}' by user '{username}' (Role: {user['role']}){admin_note}.",
            actor_id=user_id,
            actor_username=username,
            ip_address=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied: You do not have permission to access this document{admin_note}."
        )
        
    granted_level = perm_row["permission_level"]
    
    # 4. Check permission level sufficiency
    if required_level == "READ" and granted_level in ("READ", "EDIT"):
        return doc, granted_level
        
    if required_level == "EDIT" and granted_level == "EDIT":
        return doc, granted_level

    # Insufficient permission level (e.g. READ user trying to EDIT)
    log_audit_event(
        conn=db,
        action_type="ACCESS_DENIED",
        target_type="DOCUMENT",
        target_id=str(document_id),
        outcome="DENIED",
        details=f"Insufficient permissions: User '{username}' has '{granted_level}' permission but requested '{required_level}' on '{doc['title']}'.",
        actor_id=user_id,
        actor_username=username,
        ip_address=client_ip
    )
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=f"Access denied: This operation requires '{required_level}' permission, but you only have '{granted_level}' access."
    )

def verify_can_manage_permissions(
    db: sqlite3.Connection,
    user: Dict[str, Any],
    document_id: int,
    client_ip: str = "UNKNOWN"
) -> sqlite3.Row:
    """Verifies that the user has the authority to grant or revoke permissions (strictly document owner)."""
    doc = get_document_or_404(db, document_id)
    if doc["owner_id"] != user["id"]:
        log_audit_event(
            conn=db,
            action_type="PERMISSION_MANAGE_DENIED",
            target_type="DOCUMENT",
            target_id=str(document_id),
            outcome="DENIED",
            details=f"User '{user['username']}' attempted to modify permissions on document '{doc['title']}' owned by '{doc['owner_username']}'.",
            actor_id=user["id"],
            actor_username=user["username"],
            ip_address=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the document owner can grant or revoke permissions."
        )
    return doc
