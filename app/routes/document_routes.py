from datetime import datetime, timezone
import sqlite3
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Response, UploadFile, File, Form, status
from fastapi.responses import FileResponse
from app.database import get_db
from app.models import DocumentResponse, DocumentUpdateRequest
from app.auth import get_current_user
from app.authorization import verify_document_access, get_document_or_404
from app.storage import save_uploaded_file, get_vault_file_path, delete_vault_file
from app.audit import log_audit_event

router = APIRouter(prefix="/api/documents", tags=["Documents"])

def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"

@router.post("/upload")
async def upload_document(
    request: Request,
    file: UploadFile = File(...),
    title: str = Form(..., min_length=1, max_length=255),
    description: Optional[str] = Form(None, max_length=2000),
    category: str = Form("General", min_length=1, max_length=100),
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db)
):
    client_ip = get_client_ip(request)
    user_id = current_user["id"]
    username = current_user["username"]
    
    # 1. Check role: VIEWERS cannot upload root documents
    if current_user["role"] == "VIEWER":
        log_audit_event(
            conn=db,
            action_type="DOC_UPLOAD_DENIED",
            target_type="DOCUMENT",
            target_id="NEW",
            outcome="DENIED",
            details=f"Viewer '{username}' attempted to upload a document.",
            actor_id=user_id,
            actor_username=username,
            ip_address=client_ip
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="VIEWER accounts are read-only and cannot upload documents."
        )

    # 2. Validate and save file into private storage vault
    sanitized_orig_name, stored_uuid, file_size, mime_type, sha256_hash = await save_uploaded_file(file)
    now_utc = datetime.now(timezone.utc).isoformat()
    
    # 3. Insert record into database
    cursor = db.cursor()
    cursor.execute("""
        INSERT INTO documents 
        (title, description, category, original_filename, stored_filename, file_size, mime_type, file_hash_sha256, owner_id, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        title.strip(),
        description.strip() if description else None,
        category.strip(),
        sanitized_orig_name,
        stored_uuid,
        file_size,
        mime_type,
        sha256_hash,
        user_id,
        now_utc,
        now_utc
    ))
    doc_id = cursor.lastrowid
    db.commit()

    # 4. Audit upload event
    log_audit_event(
        conn=db,
        action_type="DOC_UPLOAD",
        target_type="DOCUMENT",
        target_id=str(doc_id),
        outcome="SUCCESS",
        details=f"Uploaded '{title}' ({sanitized_orig_name}, {file_size} bytes, SHA-256: {sha256_hash[:12]}...)",
        actor_id=user_id,
        actor_username=username,
        ip_address=client_ip
    )

    return {
        "status": "success",
        "document_id": doc_id,
        "title": title,
        "filename": sanitized_orig_name,
        "size": file_size,
        "sha256": sha256_hash
    }

@router.get("", response_model=List[DocumentResponse])
def list_documents(
    request: Request,
    search: Optional[str] = None,
    category: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db)
):
    """
    Lists only documents accessible to the current user (Owned OR Shared).
    Zero information leakage: Unshared confidential files are completely omitted from results and counts.
    """
    user_id = current_user["id"]
    cursor = db.cursor()

    # Query joins documents and explicit permissions
    # User sees document IF:
    # 1. user is owner (d.owner_id = user_id)
    # OR
    # 2. user has explicit permission in document_permissions
    base_sql = """
        SELECT 
            d.id, d.title, d.description, d.category, d.original_filename,
            d.file_size, d.mime_type, d.file_hash_sha256, d.owner_id,
            d.created_at, d.updated_at,
            u.username as owner_username,
            CASE 
                WHEN d.owner_id = ? THEN 'OWNER'
                ELSE dp.permission_level
            END as user_permission
        FROM documents d
        JOIN users u ON d.owner_id = u.id
        LEFT JOIN document_permissions dp ON (dp.document_id = d.id AND dp.user_id = ?)
        WHERE (d.owner_id = ? OR dp.user_id = ?)
    """
    params: List[Any] = [user_id, user_id, user_id, user_id]

    if search:
        search_pattern = f"%{search.strip()}%"
        base_sql += " AND (d.title LIKE ? OR d.description LIKE ? OR d.original_filename LIKE ?)"
        params.extend([search_pattern, search_pattern, search_pattern])

    if category:
        base_sql += " AND d.category = ?"
        params.append(category.strip())

    if date_from:
        base_sql += " AND d.created_at >= ?"
        params.append(date_from)

    if date_to:
        base_sql += " AND d.created_at <= ?"
        params.append(date_to)

    base_sql += " ORDER BY d.id DESC"
    cursor.execute(base_sql, params)
    rows = cursor.fetchall()

    return [
        DocumentResponse(
            id=r["id"],
            title=r["title"],
            description=r["description"],
            category=r["category"],
            original_filename=r["original_filename"],
            file_size=r["file_size"],
            mime_type=r["mime_type"],
            file_hash_sha256=r["file_hash_sha256"],
            owner_id=r["owner_id"],
            owner_username=r["owner_username"],
            user_permission=r["user_permission"],
            created_at=r["created_at"],
            updated_at=r["updated_at"]
        )
        for r in rows
    ]

@router.get("/{document_id}", response_model=DocumentResponse)
def get_document_details(
    document_id: int,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db)
):
    client_ip = get_client_ip(request)
    doc, perm_level = verify_document_access(db, current_user, document_id, "READ", client_ip)
    
    log_audit_event(
        conn=db,
        action_type="DOC_VIEW",
        target_type="DOCUMENT",
        target_id=str(document_id),
        outcome="SUCCESS",
        details=f"Viewed metadata for '{doc['title']}' (Access level: {perm_level})",
        actor_id=current_user["id"],
        actor_username=current_user["username"],
        ip_address=client_ip
    )
    
    return DocumentResponse(
        id=doc["id"],
        title=doc["title"],
        description=doc["description"],
        category=doc["category"],
        original_filename=doc["original_filename"],
        file_size=doc["file_size"],
        mime_type=doc["mime_type"],
        file_hash_sha256=doc["file_hash_sha256"],
        owner_id=doc["owner_id"],
        owner_username=doc["owner_username"],
        user_permission=perm_level,
        created_at=doc["created_at"],
        updated_at=doc["updated_at"]
    )

@router.get("/{document_id}/download")
def download_document(
    document_id: int,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db)
):
    client_ip = get_client_ip(request)
    doc, perm_level = verify_document_access(db, current_user, document_id, "READ", client_ip)
    
    vault_path = get_vault_file_path(doc["stored_filename"])
    
    log_audit_event(
        conn=db,
        action_type="DOC_DOWNLOAD",
        target_type="DOCUMENT",
        target_id=str(document_id),
        outcome="SUCCESS",
        details=f"Downloaded '{doc['original_filename']}' (Size: {doc['file_size']} bytes)",
        actor_id=current_user["id"],
        actor_username=current_user["username"],
        ip_address=client_ip
    )

    # Force attachment download header and nosniff to prevent inline XSS
    return FileResponse(
        path=vault_path,
        media_type="application/octet-stream",
        filename=doc["original_filename"],
        headers={
            "Content-Disposition": f'attachment; filename="{doc["original_filename"]}"',
            "X-Content-Type-Options": "nosniff"
        }
    )

@router.get("/{document_id}/preview")
def preview_document(
    document_id: int,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db)
):
    client_ip = get_client_ip(request)
    doc, perm_level = verify_document_access(db, current_user, document_id, "READ", client_ip)
    
    vault_path = get_vault_file_path(doc["stored_filename"])
    
    log_audit_event(
        conn=db,
        action_type="DOC_PREVIEW",
        target_type="DOCUMENT",
        target_id=str(document_id),
        outcome="SUCCESS",
        details=f"Previewed document '{doc['original_filename']}'",
        actor_id=current_user["id"],
        actor_username=current_user["username"],
        ip_address=client_ip
    )

    return FileResponse(
        path=vault_path,
        media_type=doc["mime_type"],
        headers={
            "Content-Disposition": f'inline; filename="{doc["original_filename"]}"',
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox"
        }
    )

@router.put("/{document_id}")
def update_document(
    document_id: int,
    payload: DocumentUpdateRequest,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db)
):
    client_ip = get_client_ip(request)
    doc, perm_level = verify_document_access(db, current_user, document_id, "EDIT", client_ip)
    
    updates = []
    params: List[Any] = []
    changes = []
    
    if payload.title is not None:
        updates.append("title = ?")
        params.append(payload.title.strip())
        changes.append(f"title='{payload.title.strip()}'")
        
    if payload.description is not None:
        updates.append("description = ?")
        params.append(payload.description.strip())
        changes.append("description updated")
        
    if payload.category is not None:
        updates.append("category = ?")
        params.append(payload.category.strip())
        changes.append(f"category='{payload.category.strip()}'")
        
    if not updates:
        return {"status": "success", "message": "No changes specified."}
        
    now_utc = datetime.now(timezone.utc).isoformat()
    updates.append("updated_at = ?")
    params.append(now_utc)
    params.append(document_id)
    
    cursor = db.cursor()
    cursor.execute(f"UPDATE documents SET {', '.join(updates)} WHERE id = ?", params)
    db.commit()
    
    log_audit_event(
        conn=db,
        action_type="DOC_EDIT",
        target_type="DOCUMENT",
        target_id=str(document_id),
        outcome="SUCCESS",
        details=f"Edited document '{doc['title']}': {', '.join(changes)}",
        actor_id=current_user["id"],
        actor_username=current_user["username"],
        ip_address=client_ip
    )
    
    return {"status": "success", "message": "Document updated successfully."}

@router.delete("/{document_id}")
def delete_document(
    document_id: int,
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db)
):
    client_ip = get_client_ip(request)
    # Strictly checks OWNER authorization
    doc, perm_level = verify_document_access(db, current_user, document_id, "DELETE", client_ip)
    
    # Delete underlying physical file
    delete_vault_file(doc["stored_filename"])
    
    # Delete database record (cascades permissions)
    cursor = db.cursor()
    cursor.execute("DELETE FROM documents WHERE id = ?", (document_id,))
    db.commit()
    
    log_audit_event(
        conn=db,
        action_type="DOC_DELETE",
        target_type="DOCUMENT",
        target_id=str(document_id),
        outcome="SUCCESS",
        details=f"Owner '{current_user['username']}' deleted document '{doc['title']}' ({doc['original_filename']})",
        actor_id=current_user["id"],
        actor_username=current_user["username"],
        ip_address=client_ip
    )
    
    return {"status": "success", "message": f"Document '{doc['title']}' deleted successfully."}
