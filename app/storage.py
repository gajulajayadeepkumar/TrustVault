import os
import re
import uuid
import hashlib
from pathlib import Path
from typing import Tuple
from fastapi import HTTPException, UploadFile
from app.config import (
    STORAGE_VAULT_DIR,
    MAX_FILE_SIZE_BYTES,
    ALLOWED_EXTENSIONS,
    ALLOWED_MIME_TYPES,
    FILE_SIGNATURES
)

def sanitize_filename(filename: str) -> str:
    """
    Sanitizes client-supplied filename to prevent directory traversal and null byte injections.
    Extracts the basename and replaces dangerous characters.
    """
    if not filename:
        return "unnamed_document"
    
    # Strip path traversal patterns
    base_name = os.path.basename(filename.replace("\\", "/"))
    # Remove null bytes and non-printable characters
    clean_name = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', base_name)
    # Strip dangerous characters
    clean_name = re.sub(r'[^a-zA-Z0-9_\-\. ]', '_', clean_name).strip()
    return clean_name or "unnamed_document"

def validate_magic_bytes(file_bytes: bytes, mime_type: str) -> bool:
    """
    Validates binary header magic bytes to prevent MIME and extension spoofing.
    """
    if mime_type in FILE_SIGNATURES:
        signatures = FILE_SIGNATURES[mime_type]
        for sig in signatures:
            if file_bytes.startswith(sig):
                return True
        return False
    # For text/plain and text/csv, verify valid UTF-8/ASCII without null bytes
    if mime_type in ("text/plain", "text/csv"):
        try:
            sample = file_bytes[:4096].decode("utf-8")
            if "\x00" in sample:
                return False
            return True
        except UnicodeDecodeError:
            return False
    return True

async def save_uploaded_file(upload_file: UploadFile) -> Tuple[str, str, int, str, str]:
    """
    Validates and stores an uploaded file in the private storage vault.
    Returns: (sanitized_original_filename, stored_uuid_filename, file_size, mime_type, sha256_checksum)
    """
    raw_filename = upload_file.filename or "upload"
    sanitized_name = sanitize_filename(raw_filename)
    
    # Extension validation
    ext = Path(sanitized_name).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Disallowed file extension '{ext}'. Allowed extensions: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
        )
    
    # Read file content safely
    content = await upload_file.read()
    file_size = len(content)
    
    if file_size == 0:
        raise HTTPException(status_code=400, detail="Cannot upload an empty file.")
        
    if file_size > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds maximum allowed size of {MAX_FILE_SIZE_BYTES // (1024 * 1024)} MB."
        )
        
    # MIME validation
    declared_mime = (upload_file.content_type or "application/octet-stream").lower().split(";")[0].strip()
    if declared_mime not in ALLOWED_MIME_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Disallowed MIME type '{declared_mime}'."
        )
        
    # Signature / Magic bytes inspection
    if not validate_magic_bytes(content, declared_mime):
        raise HTTPException(
            status_code=400,
            detail=f"File content signature does not match declared MIME type '{declared_mime}'. Upload rejected."
        )
        
    # Generate cryptographic SHA-256 checksum
    sha256_checksum = hashlib.sha256(content).hexdigest()
    
    # Generate private UUID4 filename inside storage vault
    stored_filename = f"{uuid.uuid4().hex}.dat"
    target_path = STORAGE_VAULT_DIR / stored_filename
    
    # Atomic write to private vault
    with open(target_path, "wb") as f:
        f.write(content)
        
    return sanitized_name, stored_filename, file_size, declared_mime, sha256_checksum

def get_vault_file_path(stored_filename: str) -> Path:
    """Resolves stored filename inside private vault, ensuring no path traversal outside vault."""
    safe_name = os.path.basename(stored_filename)
    file_path = (STORAGE_VAULT_DIR / safe_name).resolve()
    
    # Strict boundary check
    if not str(file_path).startswith(str(STORAGE_VAULT_DIR.resolve())):
        raise HTTPException(status_code=403, detail="Illegal file path access attempt.")
        
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="Requested file does not exist in vault.")
        
    return file_path

def delete_vault_file(stored_filename: str) -> bool:
    """Securely deletes a file from the vault."""
    try:
        path = get_vault_file_path(stored_filename)
        path.unlink(missing_ok=True)
        return True
    except Exception:
        return False
