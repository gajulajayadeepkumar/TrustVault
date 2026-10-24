import os
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
STORAGE_VAULT_DIR = BASE_DIR / "storage_vault"
DATABASE_PATH = BASE_DIR / "trustvault.db"

# Ensure storage vault directory exists
STORAGE_VAULT_DIR.mkdir(parents=True, exist_ok=True)

# Security & Session Settings
SECRET_KEY = os.getenv("TRUSTVAULT_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError("TRUSTVAULT_SECRET_KEY environment variable must be set")
SESSION_EXPIRE_SECONDS = int(os.getenv("TRUSTVAULT_SESSION_EXPIRE", "7200"))  # 2 Hours
MAX_LOGIN_ATTEMPTS = int(os.getenv("TRUSTVAULT_MAX_LOGIN_ATTEMPTS", "5"))
LOCKOUT_DURATION_SECONDS = int(os.getenv("TRUSTVAULT_LOCKOUT_SECONDS", "900"))  # 15 Minutes

# Rate Limiting
RATE_LIMIT_LOGIN_MAX = 5
RATE_LIMIT_LOGIN_WINDOW = 60  # seconds
RATE_LIMIT_API_MAX = 100
RATE_LIMIT_API_WINDOW = 60

# File Upload Security Settings
MAX_FILE_SIZE_BYTES = 20 * 1024 * 1024  # 20 MB
ALLOWED_EXTENSIONS = {
    ".pdf", ".docx", ".xlsx", ".png", ".jpg", ".jpeg", ".txt", ".csv"
}

ALLOWED_MIME_TYPES = {
    "application/pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "image/png",
    "image/jpeg",
    "text/plain",
    "text/csv"
}

# Magic bytes (file signatures) to prevent MIME and extension spoofing
FILE_SIGNATURES = {
    "application/pdf": [b"%PDF-"],
    "image/png": [b"\x89PNG\r\n\x1a\n"],
    "image/jpeg": [b"\xff\xd8\xff"],
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": [b"PK\x03\x04"],
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": [b"PK\x03\x04"],
}

# Genesis hash for tamper-evident audit ledger
GENESIS_HASH = "GENESIS_HASH_TRUSTVAULT_ROOT_0000000000000000000000000000000000"
