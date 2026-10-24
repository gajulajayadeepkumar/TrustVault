from typing import Optional, List
from pydantic import BaseModel, Field, EmailStr, ConfigDict

class UserRegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_\-\.]+$")
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    role: str = Field(..., pattern=r"^(ADMIN|OWNER|VIEWER)$")

class UserLoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(..., min_length=1, max_length=50)
    password: str = Field(..., min_length=1, max_length=128)

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    created_at: str

class UserProfileResponse(BaseModel):
    user: UserResponse
    permissions: List[str]

class DocumentUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=2000)
    category: Optional[str] = Field(None, min_length=1, max_length=100)

class PermissionGrantRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_username: str = Field(..., min_length=1, max_length=50)
    permission_level: str = Field(..., pattern=r"^(READ|EDIT)$")

class DocumentPermissionItem(BaseModel):
    id: int
    user_id: int
    username: str
    permission_level: str
    granted_by: int
    granted_at: str

class DocumentResponse(BaseModel):
    id: int
    title: str
    description: Optional[str]
    category: str
    original_filename: str
    file_size: int
    mime_type: str
    file_hash_sha256: str
    owner_id: int
    owner_username: str
    user_permission: str  # 'OWNER', 'EDIT', 'READ'
    created_at: str
    updated_at: str

class AuditEventResponse(BaseModel):
    id: int
    timestamp: str
    actor_id: Optional[int]
    actor_username: Optional[str]
    action_type: str
    target_type: str
    target_id: Optional[str]
    outcome: str
    details: Optional[str]
    ip_address: Optional[str]
    prev_hash: str
    record_hash: str

class AuditVerificationResponse(BaseModel):
    is_valid: bool
    total_events: int
    broken_event_id: Optional[int] = None
    error_message: Optional[str] = None
    verification_time_ms: float
