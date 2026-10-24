from typing import Dict, Any, List, Optional
import sqlite3
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from app.database import get_db
from app.auth import require_admin
from app.audit import verify_audit_chain, compute_record_hash, log_audit_event
from app.models import AuditEventResponse, AuditVerificationResponse

router = APIRouter(prefix="/api/audit", tags=["Audit & Integrity"])

def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"

@router.get("/events")
def get_audit_events(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    actor: Optional[str] = None,
    action: Optional[str] = None,
    outcome: Optional[str] = None,
    admin_user: Dict[str, Any] = Depends(require_admin),
    db: sqlite3.Connection = Depends(get_db)
):
    """Admin-only view of the tamper-evident audit ledger."""
    cursor = db.cursor()
    
    where_clauses = []
    params: List[Any] = []
    
    if actor:
        where_clauses.append("actor_username = ?")
        params.append(actor.strip())
    if action:
        where_clauses.append("action_type = ?")
        params.append(action.strip())
    if outcome:
        where_clauses.append("outcome = ?")
        params.append(outcome.strip())
        
    where_str = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
    
    # Get total count
    cursor.execute(f"SELECT COUNT(*) FROM audit_events {where_str}", params)
    total = cursor.fetchone()[0]
    
    # Get paginated rows
    params.extend([limit, offset])
    cursor.execute(f"""
        SELECT * FROM audit_events 
        {where_str}
        ORDER BY id DESC 
        LIMIT ? OFFSET ?
    """, params)
    rows = cursor.fetchall()
    
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "events": [
            AuditEventResponse(
                id=r["id"],
                timestamp=r["timestamp"],
                actor_id=r["actor_id"],
                actor_username=r["actor_username"],
                action_type=r["action_type"],
                target_type=r["target_type"],
                target_id=r["target_id"],
                outcome=r["outcome"],
                details=r["details"],
                ip_address=r["ip_address"],
                prev_hash=r["prev_hash"],
                record_hash=r["record_hash"]
            )
            for r in rows
        ]
    }

@router.get("/verify", response_model=AuditVerificationResponse)
def verify_audit_trail_integrity(
    request: Request,
    admin_user: Dict[str, Any] = Depends(require_admin),
    db: sqlite3.Connection = Depends(get_db)
):
    """
    Verifies the entire cryptographic SHA-256 chain from the genesis record to the latest event.
    Detects any modification, insertion, deletion, or reordering.
    """
    is_valid, total, broken_id, error_msg, elapsed_ms = verify_audit_chain(db)
    return AuditVerificationResponse(
        is_valid=is_valid,
        total_events=total,
        broken_event_id=broken_id,
        error_message=error_msg,
        verification_time_ms=round(elapsed_ms, 2)
    )

@router.post("/tamper-test")
def simulate_audit_tampering(
    admin_user: Dict[str, Any] = Depends(require_admin),
    db: sqlite3.Connection = Depends(get_db)
):
    """
    Adversarial demonstration utility:
    Intentionally modifies record ID 2 in the database to prove that the SHA-256
    verification engine immediately catches unauthorized record alterations.
    """
    cursor = db.cursor()
    cursor.execute("SELECT id, details FROM audit_events WHERE id = 2;")
    row = cursor.fetchone()
    if not row:
        raise HTTPException(status_code=400, detail="Audit record 2 not found.")
        
    cursor.execute("""
        UPDATE audit_events 
        SET details = 'UNAUTHORIZED DBA MODIFICATION: Injected unauthorized change' 
        WHERE id = 2;
    """)
    db.commit()
    return {"status": "tampered", "modified_record_id": 2}

@router.post("/repair")
def repair_audit_tampering(
    admin_user: Dict[str, Any] = Depends(require_admin),
    db: sqlite3.Connection = Depends(get_db)
):
    """Restores the database by re-seeding the clean cryptographic ledger."""
    from seed_data import seed
    seed()
    return {"status": "restored", "message": "Audit ledger restored to pristine cryptographic state."}

