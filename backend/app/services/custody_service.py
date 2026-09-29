"""Docspector Custody Chain Service (Milestone 11).

Inspect. Verify. Trust.

This module provides the centralized, deterministic cryptographic custody ledger:
1. Canonical field serialization and SHA-256 hash calculation.
2. Genesis event handling (sequence 1, previous_event_hash=None, GENESIS seed).
3. Monotonically increasing sequence number allocation per case.
4. Concurrency handling and transaction serialization for event appends.
5. Read-only, comprehensive cryptographic chain verification.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import random
import time
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from app.core.authorization import verify_case_assignment
from app.db.models.custody_event import CustodyEvent
from app.db.models.document import Document
from app.db.models.document_version import DocumentVersion
from app.db.models.user import User
from app.schemas.custody import (
    CaseAuditResponse,
    ChainIntegritySummary,
    CustodyEventItem,
    DocumentCustodyResponse,
)

# Canonical validation result error codes
CHAIN_VALID: str = "VALID"
CHAIN_EMPTY: str = "EMPTY_CHAIN"
CHAIN_INVALID_GENESIS: str = "INVALID_GENESIS"
CHAIN_BROKEN_SEQUENCE: str = "BROKEN_SEQUENCE"
CHAIN_BROKEN_PREDECESSOR_LINK: str = "BROKEN_PREDECESSOR_LINK"
CHAIN_HASH_MISMATCH: str = "HASH_MISMATCH"
CHAIN_DUPLICATE_SEQUENCE: str = "DUPLICATE_SEQUENCE"
CHAIN_DUPLICATE_HASH: str = "DUPLICATE_EVENT_HASH"


@dataclass(frozen=True)
class ChainValidationResult:
    """Structured result from a read-only custody chain verification audit."""

    is_valid: bool
    case_id: int
    total_events: int
    status_code: str
    error_message: str | None = None
    broken_sequence_number: int | None = None
    details: dict[str, Any] = field(default_factory=dict)


def canonicalize_event_time(event_time: datetime) -> str:
    """Format a datetime into canonical ISO-8601 UTC string representation."""
    if event_time.tzinfo is None:
        utc_dt = event_time.replace(tzinfo=timezone.utc)
    else:
        utc_dt = event_time.astimezone(timezone.utc)
    return utc_dt.isoformat()


def serialize_event_data(event_data: dict[str, Any] | str | None) -> str | None:
    """Deterministically serialize event_data payload into a sorted JSON string."""
    if event_data is None:
        return None
    if isinstance(event_data, str):
        # Validate or parse JSON string if valid JSON to ensure deterministic key sorting
        try:
            parsed = json.loads(event_data)
            return json.dumps(parsed, sort_keys=True, separators=(",", ":"))
        except Exception:
            return event_data
    return json.dumps(event_data, sort_keys=True, separators=(",", ":"))


def compute_canonical_event_hash(
    case_id: int,
    sequence_number: int,
    event_type: str,
    actor_user_id: int,
    event_time: datetime,
    document_version_id: int | None = None,
    event_data_json: str | None = None,
    previous_event_hash: str | None = None,
) -> str:
    """Compute deterministic SHA-256 digest for a custody event in canonical format.

    Canonical format:
    SHA256(
      case_id:sequence_number:event_type:actor_user_id:iso_time:doc_v_id:event_data:prev_hash
    )
    Where:
    - previous_event_hash is replaced with 'GENESIS' when None (sequence 1).
    - event_data_json is replaced with 'EMPTY_DATA' when None.
    - document_version_id is replaced with 'NONE' when None.
    - Output is strictly 64 lowercase hexadecimal characters.
    """
    time_str = canonicalize_event_time(event_time)
    prev_str = previous_event_hash if previous_event_hash else "GENESIS"
    doc_str = str(document_version_id) if document_version_id is not None else "NONE"
    data_str = event_data_json if event_data_json is not None else "EMPTY_DATA"

    canonical_payload = (
        f"{case_id}:{sequence_number}:{event_type}:{actor_user_id}:"
        f"{time_str}:{doc_str}:{data_str}:{prev_str}"
    )
    return hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest().lower()


def append_custody_event(
    db: Session,
    case_id: int,
    event_type: str,
    actor_user_id: int,
    document_version_id: int | None = None,
    event_data: dict[str, Any] | str | None = None,
    event_time: datetime | None = None,
    max_retries: int = 5,
) -> CustodyEvent:
    """Append a new custody event to the case hash chain with concurrency control.

    Enforces:
    - Monotonically increasing sequence number per case (1, 2, 3, ...).
    - Sequence 1 has previous_event_hash = None and uses GENESIS root.
    - Sequence N > 1 has previous_event_hash equal to Event N-1's event_hash.
    - Deterministic canonical event_hash calculation.
    - Retries boundedly on concurrent sequence collisions or database locks.
    """
    now_utc = event_time or datetime.now(timezone.utc)
    event_data_json = serialize_event_data(event_data)

    for attempt in range(max_retries):
        try:
            with db.begin_nested():
                # Query the latest event for this case
                last_event = (
                    db.query(CustodyEvent)
                    .filter(CustodyEvent.case_id == case_id)
                    .order_by(CustodyEvent.sequence_number.desc())
                    .first()
                )

                sequence_number = (last_event.sequence_number + 1) if last_event else 1
                previous_event_hash = last_event.event_hash if last_event else None

                # Genesis invariant check
                if sequence_number == 1 and previous_event_hash is not None:
                    raise ValueError("Genesis event (sequence 1) must not have a previous_event_hash.")

                event_hash = compute_canonical_event_hash(
                    case_id=case_id,
                    sequence_number=sequence_number,
                    event_type=event_type,
                    actor_user_id=actor_user_id,
                    event_time=now_utc,
                    document_version_id=document_version_id,
                    event_data_json=event_data_json,
                    previous_event_hash=previous_event_hash,
                )

                event = CustodyEvent(
                    case_id=case_id,
                    document_version_id=document_version_id,
                    sequence_number=sequence_number,
                    event_type=event_type,
                    actor_user_id=actor_user_id,
                    event_time=now_utc,
                    event_data=event_data_json,
                    previous_event_hash=previous_event_hash,
                    event_hash=event_hash,
                )
                db.add(event)
                db.flush()
            return event

        except (IntegrityError, OperationalError) as exc:
            db.rollback()
            err_msg = str(exc)
            is_conflict = (
                "uq_custody_events_case_sequence" in err_msg
                or "uq_custody_events_event_hash" in err_msg
                or "database is locked" in err_msg
                or "SQLITE_BUSY" in err_msg
                or "UNIQUE constraint failed" in err_msg
            )
            if is_conflict and attempt < max_retries - 1:
                time.sleep(random.uniform(0.01, 0.04) * (1.5**attempt))
                continue
            raise


def validate_custody_chain(
    db: Session,
    case_id: int,
) -> ChainValidationResult:
    """Perform a comprehensive, strictly read-only cryptographic audit of a case's custody chain.

    Checks:
    1. Events are ordered strictly by sequence_number ascending.
    2. Sequence 1 satisfies Genesis semantics (previous_event_hash == None).
    3. Sequence numbers increment strictly by 1 without gaps or duplicates.
    4. Each event's previous_event_hash strictly matches the previous event's event_hash.
    5. Each event's event_hash matches the recomputed canonical SHA-256 digest.
    6. No duplicate event hashes.

    This function NEVER modifies, repairs, or rewrites any rows in the database.
    """
    events = (
        db.query(CustodyEvent)
        .filter(CustodyEvent.case_id == case_id)
        .order_by(CustodyEvent.sequence_number.asc())
        .all()
    )

    total_events = len(events)
    if total_events == 0:
        return ChainValidationResult(
            is_valid=True,
            case_id=case_id,
            total_events=0,
            status_code=CHAIN_EMPTY,
            error_message="Custody ledger is empty for this case.",
        )

    seen_sequences: set[int] = set()
    seen_hashes: set[str] = set()
    expected_prev_hash: str | None = None

    for idx, event in enumerate(events):
        seq = event.sequence_number
        expected_seq = idx + 1

        # Check for duplicate sequence numbers
        if seq in seen_sequences:
            return ChainValidationResult(
                is_valid=False,
                case_id=case_id,
                total_events=total_events,
                status_code=CHAIN_DUPLICATE_SEQUENCE,
                error_message=f"Duplicate sequence number {seq} detected at event index {idx}.",
                broken_sequence_number=seq,
                details={"event_id": event.id, "duplicate_sequence": seq},
            )
        seen_sequences.add(seq)

        # Check for sequence continuity
        if seq != expected_seq:
            return ChainValidationResult(
                is_valid=False,
                case_id=case_id,
                total_events=total_events,
                status_code=CHAIN_BROKEN_SEQUENCE,
                error_message=f"Sequence gap detected: expected sequence {expected_seq}, but found {seq}.",
                broken_sequence_number=seq,
                details={"expected_sequence": expected_seq, "actual_sequence": seq},
            )

        # Genesis validation (Sequence 1)
        if seq == 1:
            if event.previous_event_hash is not None:
                return ChainValidationResult(
                    is_valid=False,
                    case_id=case_id,
                    total_events=total_events,
                    status_code=CHAIN_INVALID_GENESIS,
                    error_message=f"Genesis event (sequence 1) must have previous_event_hash=None, but found '{event.previous_event_hash}'.",
                    broken_sequence_number=1,
                    details={"actual_previous_event_hash": event.previous_event_hash},
                )
        else:
            # Successor event validation (Sequence > 1)
            if event.previous_event_hash != expected_prev_hash:
                return ChainValidationResult(
                    is_valid=False,
                    case_id=case_id,
                    total_events=total_events,
                    status_code=CHAIN_BROKEN_PREDECESSOR_LINK,
                    error_message=(
                        f"Broken cryptographic link at sequence {seq}: "
                        f"previous_event_hash '{event.previous_event_hash}' does not match "
                        f"predecessor hash '{expected_prev_hash}'."
                    ),
                    broken_sequence_number=seq,
                    details={
                        "sequence": seq,
                        "stored_previous_event_hash": event.previous_event_hash,
                        "expected_previous_event_hash": expected_prev_hash,
                    },
                )

        # Recompute cryptographic hash from canonical fields
        recomputed_hash = compute_canonical_event_hash(
            case_id=event.case_id,
            sequence_number=event.sequence_number,
            event_type=event.event_type,
            actor_user_id=event.actor_user_id,
            event_time=event.event_time,
            document_version_id=event.document_version_id,
            event_data_json=event.event_data,
            previous_event_hash=event.previous_event_hash,
        )

        if event.event_hash != recomputed_hash:
            return ChainValidationResult(
                is_valid=False,
                case_id=case_id,
                total_events=total_events,
                status_code=CHAIN_HASH_MISMATCH,
                error_message=(
                    f"Hash mismatch at sequence {seq}: stored hash '{event.event_hash}' "
                    f"does not match recomputed hash '{recomputed_hash}'."
                ),
                broken_sequence_number=seq,
                details={
                    "sequence": seq,
                    "stored_hash": event.event_hash,
                    "recomputed_hash": recomputed_hash,
                },
            )

        # Check for duplicate event hashes
        if event.event_hash in seen_hashes:
            return ChainValidationResult(
                is_valid=False,
                case_id=case_id,
                total_events=total_events,
                status_code=CHAIN_DUPLICATE_HASH,
                error_message=f"Duplicate event_hash detected: '{event.event_hash}'.",
                broken_sequence_number=seq,
                details={"duplicate_hash": event.event_hash},
            )
        seen_hashes.add(event.event_hash)

        expected_prev_hash = event.event_hash

    return ChainValidationResult(
        is_valid=True,
        case_id=case_id,
        total_events=total_events,
        status_code=CHAIN_VALID,
        error_message=None,
    )


def get_document_custody(
    db: Session,
    document_id: int,
    current_user: User,
) -> DocumentCustodyResponse:
    """Retrieve custody history for a specific document.

    Authorization & Non-Disclosure:
    - User must be authenticated and actively assigned to the document's case.
    - If document does not exist or user is unassigned, returns 404 (IDOR non-disclosure).
    """
    document = db.query(Document).filter(Document.id == document_id).first()
    if document is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found",
        )

    verify_case_assignment(db, current_user, document.case_id)

    version_ids = [
        row[0]
        for row in db.query(DocumentVersion.id)
        .filter(DocumentVersion.document_id == document_id)
        .all()
    ]

    events = []
    if version_ids:
        events = (
            db.query(CustodyEvent)
            .filter(
                CustodyEvent.case_id == document.case_id,
                CustodyEvent.document_version_id.in_(version_ids),
            )
            .order_by(CustodyEvent.sequence_number.asc())
            .all()
        )

    chain_res = validate_custody_chain(db=db, case_id=document.case_id)
    chain_summary = ChainIntegritySummary(
        is_valid=chain_res.is_valid,
        status=chain_res.status_code,
        total_events=chain_res.total_events,
        broken_sequence_number=chain_res.broken_sequence_number,
        error_message=chain_res.error_message,
    )

    event_items = [CustodyEventItem.model_validate(e) for e in events]

    return DocumentCustodyResponse(
        document_id=document.id,
        case_id=document.case_id,
        document_number=document.document_number,
        events=event_items,
        chain_integrity=chain_summary,
    )


def get_case_audit(
    db: Session,
    case_id: int,
    current_user: User,
) -> CaseAuditResponse:
    """Retrieve full chronological audit history for a case across all accessible events.

    Authorization & Non-Disclosure:
    - User must be authenticated and actively assigned to the case.
    - If case does not exist or user is unassigned, returns 404.
    """
    case = verify_case_assignment(db, current_user, case_id)

    events = (
        db.query(CustodyEvent)
        .filter(CustodyEvent.case_id == case.id)
        .order_by(CustodyEvent.sequence_number.asc())
        .all()
    )

    chain_res = validate_custody_chain(db=db, case_id=case.id)
    chain_summary = ChainIntegritySummary(
        is_valid=chain_res.is_valid,
        status=chain_res.status_code,
        total_events=chain_res.total_events,
        broken_sequence_number=chain_res.broken_sequence_number,
        error_message=chain_res.error_message,
    )

    event_items = [CustodyEventItem.model_validate(e) for e in events]

    return CaseAuditResponse(
        case_id=case.id,
        case_number=case.case_number,
        events=event_items,
        chain_integrity=chain_summary,
    )
