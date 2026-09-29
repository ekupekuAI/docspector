"""Docspector Storage Reconciliation & Consistency Service (Milestone 17).

Inspect. Verify. Trust.

Provides centralized auditing and reconciliation between database metadata and private storage:
1. Missing-file detection (DB has record, storage file missing -> marks RESTRICTED + logs alert).
2. Physical size mismatch detection (DB metadata != disk size -> marks RESTRICTED + logs alert).
3. Hash mismatch detection (DB SHA-256 != recomputed disk hash -> marks RESTRICTED + logs alert).
4. Stale UPLOADING record handling (unfinalized transaction -> marks RESTRICTED/QUARANTINED + logs alert).
5. Orphan file detection (storage file exists with no DB record -> flagged, preserved as evidence).
6. Orphan temporary file detection (stray .tmp files -> flagged/reported).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.models.document import Document
from app.db.models.document_version import DocumentVersion
from app.db.models.integrity_alert import IntegrityAlert
from app.services.file_validation import DEFAULT_CHUNK_SIZE_BYTES, safe_resolve_storage_path

settings = get_settings()


@dataclass
class ReconciliationReport:
    """Structured report produced by storage reconciliation audit."""

    total_versions_checked: int = 0
    valid_versions_count: int = 0
    missing_files_count: int = 0
    size_mismatches_count: int = 0
    hash_mismatches_count: int = 0
    stale_uploading_count: int = 0
    orphan_files: list[str] = field(default_factory=list)
    orphan_temp_files: list[str] = field(default_factory=list)
    alerts_created: list[int] = field(default_factory=list)


def _get_or_create_reconciliation_alert(
    db: Session,
    case_id: int,
    document_version_id: int | None,
    alert_type: str,
    message: str,
    severity: str = "CRITICAL",
) -> IntegrityAlert:
    """Idempotently fetch or create an OPEN integrity alert for a storage inconsistency."""
    existing_alert = (
        db.query(IntegrityAlert)
        .filter(
            IntegrityAlert.case_id == case_id,
            IntegrityAlert.document_version_id == document_version_id,
            IntegrityAlert.alert_type == alert_type,
            IntegrityAlert.status == "OPEN",
        )
        .first()
    )
    if existing_alert:
        return existing_alert

    alert = IntegrityAlert(
        case_id=case_id,
        document_version_id=document_version_id,
        alert_type=alert_type,
        severity=severity,
        message=message,
        status="OPEN",
        created_at=datetime.now(timezone.utc),
    )
    db.add(alert)
    db.flush()
    return alert


def audit_storage_and_reconcile(
    db: Session,
    storage_dir: Path | str | None = None,
) -> ReconciliationReport:
    """Execute full two-way reconciliation audit between DB metadata and physical storage."""
    active_storage_dir = Path(storage_dir or settings.storage_dir)
    active_storage_dir.mkdir(parents=True, exist_ok=True)

    report = ReconciliationReport()

    # 1. Fetch all versions from database
    versions = db.query(DocumentVersion).all()
    known_storage_keys: set[str] = set()

    for version in versions:
        report.total_versions_checked += 1
        known_storage_keys.add(version.storage_key)

        document = db.query(Document).filter(Document.id == version.document_id).first()
        case_id = document.case_id if document else 1

        # Check for stale UPLOADING records
        if version.state == "UPLOADING":
            version.state = "RESTRICTED"
            alert = _get_or_create_reconciliation_alert(
                db=db,
                case_id=case_id,
                document_version_id=version.id,
                alert_type="STORAGE_INCONSISTENCY",
                message=f"Stale unfinalized UPLOADING state detected for version {version.id} (version #{version.version_number}).",
                severity="HIGH",
            )
            report.stale_uploading_count += 1
            report.alerts_created.append(alert.id)
            continue

        if version.state in ("STORED", "RESTRICTED", "QUARANTINED"):
            try:
                target_file = safe_resolve_storage_path(active_storage_dir, version.storage_key)
            except Exception as exc:
                target_file = active_storage_dir / version.storage_key

            # A. Check existence
            if not target_file.is_file():
                version.state = "RESTRICTED"
                alert = _get_or_create_reconciliation_alert(
                    db=db,
                    case_id=case_id,
                    document_version_id=version.id,
                    alert_type="STORAGE_INCONSISTENCY",
                    message=f"Physical file missing for document version {version.id} (expected storage key '{version.storage_key}').",
                    severity="CRITICAL",
                )
                report.missing_files_count += 1
                report.alerts_created.append(alert.id)
                continue

            # B. Check file size
            actual_size = target_file.stat().st_size
            if actual_size != version.size_bytes:
                version.state = "RESTRICTED"
                alert = _get_or_create_reconciliation_alert(
                    db=db,
                    case_id=case_id,
                    document_version_id=version.id,
                    alert_type="STORAGE_INCONSISTENCY",
                    message=f"Physical file size mismatch: stored={version.size_bytes} bytes, actual={actual_size} bytes.",
                    severity="CRITICAL",
                )
                report.size_mismatches_count += 1
                report.alerts_created.append(alert.id)
                continue

            # C. Check SHA-256 digest
            sha256 = hashlib.sha256()
            with open(target_file, "rb") as f:
                while True:
                    chunk = f.read(DEFAULT_CHUNK_SIZE_BYTES)
                    if not chunk:
                        break
                    sha256.update(chunk)
            actual_hash = sha256.hexdigest().lower()

            if actual_hash != version.sha256_hash.lower():
                version.state = "RESTRICTED"
                alert = _get_or_create_reconciliation_alert(
                    db=db,
                    case_id=case_id,
                    document_version_id=version.id,
                    alert_type="STORAGE_INCONSISTENCY",
                    message=f"Physical file hash mismatch: expected={version.sha256_hash}, actual={actual_hash}.",
                    severity="CRITICAL",
                )
                report.hash_mismatches_count += 1
                report.alerts_created.append(alert.id)
                continue

            report.valid_versions_count += 1

    # 2. Audit disk directory for orphan files and stale temporary files
    for entry in active_storage_dir.iterdir():
        if entry.is_file():
            if entry.name.endswith(".tmp"):
                report.orphan_temp_files.append(entry.name)
            elif entry.name not in known_storage_keys:
                report.orphan_files.append(entry.name)

    db.commit()
    return report
