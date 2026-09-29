from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.db.models.custody_event import CustodyEvent
    from app.db.models.document import Document
    from app.db.models.integrity_alert import IntegrityAlert
    from app.db.models.transfer import Transfer
    from app.db.models.user import User


class DocumentVersion(Base):
    __tablename__ = "document_versions"
    __table_args__ = (
        UniqueConstraint("document_id", "version_number", name="uq_document_versions_doc_version"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    document_id: Mapped[int] = mapped_column(
        ForeignKey("documents.id", ondelete="CASCADE"),
        nullable=False,
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[str] = mapped_column(String(50), nullable=False)
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    mime_type: Mapped[str] = mapped_column(String(100), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    storage_key: Mapped[str] = mapped_column(String(500), nullable=False)
    created_by_user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    document: Mapped["Document"] = relationship("Document", back_populates="versions")
    created_by_user: Mapped["User"] = relationship("User", back_populates="created_versions")
    transfers: Mapped[list["Transfer"]] = relationship(
        "Transfer",
        back_populates="document_version",
        cascade="all, delete-orphan",
    )
    custody_events: Mapped[list["CustodyEvent"]] = relationship(
        "CustodyEvent",
        back_populates="document_version",
    )
    integrity_alerts: Mapped[list["IntegrityAlert"]] = relationship(
        "IntegrityAlert",
        back_populates="document_version",
    )
