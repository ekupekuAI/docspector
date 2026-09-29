from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.db.models.case_assignment import CaseAssignment
    from app.db.models.custody_event import CustodyEvent
    from app.db.models.document import Document
    from app.db.models.document_version import DocumentVersion
    from app.db.models.integrity_alert import IntegrityAlert
    from app.db.models.transfer import Transfer


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    case_assignments: Mapped[list["CaseAssignment"]] = relationship(
        "CaseAssignment",
        back_populates="user",
        cascade="all, delete-orphan",
    )
    created_documents: Mapped[list["Document"]] = relationship(
        "Document",
        back_populates="created_by_user",
    )
    created_versions: Mapped[list["DocumentVersion"]] = relationship(
        "DocumentVersion",
        back_populates="created_by_user",
    )
    requested_transfers: Mapped[list["Transfer"]] = relationship(
        "Transfer",
        back_populates="requester_user",
        foreign_keys="Transfer.requester_user_id",
    )
    received_transfers: Mapped[list["Transfer"]] = relationship(
        "Transfer",
        back_populates="recipient_user",
        foreign_keys="Transfer.recipient_user_id",
    )
    decided_transfers: Mapped[list["Transfer"]] = relationship(
        "Transfer",
        back_populates="decided_by_user",
        foreign_keys="Transfer.decided_by_user_id",
    )
    custody_events: Mapped[list["CustodyEvent"]] = relationship(
        "CustodyEvent",
        back_populates="actor_user",
    )
    reviewed_alerts: Mapped[list["IntegrityAlert"]] = relationship(
        "IntegrityAlert",
        back_populates="reviewed_by_user",
    )
