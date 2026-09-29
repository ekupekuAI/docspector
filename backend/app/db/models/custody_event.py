from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.db.models.case import Case
    from app.db.models.document_version import DocumentVersion
    from app.db.models.user import User


class CustodyEvent(Base):
    __tablename__ = "custody_events"
    __table_args__ = (
        UniqueConstraint("case_id", "sequence_number", name="uq_custody_events_case_sequence"),
        UniqueConstraint("event_hash", name="uq_custody_events_event_hash"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    case_id: Mapped[int] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False,
    )
    document_version_id: Mapped[int | None] = mapped_column(
        ForeignKey("document_versions.id", ondelete="SET NULL"),
        nullable=True,
    )
    sequence_number: Mapped[int] = mapped_column(Integer, nullable=False)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    actor_user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"),
        nullable=False,
    )
    event_time: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    event_data: Mapped[str | None] = mapped_column(Text, nullable=True)
    previous_event_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    case: Mapped["Case"] = relationship("Case", back_populates="custody_events")
    document_version: Mapped["DocumentVersion | None"] = relationship(
        "DocumentVersion",
        back_populates="custody_events",
    )
    actor_user: Mapped["User"] = relationship("User", back_populates="custody_events")
