from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.db.models.document_version import DocumentVersion
    from app.db.models.user import User


class Transfer(Base):
    __tablename__ = "transfers"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    document_version_id: Mapped[int] = mapped_column(
        ForeignKey("document_versions.id", ondelete="CASCADE"),
        nullable=False,
    )
    requester_user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"),
        nullable=False,
    )
    recipient_user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id"),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(String(50), default="PENDING", nullable=False)
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    decided_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"),
        nullable=True,
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    document_version: Mapped["DocumentVersion"] = relationship(
        "DocumentVersion",
        back_populates="transfers",
    )
    requester_user: Mapped["User"] = relationship(
        "User",
        foreign_keys=[requester_user_id],
        back_populates="requested_transfers",
    )
    recipient_user: Mapped["User"] = relationship(
        "User",
        foreign_keys=[recipient_user_id],
        back_populates="received_transfers",
    )
    decided_by_user: Mapped["User | None"] = relationship(
        "User",
        foreign_keys=[decided_by_user_id],
        back_populates="decided_transfers",
    )
