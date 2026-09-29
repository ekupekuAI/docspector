from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.db.models.case import Case
    from app.db.models.document_version import DocumentVersion
    from app.db.models.user import User


class IntegrityAlert(Base):
    __tablename__ = "integrity_alerts"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    case_id: Mapped[int] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False,
    )
    document_version_id: Mapped[int | None] = mapped_column(
        ForeignKey("document_versions.id", ondelete="SET NULL"),
        nullable=True,
    )
    alert_type: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[str] = mapped_column(String(50), default="HIGH", nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="OPEN", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reviewed_by_user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id"),
        nullable=True,
    )

    # Relationships
    case: Mapped["Case"] = relationship("Case", back_populates="integrity_alerts")
    document_version: Mapped["DocumentVersion | None"] = relationship(
        "DocumentVersion",
        back_populates="integrity_alerts",
    )
    reviewed_by_user: Mapped["User | None"] = relationship("User", back_populates="reviewed_alerts")
