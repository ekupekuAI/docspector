from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.db.models.case import Case
    from app.db.models.user import User


class CaseAssignment(Base):
    __tablename__ = "case_assignments"
    __table_args__ = (
        UniqueConstraint("case_id", "user_id", name="uq_case_assignments_case_user"),
    )

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    case_id: Mapped[int] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    assigned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Relationships
    case: Mapped["Case"] = relationship("Case", back_populates="assignments")
    user: Mapped["User"] = relationship("User", back_populates="case_assignments")
