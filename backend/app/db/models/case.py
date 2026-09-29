from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.db.models.case_assignment import CaseAssignment
    from app.db.models.custody_event import CustodyEvent
    from app.db.models.document import Document
    from app.db.models.integrity_alert import IntegrityAlert


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    case_number: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="OPEN", nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    assignments: Mapped[list["CaseAssignment"]] = relationship(
        "CaseAssignment",
        back_populates="case",
        cascade="all, delete-orphan",
    )
    documents: Mapped[list["Document"]] = relationship(
        "Document",
        back_populates="case",
        cascade="all, delete-orphan",
    )
    custody_events: Mapped[list["CustodyEvent"]] = relationship(
        "CustodyEvent",
        back_populates="case",
        cascade="all, delete-orphan",
    )
    integrity_alerts: Mapped[list["IntegrityAlert"]] = relationship(
        "IntegrityAlert",
        back_populates="case",
        cascade="all, delete-orphan",
    )
