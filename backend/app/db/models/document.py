from datetime import datetime, timezone
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base

if TYPE_CHECKING:
    from app.db.models.case import Case
    from app.db.models.document_version import DocumentVersion
    from app.db.models.user import User


class Document(Base):
    __tablename__ = "documents"

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    case_id: Mapped[int] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False,
    )
    document_number: Mapped[str] = mapped_column(String(100), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
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
    case: Mapped["Case"] = relationship("Case", back_populates="documents")
    created_by_user: Mapped["User"] = relationship("User", back_populates="created_documents")
    versions: Mapped[list["DocumentVersion"]] = relationship(
        "DocumentVersion",
        back_populates="document",
        cascade="all, delete-orphan",
    )
