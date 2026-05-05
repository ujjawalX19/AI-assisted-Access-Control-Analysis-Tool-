"""
app/models/project.py
─────────────────────
SQLAlchemy ORM model for the `projects` table.

Notes
─────
• created_at uses DateTime(timezone=True) to match the `users` table.
  Mixing timezone-aware and timezone-naive columns causes silent comparison
  bugs and can raise errors in newer versions of asyncpg/PostgreSQL drivers.

• The `owner` back-reference resolves to the User class via SQLAlchemy's
  string-based lazy resolution — no `from app.models.user import User`
  needed here, which breaks the circular import chain.
"""

from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.core.database import Base


class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True)

    # FK to users.id — CASCADE on delete so orphan projects are cleaned up
    user_id = Column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    base_url = Column(String(500), nullable=True)

    # ── Timezone-aware timestamp (matches users.created_at) ────────────────
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # ── Relationships ──────────────────────────────────────────────────────
    # String references resolve after all models are loaded — avoids circular imports
    owner = relationship("User", back_populates="projects")
    api_requests = relationship(
        "APIRequest",
        back_populates="project",
        cascade="all, delete",
        passive_deletes=True,
    )
