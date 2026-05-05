"""
app/models/user.py
──────────────────
SQLAlchemy ORM model for the `users` table.

Design decisions
────────────────
• role is a plain VARCHAR/String column, NOT a PostgreSQL ENUM type.
  Using SQLAlchemy's Enum() would try to CREATE TYPE in PG; our schema
  was created with a plain text column, so that would raise a 500 on every
  startup.  String is always compatible.

• created_at uses DateTime(timezone=True) so PostgreSQL stores TIMESTAMPTZ.
  The default is a lambda so the datetime is evaluated at INSERT time, not
  at module import time.

• The `Project` relationship is expressed as the string "Project" (lazy
  class reference) to deliberately avoid a direct `from app.models.project
  import Project` import here. That would create a circular import chain:
      database.py → user.py → project.py → database.py
  SQLAlchemy resolves string-based relationships at mapper configuration
  time, after all modules are loaded.
"""

from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Integer, String
from sqlalchemy.orm import relationship

from app.core.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)

    # ── VARCHAR role column ────────────────────────────────────────────────
    # Plain String prevents PostgreSQL ENUM type-check errors.
    # Allowed values (application-level): "user", "admin", "auditor"
    role = Column(String(50), default="user", nullable=False)

    # ── Timezone-aware timestamp ───────────────────────────────────────────
    # DateTime(timezone=True) → TIMESTAMPTZ in PostgreSQL.
    # lambda ensures the value is computed at row-insert time, not at
    # class-definition time.
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # ── Relationships ──────────────────────────────────────────────────────
    # String reference avoids the circular import:
    #   user.py ↔ project.py (both imported by models/__init__.py)
    projects = relationship(
        "Project",
        back_populates="owner",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )