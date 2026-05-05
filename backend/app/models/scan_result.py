"""
app/models/scan_result.py
─────────────────────────
SQLAlchemy ORM model for scan findings.

Enum columns — why we use String instead of SQLAlchemy's Enum()
───────────────────────────────────────────────────────────────
SQLAlchemy's `Enum(PythonEnum)` tries to CREATE TYPE in PostgreSQL.
If the database was created without those custom types (e.g., first run,
or after `drop table` without `drop type`) the startup will fail with:

    sqlalchemy.exc.ProgrammingError: (asyncpg.exceptions.DuplicateObjectError)
    type "scanstatus" already exists

Using `String` with `Enum(PythonEnum, values_callable=...)` or simply
plain `String` avoids all of that.  The Python-side enums (ScanStatus,
VulnType, Severity) are still used as value constants throughout the
codebase — they just aren't embedded into the PG schema.
"""

import enum
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship

from app.core.database import Base


# ── Application-level enums (used as value constants, NOT PG types) ──────────

class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnType(str, enum.Enum):
    IDOR = "IDOR"
    AUTH_BYPASS = "AUTH_BYPASS"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    METHOD_MANIPULATION = "METHOD_MANIPULATION"
    ENDPOINT_DISCOVERY = "ENDPOINT_DISCOVERY"
    GRAPHQL_INTROSPECTION = "GRAPHQL_INTROSPECTION"
    INFO = "INFO"


class ScanStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    api_request_id = Column(
        Integer,
        ForeignKey("api_requests.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    scan_id = Column(String(64), nullable=False, index=True)  # Celery task UUID

    # ── Plain String columns — no PG ENUM types created ───────────────────
    # Values are validated at the application layer using the Python enums above.
    status = Column(String(20), default=ScanStatus.PENDING.value, nullable=False)

    # Finding details — nullable because placeholder rows have no finding data
    endpoint = Column(String(1000), nullable=True)
    method = Column(String(20), nullable=True)
    vuln_type = Column(String(50), nullable=True)    # VulnType enum values
    severity = Column(String(20), nullable=True)     # Severity enum values

    # ── Diff data ─────────────────────────────────────────────────────────
    original_request = Column(Text, nullable=True)
    modified_request = Column(Text, nullable=True)
    original_response = Column(Text, nullable=True)
    modified_response = Column(Text, nullable=True)
    response_diff = Column(Text, nullable=True)
    similarity_score = Column(Float, nullable=True)

    # ── Learning-mode fields ───────────────────────────────────────────────
    explanation = Column(Text, nullable=True)
    fix_suggestion = Column(Text, nullable=True)
    cwe_id = Column(String(50), nullable=True)
    owasp_ref = Column(String(100), nullable=True)

    # ── AI Intelligence fields ─────────────────────────────────────────────
    ai_risk_score = Column(Float, nullable=True)
    ai_severity = Column(String(20), nullable=True)
    ai_confidence = Column(String(20), nullable=True)
    ai_reasoning = Column(Text, nullable=True)

    # ── Timezone-aware timestamp ───────────────────────────────────────────
    created_at = Column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    api_request = relationship("APIRequest", back_populates="scan_results")
