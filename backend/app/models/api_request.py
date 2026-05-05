from app.core.database import Base
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, JSON
from sqlalchemy.orm import relationship
from datetime import datetime, timezone


class APIRequest(Base):
    __tablename__ = "api_requests"

    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String(255), nullable=True)
    raw_request = Column(Text, nullable=False)         # Raw HTTP request string (Burp style)
    method = Column(String(20), nullable=True)
    url = Column(String(1000), nullable=True)
    headers = Column(JSON, nullable=True)              # Parsed headers dict
    body = Column(Text, nullable=True)
    api_type = Column(String(20), default="REST")      # REST or GraphQL
    user_tokens = Column(JSON, nullable=True)          # List of {label, token} objects
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    project = relationship("Project", back_populates="api_requests")
    scan_results = relationship("ScanResult", back_populates="api_request", cascade="all, delete")
