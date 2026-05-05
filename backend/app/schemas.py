from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime



class UserCreate(BaseModel):
    email: EmailStr
    password: str
    full_name: Optional[str] = None


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user_id: int
    email: str
    role: str


class UserOut(BaseModel):
    id: int
    email: str
    full_name: Optional[str]
    role: str
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ---------- Project ----------

class ProjectCreate(BaseModel):
    name: str
    description: Optional[str] = None
    base_url: Optional[str] = None


class ProjectOut(BaseModel):
    id: int
    user_id: int
    name: str
    description: Optional[str]
    base_url: Optional[str]
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ---------- APIRequest ----------

class UserToken(BaseModel):
    label: str        # e.g. "Admin", "User Alice", "No Token"
    token: str        # Bearer token or empty string


class APIRequestCreate(BaseModel):
    project_id: int
    name: Optional[str] = None
    raw_request: str
    user_tokens: Optional[list[UserToken]] = []


class APIRequestOut(BaseModel):
    id: int
    project_id: int
    name: Optional[str]
    raw_request: str
    method: Optional[str]
    url: Optional[str]
    api_type: str
    user_tokens: Optional[list]
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


# ---------- Scan ----------

class ScanStartRequest(BaseModel):
    api_request_id: int
    enabled_modules: Optional[list[str]] = [
        "idor", "auth_bypass", "privilege_escalation",
        "method_manipulation", "endpoint_discovery"
    ]


class ScanResultOut(BaseModel):
    id: int
    scan_id: str
    endpoint: Optional[str]
    method: Optional[str]
    vuln_type: Optional[str]
    severity: Optional[str]
    original_request: Optional[str]
    modified_request: Optional[str]
    original_response: Optional[str]
    modified_response: Optional[str]
    response_diff: Optional[str]
    similarity_score: Optional[float]
    explanation: Optional[str] = None
    fix_suggestion: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_ref: Optional[str] = None
    ai_risk_score: Optional[float] = None
    ai_severity: Optional[str] = None
    ai_confidence: Optional[str] = None
    ai_reasoning: Optional[str] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ScanStatusResponse(BaseModel):
    scan_id: str
    status: str
    progress: int           # 0-100
    findings_count: int
    message: str
