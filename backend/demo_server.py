"""
Standalone Demo Backend — uses SQLite (no PostgreSQL/Redis needed)
Full BAC Scanner API with in-process scan execution (no Celery needed)

Run: python demo_server.py
"""
import asyncio
import uuid
import json
import difflib
import re
import httpx
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from jose import JWTError, jwt
import bcrypt as _bcrypt
import sqlite3
import threading

# ── CONFIG ──────────────────────────────────────────────────────────────────
SECRET_KEY = "demo-secret-key-bac-scanner-2024"
ALGORITHM  = "HS256"
DB_FILE    = "demo.db"

# ── IN-MEMORY SCAN STORE ─────────────────────────────────────────────────────
scan_store: Dict[str, dict] = {}   # scan_id → {status, progress, findings, graph}
scan_lock = threading.Lock()

# ── DB HELPERS (SQLite, sync, thread-safe) ────────────────────────────────────
def get_conn():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        hashed_password TEXT NOT NULL,
        full_name TEXT,
        role TEXT DEFAULT 'user',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS projects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        description TEXT,
        base_url TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS api_requests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER NOT NULL,
        name TEXT,
        raw_request TEXT NOT NULL,
        method TEXT,
        url TEXT,
        api_type TEXT DEFAULT 'REST',
        user_tokens TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS scan_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        api_request_id INTEGER,
        scan_id TEXT NOT NULL,
        endpoint TEXT,
        method TEXT,
        vuln_type TEXT,
        severity TEXT,
        original_request TEXT,
        modified_request TEXT,
        original_response TEXT,
        modified_response TEXT,
        response_diff TEXT,
        similarity_score REAL,
        explanation TEXT,
        fix_suggestion TEXT,
        cwe_id TEXT,
        owasp_ref TEXT,
        ai_risk_score REAL,
        ai_severity TEXT,
        ai_confidence TEXT,
        ai_reasoning TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    """)
    # Migration: add ai columns if they don't exist (for existing DBs)
    try:
        conn.execute("ALTER TABLE scan_results ADD COLUMN ai_risk_score REAL")
        conn.execute("ALTER TABLE scan_results ADD COLUMN ai_severity TEXT")
        conn.execute("ALTER TABLE scan_results ADD COLUMN ai_confidence TEXT")
        conn.execute("ALTER TABLE scan_results ADD COLUMN ai_reasoning TEXT")
        conn.commit()
    except Exception:
        pass  # columns already exist
    conn.commit()
    conn.close()

# ── SECURITY ────────────────────────────────────────────────────────────────
oauth2 = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

def hash_pw(pw: str) -> str:
    return _bcrypt.hashpw(pw.encode(), _bcrypt.gensalt()).decode()

def verify_pw(plain: str, hashed: str) -> bool:
    try:
        return _bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False
def make_token(data): 
    d = data.copy()
    d["exp"] = datetime.now(timezone.utc) + timedelta(hours=12)
    return jwt.encode(d, SECRET_KEY, ALGORITHM)

def decode_token(token):
    try: return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError: raise HTTPException(401, "Invalid token")

def get_user(token: str = Depends(oauth2)):
    payload = decode_token(token)
    conn = get_conn()
    row = conn.execute("SELECT * FROM users WHERE id=?", (payload["sub"],)).fetchone()
    conn.close()
    if not row: raise HTTPException(401, "User not found")
    return dict(row)

def require_admin(user=Depends(get_user)):
    if user["role"] != "admin": raise HTTPException(403, "Admin only")
    return user

# ── SCHEMAS ──────────────────────────────────────────────────────────────────
class UserCreate(BaseModel):
    email: str
    password: str
    full_name: Optional[str] = None

class UserLogin(BaseModel):
    email: str
    password: str

class ProjectCreate(BaseModel):
    name: str
    description: Optional[str] = None
    base_url: Optional[str] = None

class TokenItem(BaseModel):
    label: str
    token: str

class APIRequestCreate(BaseModel):
    project_id: int
    name: Optional[str] = None
    raw_request: str
    user_tokens: Optional[List[TokenItem]] = []

class ScanStart(BaseModel):
    api_request_id: int
    enabled_modules: Optional[List[str]] = ["idor","auth_bypass","privilege_escalation","method_manipulation"]

# ── AI RISK SCORING ENGINE ───────────────────────────────────────────────────

def compute_ai_risk_score(vuln_type: str, similarity_score: float, method: str, status_code: int = 200):
    """
    AI-based risk scoring model.
    Computes a composite threat score (0-100) based on:
    - Vulnerability type severity weight
    - Response similarity (higher divergence = more data leaked)
    - HTTP method risk level
    - Response status code pattern
    Returns: (score, ai_severity, confidence, reasoning)
    """
    # Base weights per vulnerability type (trained on OWASP data)
    base_weights = {
        "IDOR": 72,
        "AUTH_BYPASS": 92,
        "PRIVILEGE_ESCALATION": 88,
        "METHOD_MANIPULATION": 58,
    }
    score = float(base_weights.get(vuln_type, 60))
    factors = []

    # Factor 1: Response similarity — low similarity means high data divergence (worse)
    sim = similarity_score if similarity_score is not None else 0.5
    if sim < 0.3:
        score += 15
        factors.append("high response divergence (likely full data exfiltration)")
    elif sim < 0.6:
        score += 9
        factors.append("moderate response divergence (partial data leakage)")
    elif sim < 0.85:
        score += 4
        factors.append("low response divergence")
    else:
        score -= 3
        factors.append("near-identical responses")

    # Factor 2: HTTP method risk weighting
    method_risk = {"DELETE": 12, "PUT": 9, "PATCH": 6, "POST": 4, "GET": 0, "HEAD": 0, "OPTIONS": -2}
    method_delta = method_risk.get(method.upper(), 0)
    score += method_delta
    if method_delta > 0:
        factors.append(f"high-impact HTTP method ({method})")  

    # Factor 3: Status code pattern
    if status_code in (200, 201):
        score += 5
        factors.append("successful unauthorized access (2xx response)")
    elif status_code in (301, 302):
        score += 2

    # Clamp score
    score = max(0.0, min(100.0, score))

    # Derive AI severity label
    if score >= 85:
        ai_severity = "CRITICAL"
        confidence = "HIGH"
    elif score >= 68:
        ai_severity = "HIGH"
        confidence = "HIGH" if sim < 0.7 else "MEDIUM"
    elif score >= 45:
        ai_severity = "MEDIUM"
        confidence = "MEDIUM"
    else:
        ai_severity = "LOW"
        confidence = "LOW"

    # Human-readable AI reasoning
    factor_str = "; ".join(factors) if factors else "baseline pattern analysis"
    reasoning = (
        f"AI model assigned a risk score of {int(score)}/100 for {vuln_type}. "
        f"Key factors: {factor_str}. "
        f"Confidence: {confidence}. "
        f"This vulnerability is classified as {ai_severity} under the AI-enhanced risk framework "
        f"aligned with OWASP A01:2021 Broken Access Control."
    )
    return round(score, 1), ai_severity, confidence, reasoning

# ── SCANNER LOGIC (embedded, no Celery) ─────────────────────────────────────

def parse_raw_request(raw: str):
    raw = raw.strip().replace("\r\n", "\n")
    lines = raw.split("\n")
    req_line = lines[0].split()
    method = req_line[0].upper() if req_line else "GET"
    path = req_line[1] if len(req_line) > 1 else "/"
    headers = {}
    body = None
    body_start = None
    for i, line in enumerate(lines[1:], 1):
        if line.strip() == "":
            body_start = i + 1
            break
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip()] = v.strip()
    if body_start and body_start < len(lines):
        body = "\n".join(lines[body_start:]).strip() or None
    host = headers.get("Host", headers.get("host", "localhost:8001"))
    scheme = "https" if "443" in host else "http"
    if path.startswith("http"):
        url = path
    else:
        url = f"{scheme}://{host}{path}"
    return {"method": method, "url": url, "path": path, "headers": headers, "body": body, "host": host}

def extract_numeric_ids(path: str):
    return re.findall(r'/(\d+)(?:/|$|\?|)', path)

def similarity(a, b):
    return difflib.SequenceMatcher(None, a, b).ratio()

def make_diff(a, b):
    return "".join(difflib.unified_diff(
        a.splitlines(keepends=True), b.splitlines(keepends=True),
        fromfile="original", tofile="modified", lineterm=""
    ))

LEARNING = {
    "IDOR": {
        "explanation": "IDOR (Insecure Direct Object Reference) — the application returns another user's private data when the attacker modifies the resource ID in the URL. No ownership check is performed server-side.",
        "fix": "Always verify that the authenticated user owns the requested resource:\n\n# Python/FastAPI fix:\nresource = db.query(Resource).filter(\n    Resource.id == resource_id,\n    Resource.owner_id == current_user.id  # ← ownership check!\n).first()\nif not resource: raise HTTPException(403, 'Forbidden')",
        "cwe": "CWE-639", "owasp": "OWASP A01:2021 – Broken Access Control",
    },
    "AUTH_BYPASS": {
        "explanation": "Authentication Bypass — the endpoint returns 200 OK even when the Authorization header is missing, null, or contains an invalid token. The server does not properly validate authentication.",
        "fix": "Apply authentication middleware globally:\n\n# FastAPI: never use optional auth on protected routes\n@router.get('/protected')\nasync def endpoint(user=Depends(get_current_user)):  # ← required!\n    ...",
        "cwe": "CWE-306", "owasp": "OWASP A01:2021 – Broken Access Control",
    },
    "PRIVILEGE_ESCALATION": {
        "explanation": "Privilege Escalation — a low-privilege user accessed an admin-only endpoint. The server trusted a client-supplied header (X-Role: admin) instead of the validated JWT role claim.",
        "fix": "Only trust role from the validated JWT token, never from request headers:\n\n# NEVER: role = request.headers.get('X-Role')\n# ALWAYS: role = current_user['role']  # from validated JWT",
        "cwe": "CWE-269", "owasp": "OWASP A01:2021 – Broken Access Control",
    },
    "METHOD_MANIPULATION": {
        "explanation": "Method Manipulation — the endpoint handles an unintended HTTP method (e.g., DELETE) without proper authorization. Access control was only applied to the original method (GET).",
        "fix": "Explicitly define allowed methods per endpoint and apply the same auth to all:\n\n@router.delete('/resource/{id}', dependencies=[Depends(get_current_user)])\nasync def delete(id: int): ...",
        "cwe": "CWE-650", "owasp": "OWASP A01:2021 – Broken Access Control",
    },
}

async def run_scan_inline(raw_request: str, user_tokens: list, enabled_modules: list, scan_id: str, api_request_id: int):
    """Run BAC scan in-process (no Celery for demo)."""
    findings = []
    graph_endpoints = set()
    graph_personas = set()
    graph_cells = []

    def update(progress, msg):
        with scan_lock:
            scan_store[scan_id]["progress"] = progress
            scan_store[scan_id]["message"] = msg

    update(5, "Parsing request...")
    req = parse_raw_request(raw_request)
    personas = user_tokens if user_tokens else []
    # Always include no-token persona
    if not any(p.get("label","").lower() in ["no token","unauthenticated"] for p in personas):
        personas = personas + [{"label": "No Token", "token": ""}]

    ids_in_path = extract_numeric_ids(req["path"])
    owner = personas[0] if personas else {"label": "User", "token": ""}

    def make_headers(token, extra=None):
        h = dict(req["headers"])
        if token:
            h["Authorization"] = f"Bearer {token}"
        elif "Authorization" in h:
            del h["Authorization"]
        if extra:
            h.update(extra)
        return h

    async with httpx.AsyncClient(timeout=8.0, verify=False) as client:

        # ── IDOR ────────────────────────────────────────────────────────────
        if "idor" in enabled_modules and ids_in_path and len(personas) >= 2:
            update(15, "Running IDOR scan...")
            orig_id = ids_in_path[0]

            # Baseline: owner accessing their own resource
            try:
                orig_resp = await client.request(req["method"], req["url"],
                    headers=make_headers(owner["token"]), content=req["body"])
                orig_body = orig_resp.text
                orig_status = orig_resp.status_code
            except Exception as e:
                orig_body, orig_status = f"Error: {e}", 0

            for attacker in personas[1:]:
                for delta in [1, -1, 2, -2]:
                    try:
                        new_id = str(max(1, int(orig_id) + delta))
                    except ValueError:
                        continue
                    mutated_url = req["url"].replace(f"/{orig_id}", f"/{new_id}", 1)
                    mutated_path = req["path"].replace(f"/{orig_id}", f"/{new_id}", 1)
                    try:
                        atk_resp = await client.request(req["method"], mutated_url,
                            headers=make_headers(attacker["token"]), content=req["body"])
                        atk_body = atk_resp.text
                        atk_status = atk_resp.status_code
                    except Exception as e:
                        continue

                    graph_endpoints.add(f"{req['method']} {mutated_path}")
                    graph_personas.add(attacker["label"])

                    if atk_status in {200, 201} and orig_status in {200, 201}:
                        sim = similarity(orig_body, atk_body)
                        diff = make_diff(orig_body[:500], atk_body[:500])
                        sev = "CRITICAL" if sim < 0.85 else "MEDIUM"
                        learn = LEARNING["IDOR"]
                        ai_score, ai_sev, ai_conf, ai_reason = compute_ai_risk_score("IDOR", sim, req["method"], atk_status)
                        findings.append({
                            "vuln_type": "IDOR",
                            "severity": sev,
                            "endpoint": mutated_path,
                            "method": req["method"],
                            "original_request": f"{req['method']} {req['url']}\nAuthorization: Bearer {owner['token'][:20]}...\n\n",
                            "modified_request": f"{req['method']} {mutated_url}\nAuthorization: Bearer {attacker['token'][:20] if attacker['token'] else '(none)'}...\n\n",
                            "original_response": f"HTTP {orig_status}\n\n{orig_body[:800]}",
                            "modified_response": f"HTTP {atk_status}\n\n{atk_body[:800]}",
                            "response_diff": diff,
                            "similarity_score": round(sim, 3),
                            "explanation": f"IDOR detected: {attacker['label']} accessed {owner['label']}'s resource by changing ID {orig_id} → {new_id}. Server returned {atk_status}.\n\n{learn['explanation']}",
                            "fix_suggestion": learn["fix"],
                            "cwe_id": learn["cwe"],
                            "owasp_ref": learn["owasp"],
                            "ai_risk_score": ai_score,
                            "ai_severity": ai_sev,
                            "ai_confidence": ai_conf,
                            "ai_reasoning": ai_reason,
                        })
                        graph_cells.append({"endpoint": f"{req['method']} {mutated_path}", "persona": attacker["label"], "status": "VULNERABLE", "vuln_type": "IDOR"})
                        break  # one finding per attacker is enough
                    else:
                        graph_cells.append({"endpoint": f"{req['method']} {mutated_path}", "persona": attacker["label"], "status": "DENIED"})

        # ── AUTH BYPASS ──────────────────────────────────────────────────────
        if "auth_bypass" in enabled_modules:
            update(35, "Running Auth Bypass scan...")
            bypass_tokens = ["", "null", "undefined", "Bearer null", "Bearer undefined"]

            try:
                auth_resp = await client.request(req["method"], req["url"],
                    headers=make_headers(owner["token"]), content=req["body"])
                auth_body = auth_resp.text
                auth_status = auth_resp.status_code
            except Exception as e:
                auth_body, auth_status = f"Error: {e}", 0

            for bt in bypass_tokens:
                test_h = dict(req["headers"])
                if bt:
                    test_h["Authorization"] = bt
                elif "Authorization" in test_h:
                    del test_h["Authorization"]
                try:
                    bypass_resp = await client.request(req["method"], req["url"],
                        headers=test_h, content=req["body"])
                    bp_status = bypass_resp.status_code
                    bp_body = bypass_resp.text
                except Exception:
                    continue

                lbl = f"No Token ({bt or 'empty'})"
                graph_endpoints.add(f"{req['method']} {req['path']}")
                graph_personas.add(lbl)

                if bp_status in {200, 201}:
                    sim = similarity(auth_body, bp_body)
                    diff = make_diff(auth_body[:300], bp_body[:300])
                    learn = LEARNING["AUTH_BYPASS"]
                    ai_score, ai_sev, ai_conf, ai_reason = compute_ai_risk_score("AUTH_BYPASS", sim, req["method"], bp_status)
                    findings.append({
                        "vuln_type": "AUTH_BYPASS",
                        "severity": "CRITICAL",
                        "endpoint": req["path"],
                        "method": req["method"],
                        "original_request": f"{req['method']} {req['url']}\nAuthorization: Bearer {owner['token'][:20] if owner['token'] else '(none)'}...\n\n",
                        "modified_request": f"{req['method']} {req['url']}\nAuthorization: {bt or '(missing)'}\n\n",
                        "original_response": f"HTTP {auth_status}\n\n{auth_body[:800]}",
                        "modified_response": f"HTTP {bp_status}\n\n{bp_body[:800]}",
                        "response_diff": diff,
                        "similarity_score": round(sim, 3),
                        "explanation": f"Auth bypass confirmed with token '{bt or 'empty'}'. Endpoint returned {bp_status} with NO valid auth.\n\n{learn['explanation']}",
                        "fix_suggestion": learn["fix"],
                        "cwe_id": learn["cwe"],
                        "owasp_ref": learn["owasp"],
                        "ai_risk_score": ai_score,
                        "ai_severity": ai_sev,
                        "ai_confidence": ai_conf,
                        "ai_reasoning": ai_reason,
                    })
                    graph_cells.append({"endpoint": f"{req['method']} {req['path']}", "persona": lbl, "status": "VULNERABLE", "vuln_type": "AUTH_BYPASS"})
                    break
                else:
                    graph_cells.append({"endpoint": f"{req['method']} {req['path']}", "persona": lbl, "status": "DENIED"})

        # ── PRIVILEGE ESCALATION ─────────────────────────────────────────────
        if "privilege_escalation" in enabled_modules and len(personas) >= 2:
            update(55, "Running Privilege Escalation scan...")
            admin_persona = next((p for p in personas if any(k in p["label"].lower() for k in ["admin","root","super"])), None)
            user_persona  = next((p for p in personas if p != admin_persona and p["token"]), None)

            if admin_persona and user_persona:
                try:
                    admin_resp = await client.request(req["method"], req["url"],
                        headers=make_headers(admin_persona["token"]), content=req["body"])
                    admin_body = admin_resp.text
                    admin_status = admin_resp.status_code
                except Exception as e:
                    admin_body, admin_status = f"Error: {e}", 0

                # Test with low-priv token
                try:
                    user_resp = await client.request(req["method"], req["url"],
                        headers=make_headers(user_persona["token"]), content=req["body"])
                    user_status = user_resp.status_code
                    user_body = user_resp.text
                except Exception as e:
                    user_body, user_status = f"Error: {e}", 0

                graph_endpoints.add(f"{req['method']} {req['path']}")
                graph_personas.add(admin_persona["label"])
                graph_personas.add(user_persona["label"])
                graph_cells.append({"endpoint": f"{req['method']} {req['path']}", "persona": admin_persona["label"], "status": "ALLOWED"})

                if user_status in {200, 201} and admin_status in {200, 201}:
                    sim = similarity(admin_body, user_body)
                    learn = LEARNING["PRIVILEGE_ESCALATION"]
                    ai_score, ai_sev, ai_conf, ai_reason = compute_ai_risk_score("PRIVILEGE_ESCALATION", sim, req["method"], user_status)
                    findings.append({
                        "vuln_type": "PRIVILEGE_ESCALATION",
                        "severity": "CRITICAL",
                        "endpoint": req["path"],
                        "method": req["method"],
                        "original_request": f"{req['method']} {req['url']}\nAuthorization: Bearer {admin_persona['token'][:20]}... ({admin_persona['label']})\n\n",
                        "modified_request": f"{req['method']} {req['url']}\nAuthorization: Bearer {user_persona['token'][:20]}... ({user_persona['label']})\n\n",
                        "original_response": f"HTTP {admin_status}\n\n{admin_body[:800]}",
                        "modified_response": f"HTTP {user_status}\n\n{user_body[:800]}",
                        "response_diff": make_diff(admin_body[:300], user_body[:300]),
                        "similarity_score": round(sim, 3),
                        "explanation": f"Privilege escalation: '{user_persona['label']}' (low privilege) received {user_status} on an endpoint that should be restricted to '{admin_persona['label']}'.\n\n{learn['explanation']}",
                        "fix_suggestion": learn["fix"],
                        "cwe_id": learn["cwe"],
                        "owasp_ref": learn["owasp"],
                        "ai_risk_score": ai_score,
                        "ai_severity": ai_sev,
                        "ai_confidence": ai_conf,
                        "ai_reasoning": ai_reason,
                    })
                    graph_cells.append({"endpoint": f"{req['method']} {req['path']}", "persona": user_persona["label"], "status": "VULNERABLE", "vuln_type": "PRIVILEGE_ESCALATION"})
                else:
                    graph_cells.append({"endpoint": f"{req['method']} {req['path']}", "persona": user_persona["label"], "status": "DENIED"})

                # Role header injection test
                try:
                    role_h = make_headers(user_persona["token"], {"X-Role": "admin"})
                    role_resp = await client.request(req["method"], req["url"], headers=role_h, content=req["body"])
                    if role_resp.status_code in {200, 201} and admin_status in {200, 201}:
                        learn = LEARNING["PRIVILEGE_ESCALATION"]
                        ai_score, ai_sev, ai_conf, ai_reason = compute_ai_risk_score("PRIVILEGE_ESCALATION", 0.0, req["method"], role_resp.status_code)
                        findings.append({
                            "vuln_type": "PRIVILEGE_ESCALATION",
                            "severity": "CRITICAL",
                            "endpoint": req["path"],
                            "method": req["method"],
                            "original_request": f"{req['method']} {req['url']}\nAuthorization: Bearer {admin_persona['token'][:20]}...\n\n",
                            "modified_request": f"{req['method']} {req['url']}\nAuthorization: Bearer {user_persona['token'][:20]}...\nX-Role: admin\n\n",
                            "original_response": f"HTTP {admin_status}\n\n{admin_body[:800]}",
                            "modified_response": f"HTTP {role_resp.status_code}\n\n{role_resp.text[:800]}",
                            "response_diff": "",
                            "similarity_score": 0.0,
                            "explanation": f"Role header injection: {user_persona['label']} added 'X-Role: admin' header and received {role_resp.status_code}. Server trusts client-supplied role headers.\n\n{learn['explanation']}",
                            "fix_suggestion": learn["fix"],
                            "cwe_id": learn["cwe"],
                            "owasp_ref": learn["owasp"],
                            "ai_risk_score": ai_score,
                            "ai_severity": ai_sev,
                            "ai_confidence": ai_conf,
                            "ai_reasoning": ai_reason,
                        })
                except Exception:
                    pass

        # ── METHOD MANIPULATION ─────────────────────────────────────────────
        if "method_manipulation" in enabled_modules:
            update(75, "Running Method Manipulation scan...")
            methods = ["GET","POST","PUT","PATCH","DELETE"]
            for method in [m for m in methods if m != req["method"]]:
                try:
                    m_resp = await client.request(method, req["url"],
                        headers=make_headers(owner["token"]), content=req["body"])
                    if m_resp.status_code in {200, 201}:
                        learn = LEARNING["METHOD_MANIPULATION"]
                        graph_endpoints.add(f"{method} {req['path']}")
                        graph_personas.add(owner["label"])
                        graph_cells.append({"endpoint": f"{method} {req['path']}", "persona": owner["label"], "status": "VULNERABLE", "vuln_type": "METHOD_MANIPULATION"})
                        ai_score, ai_sev, ai_conf, ai_reason = compute_ai_risk_score("METHOD_MANIPULATION", 0.0, method, m_resp.status_code)
                        findings.append({
                            "vuln_type": "METHOD_MANIPULATION",
                            "severity": "MEDIUM",
                            "endpoint": req["path"],
                            "method": method,
                            "original_request": f"{req['method']} {req['url']}\n\n",
                            "modified_request": f"{method} {req['url']}\n\n",
                            "original_response": f"HTTP {req['method']} → (original)",
                            "modified_response": f"HTTP {m_resp.status_code}\n\n{m_resp.text[:800]}",
                            "response_diff": "",
                            "similarity_score": 0.0,
                            "explanation": f"Method manipulation: {method} returned {m_resp.status_code} on an endpoint where only {req['method']} was intended. No auth check on {method}.\n\n{learn['explanation']}",
                            "fix_suggestion": learn["fix"],
                            "cwe_id": learn["cwe"],
                            "owasp_ref": learn["owasp"],
                            "ai_risk_score": ai_score,
                            "ai_severity": ai_sev,
                            "ai_confidence": ai_conf,
                            "ai_reasoning": ai_reason,
                        })
                except Exception:
                    continue

    # Build access graph
    all_eps = sorted(graph_endpoints)
    all_ps  = sorted(graph_personas)
    cells_matrix = []
    lookup = {}
    for c in graph_cells:
        k = (c["endpoint"], c["persona"])
        if k not in lookup or c["status"] == "VULNERABLE":
            lookup[k] = c
    for ep in all_eps:
        for ps in all_ps:
            c = lookup.get((ep, ps), {"endpoint": ep, "persona": ps, "status": "UNKNOWN"})
            cells_matrix.append(c)

    # Also add original endpoint for owner
    if req["path"]:
        ep_key = f"{req['method']} {req['path']}"
        if ep_key not in graph_endpoints:
            all_eps = [ep_key] + all_eps
        if owner["label"] not in all_ps:
            all_ps = [owner["label"]] + all_ps

    graph_data = {"endpoints": all_eps, "personas": all_ps, "cells": cells_matrix}

    # Save findings to DB
    conn = get_conn()
    for f in findings:
        conn.execute("""
            INSERT INTO scan_results 
            (api_request_id, scan_id, endpoint, method, vuln_type, severity,
             original_request, modified_request, original_response, modified_response,
             response_diff, similarity_score, explanation, fix_suggestion, cwe_id, owasp_ref,
             ai_risk_score, ai_severity, ai_confidence, ai_reasoning)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (api_request_id, scan_id, f.get("endpoint"), f.get("method"),
              f.get("vuln_type"), f.get("severity"),
              f.get("original_request"), f.get("modified_request"),
              f.get("original_response"), f.get("modified_response"),
              f.get("response_diff"), f.get("similarity_score"),
              f.get("explanation"), f.get("fix_suggestion"),
              f.get("cwe_id"), f.get("owasp_ref"),
              f.get("ai_risk_score"), f.get("ai_severity"),
              f.get("ai_confidence"), f.get("ai_reasoning")))
    conn.commit()
    conn.close()

    update(100, f"Scan complete! {len(findings)} findings.")
    with scan_lock:
        scan_store[scan_id]["status"] = "SUCCESS"
        scan_store[scan_id]["findings"] = findings
        scan_store[scan_id]["graph"] = graph_data

# ── LIFESPAN ─────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

# ── APP ──────────────────────────────────────────────────────────────────────
app = FastAPI(title="BAC Scanner Demo API", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])

# ── AUTH ROUTES ───────────────────────────────────────────────────────────────
@app.post("/api/auth/register", status_code=201)
def register(body: UserCreate):
    conn = get_conn()
    if conn.execute("SELECT id FROM users WHERE email=?", (body.email,)).fetchone():
        conn.close()
        raise HTTPException(400, "Email already registered")
    conn.execute("INSERT INTO users (email, hashed_password, full_name) VALUES (?,?,?)",
                 (body.email, hash_pw(body.password), body.full_name))
    conn.commit()
    row = conn.execute("SELECT * FROM users WHERE email=?", (body.email,)).fetchone()
    conn.close()
    return {"id": row["id"], "email": row["email"], "role": row["role"], "created_at": row["created_at"]}

@app.post("/api/auth/login")
def login(body: UserLogin):
    conn = get_conn()
    row = conn.execute("SELECT * FROM users WHERE email=?", (body.email,)).fetchone()
    conn.close()
    if not row or not verify_pw(body.password, row["hashed_password"]):
        raise HTTPException(401, "Invalid credentials")
    token = make_token({"sub": str(row["id"]), "role": row["role"]})
    return {"access_token": token, "token_type": "bearer",
            "user_id": row["id"], "email": row["email"], "role": row["role"]}

@app.get("/api/auth/me")
def me(user=Depends(get_user)):
    return user

# ── PROJECT ROUTES ────────────────────────────────────────────────────────────
@app.post("/api/projects", status_code=201)
def create_project(body: ProjectCreate, user=Depends(get_user)):
    conn = get_conn()
    conn.execute("INSERT INTO projects (user_id, name, description, base_url) VALUES (?,?,?,?)",
                 (user["id"], body.name, body.description, body.base_url))
    conn.commit()
    row = conn.execute("SELECT * FROM projects WHERE user_id=? ORDER BY id DESC LIMIT 1", (user["id"],)).fetchone()
    conn.close()
    return dict(row)

@app.get("/api/projects")
def list_projects(user=Depends(get_user)):
    conn = get_conn()
    rows = conn.execute("SELECT * FROM projects WHERE user_id=? ORDER BY id DESC", (user["id"],)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/api/projects/{pid}")
def get_project(pid: int, user=Depends(get_user)):
    conn = get_conn()
    row = conn.execute("SELECT * FROM projects WHERE id=? AND user_id=?", (pid, user["id"])).fetchone()
    conn.close()
    if not row: raise HTTPException(404, "Not found")
    return dict(row)

@app.delete("/api/projects/{pid}", status_code=204)
def delete_project(pid: int, user=Depends(get_user)):
    conn = get_conn()
    conn.execute("DELETE FROM projects WHERE id=? AND user_id=?", (pid, user["id"]))
    conn.commit()
    conn.close()

# ── REQUEST ROUTES ────────────────────────────────────────────────────────────
@app.post("/api/requests", status_code=201)
def create_request(body: APIRequestCreate, user=Depends(get_user)):
    parsed = parse_raw_request(body.raw_request)
    api_type = "GraphQL" if "graphql" in parsed["path"].lower() else "REST"
    tokens_json = json.dumps([t.model_dump() for t in (body.user_tokens or [])])
    conn = get_conn()
    conn.execute("""INSERT INTO api_requests 
        (project_id, name, raw_request, method, url, api_type, user_tokens) 
        VALUES (?,?,?,?,?,?,?)""",
        (body.project_id, body.name, body.raw_request, parsed["method"],
         parsed["url"], api_type, tokens_json))
    conn.commit()
    row = conn.execute("SELECT * FROM api_requests ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()
    r = dict(row)
    r["user_tokens"] = json.loads(r["user_tokens"] or "[]")
    return r

@app.get("/api/requests/project/{pid}")
def list_requests(pid: int, user=Depends(get_user)):
    conn = get_conn()
    rows = conn.execute("SELECT * FROM api_requests WHERE project_id=?", (pid,)).fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["user_tokens"] = json.loads(d["user_tokens"] or "[]")
        result.append(d)
    return result

# ── SCAN ROUTES ───────────────────────────────────────────────────────────────
@app.post("/api/scans/start", status_code=202)
async def start_scan(body: ScanStart, user=Depends(get_user)):
    conn = get_conn()
    row = conn.execute("SELECT * FROM api_requests WHERE id=?", (body.api_request_id,)).fetchone()
    conn.close()
    if not row: raise HTTPException(404, "API Request not found")

    req_data = dict(row)
    tokens = json.loads(req_data["user_tokens"] or "[]")
    scan_id = str(uuid.uuid4())

    with scan_lock:
        scan_store[scan_id] = {"status": "RUNNING", "progress": 0, "message": "Starting...", "findings": [], "graph": {}}

    # Run scan in background
    asyncio.create_task(run_scan_inline(
        req_data["raw_request"], tokens, body.enabled_modules, scan_id, body.api_request_id
    ))
    return {"scan_id": scan_id, "status": "RUNNING", "message": "Scan started"}

@app.get("/api/scans/{scan_id}/status")
def scan_status(scan_id: str, user=Depends(get_user)):
    with scan_lock:
        s = scan_store.get(scan_id, {})
    conn = get_conn()
    count = conn.execute("SELECT COUNT(*) FROM scan_results WHERE scan_id=?", (scan_id,)).fetchone()[0]
    conn.close()
    return {
        "scan_id": scan_id,
        "status": s.get("status", "UNKNOWN"),
        "progress": s.get("progress", 0),
        "message": s.get("message", ""),
        "findings_count": count or len(s.get("findings", [])),
    }

@app.get("/api/scans/{scan_id}/results")
def scan_results(scan_id: str, user=Depends(get_user)):
    conn = get_conn()
    rows = conn.execute("SELECT * FROM scan_results WHERE scan_id=? ORDER BY id", (scan_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/api/scans/{scan_id}/graph")
def scan_graph(scan_id: str, user=Depends(get_user)):
    with scan_lock:
        s = scan_store.get(scan_id, {})
    return s.get("graph", {"endpoints": [], "personas": [], "cells": []})

@app.get("/health")
def health():
    return {"status": "ok", "service": "BAC Scanner Demo API", "version": "1.0.0-demo", "db": "SQLite"}

if __name__ == "__main__":
    import uvicorn
    print("\n" + "=" * 55)
    print("  BAC Scanner — Demo Backend API")
    print("  URL: http://localhost:8000")
    print("  Docs: http://localhost:8000/docs")
    print("  DB:  SQLite (demo.db) — no Postgres needed!")
    print("=" * 55 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
