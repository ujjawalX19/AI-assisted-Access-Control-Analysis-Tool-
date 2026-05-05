"""
Learning Mode — maps vulnerability types to explanations, fix suggestions,
CWE IDs, and OWASP references.
"""
from typing import Optional

LEARNING_DB = {
    "IDOR": {
        "title": "Insecure Direct Object Reference (IDOR)",
        "explanation": (
            "IDOR occurs when an application uses user-supplied input to access objects "
            "directly without proper authorization checks. An attacker can manipulate "
            "resource identifiers (IDs, UUIDs) in requests to access data belonging to "
            "other users — bypassing the intended access control."
        ),
        "example": (
            "GET /api/users/42/profile → attacker changes 42 to 43 and gets another user's profile."
        ),
        "fix": (
            "1. Never rely on user-supplied IDs alone for access control.\n"
            "2. Always verify that the authenticated user owns the requested resource.\n"
            "3. Use indirect object references (e.g., map internal IDs to session-specific tokens).\n"
            "4. Implement server-side authorization checks on every request.\n\n"
            "Code fix example (Python/FastAPI):\n"
            "```python\n"
            "# BAD: directly uses user-supplied ID\n"
            "resource = db.get(Resource, resource_id)\n\n"
            "# GOOD: ensures ownership\n"
            "resource = db.query(Resource).filter(\n"
            "    Resource.id == resource_id,\n"
            "    Resource.owner_id == current_user.id  # ownership check!\n"
            ").first()\n"
            "if not resource:\n"
            "    raise HTTPException(status_code=403, detail='Forbidden')\n"
            "```"
        ),
        "cwe_id": "CWE-639",
        "owasp_ref": "OWASP A01:2021 – Broken Access Control",
        "severity_default": "CRITICAL",
    },
    "AUTH_BYPASS": {
        "title": "Authentication Bypass",
        "explanation": (
            "Authentication bypass occurs when an endpoint that should require a valid "
            "authentication token can be accessed without one (or with a manipulated token). "
            "This allows unauthenticated attackers to access protected resources."
        ),
        "example": (
            "GET /api/admin/users — returns 200 even when `Authorization` header is omitted."
        ),
        "fix": (
            "1. Apply authentication middleware globally — never rely on route-level opt-in.\n"
            "2. Validate JWT signature, expiry, and claims on every protected route.\n"
            "3. Return 401 for missing tokens, 403 for insufficient permissions.\n\n"
            "Code fix example:\n"
            "```python\n"
            "# Apply globally in FastAPI\n"
            "app.add_middleware(AuthMiddleware)\n\n"
            "# Or use dependency injection on every route:\n"
            "@router.get('/protected')\n"
            "async def protected(user=Depends(get_current_user)):\n"
            "    ...\n"
            "```"
        ),
        "cwe_id": "CWE-306",
        "owasp_ref": "OWASP A01:2021 – Broken Access Control",
        "severity_default": "CRITICAL",
    },
    "PRIVILEGE_ESCALATION": {
        "title": "Privilege Escalation / Broken Function-Level Authorization",
        "explanation": (
            "Privilege escalation happens when a lower-privileged user (e.g., regular user) "
            "can access endpoints or perform actions that should be restricted to higher-privileged "
            "roles (e.g., admin). This is often caused by missing role checks on sensitive endpoints."
        ),
        "example": (
            "POST /api/admin/users/delete — a normal user token returns 200 and deletes another user."
        ),
        "fix": (
            "1. Implement role-based access control (RBAC) checks at the function/route level.\n"
            "2. Maintain a centralized authorization policy — not scattered checks.\n"
            "3. Test every admin endpoint with non-admin tokens as part of CI.\n\n"
            "Code fix example:\n"
            "```python\n"
            "@router.delete('/admin/users/{user_id}')\n"
            "async def delete_user(\n"
            "    user_id: int,\n"
            "    current_user=Depends(require_admin)  # enforces admin role\n"
            "):\n"
            "    ...\n"
            "```"
        ),
        "cwe_id": "CWE-269",
        "owasp_ref": "OWASP A01:2021 – Broken Access Control",
        "severity_default": "CRITICAL",
    },
    "METHOD_MANIPULATION": {
        "title": "HTTP Method Manipulation",
        "explanation": (
            "Some APIs implement access control only for specific HTTP methods but allow "
            "unintended methods (GET, PUT, DELETE, PATCH) on the same endpoint. An attacker "
            "can bypass restrictions by switching to an allowed but unguarded method."
        ),
        "example": (
            "GET /api/resource/1 is public, but DELETE /api/resource/1 is also allowed without auth."
        ),
        "fix": (
            "1. Explicitly restrict allowed HTTP methods per endpoint.\n"
            "2. Return 405 Method Not Allowed for unintended methods.\n"
            "3. Apply the same authorization checks to ALL methods on an endpoint.\n\n"
            "Code fix:\n"
            "```python\n"
            "# Explicitly define only the methods you support\n"
            "@router.get('/resource/{id}')    # only GET\n"
            "# NOT: @router.api_route('/resource/{id}', methods=['GET', 'DELETE'])\n"
            "```"
        ),
        "cwe_id": "CWE-650",
        "owasp_ref": "OWASP A01:2021 – Broken Access Control",
        "severity_default": "MEDIUM",
    },
    "ENDPOINT_DISCOVERY": {
        "title": "Unprotected Endpoint Discovery",
        "explanation": (
            "Sensitive endpoints may exist but not be documented or linked in the UI. "
            "Attackers can discover these using common paths, API versioning patterns, "
            "or fuzzing — and may find they are unprotected."
        ),
        "example": (
            "/api/v2/admin, /api/internal/debug, /api/users/export — found by guessing and returned 200."
        ),
        "fix": (
            "1. Protect ALL endpoints with authentication by default.\n"
            "2. Disable debug/internal endpoints in production.\n"
            "3. Use an API gateway to enforce access policies.\n"
            "4. Implement proper 404 responses for non-existent paths (not 403 — don't reveal existence)."
        ),
        "cwe_id": "CWE-200",
        "owasp_ref": "OWASP A01:2021 – Broken Access Control",
        "severity_default": "MEDIUM",
    },
    "GRAPHQL_INTROSPECTION": {
        "title": "GraphQL Introspection Enabled in Production",
        "explanation": (
            "GraphQL introspection allows querying the full schema of the API — including "
            "all types, queries, and mutations. In production, this can expose internal "
            "API structure to attackers, aiding reconnaissance."
        ),
        "fix": (
            "Disable introspection in production:\n"
            "```python\n"
            "# Strawberry GraphQL\n"
            "schema = strawberry.Schema(query=Query, introspection=False)\n"
            "```"
        ),
        "cwe_id": "CWE-200",
        "owasp_ref": "OWASP A01:2021 – Broken Access Control",
        "severity_default": "MEDIUM",
    },
}


def get_learning(vuln_type: str) -> dict:
    """Return the full learning entry for a vulnerability type."""
    return LEARNING_DB.get(vuln_type, {
        "title": vuln_type,
        "explanation": "No detailed explanation available.",
        "fix": "Review your access control implementation.",
        "cwe_id": "CWE-284",
        "owasp_ref": "OWASP A01:2021 – Broken Access Control",
        "severity_default": "MEDIUM",
    })
