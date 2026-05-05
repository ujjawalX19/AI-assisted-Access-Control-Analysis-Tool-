"""
Auth Bypass Attack Module — tests endpoints without authentication tokens.
"""
import httpx
from typing import List
from app.scanner.request_parser import ParsedRequest, inject_token
from app.scanner.response_analyzer import analyze_auth_bypass
from app.scanner.token_manager import TokenManager
from app.scanner.learning_mode import get_learning
from app.scanner.access_graph import AccessGraph

# Common auth bypass strings to test
BYPASS_TOKENS = [
    "",              # No token
    "null",          # Literal "null"
    "undefined",     # Common JS leak
    "Bearer ",       # Empty bearer
    "Bearer null",
    "Bearer undefined",
    "Bearer 0",
]

BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Original-URL": "/"},
    {"X-Rewrite-URL": "/"},
]


async def run_auth_bypass_scan(
    request: ParsedRequest,
    token_manager: TokenManager,
    access_graph: AccessGraph,
    timeout: float = 10.0,
) -> List[dict]:
    findings = []
    owner = token_manager.get_all()[0] if token_manager.get_all() else None
    if not owner:
        return findings

    async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
        # Get baseline with valid token
        auth_req = inject_token(request, owner.token)
        try:
            auth_resp = await client.request(
                method=auth_req.method, url=auth_req.url,
                headers=auth_req.headers, content=auth_req.body,
            )
            auth_body = auth_resp.text
            auth_status = auth_resp.status_code
        except httpx.RequestError as e:
            return [{"error": str(e), "module": "auth_bypass"}]

        # Test with no token / invalid tokens
        for bypass_token in BYPASS_TOKENS:
            test_headers = dict(request.headers)
            if bypass_token:
                test_headers["Authorization"] = bypass_token
            elif "Authorization" in test_headers:
                del test_headers["Authorization"]

            try:
                bypass_resp = await client.request(
                    method=request.method, url=request.url,
                    headers=test_headers, content=request.body,
                )
                bypass_status = bypass_resp.status_code
                bypass_body = bypass_resp.text
            except httpx.RequestError:
                continue

            result = analyze_auth_bypass(auth_status, auth_body, bypass_status, bypass_body)

            persona_label = f"No Token ({bypass_token or 'empty'})"
            access_graph.add_edge(
                endpoint=request.path, method=request.method, persona=persona_label,
                status="VULNERABLE" if result.is_vulnerable else "DENIED",
                vuln_type="AUTH_BYPASS" if result.is_vulnerable else None,
            )

            if result.is_vulnerable:
                learning = get_learning("AUTH_BYPASS")
                findings.append({
                    "vuln_type": "AUTH_BYPASS",
                    "severity": result.severity,
                    "endpoint": request.path,
                    "method": request.method,
                    "original_request": auth_req.to_raw(),
                    "modified_request": f"{request.method} {request.url}\nAuthorization: {bypass_token or '(none)'}\n\n{request.body or ''}",
                    "original_response": f"HTTP {auth_status}\n\n{auth_body[:2000]}",
                    "modified_response": f"HTTP {bypass_status}\n\n{bypass_body[:2000]}",
                    "response_diff": result.response_diff,
                    "similarity_score": result.similarity_score,
                    "explanation": f"{result.reason}\n\nTested bypass token: '{bypass_token}'\n\n{learning['explanation']}",
                    "fix_suggestion": learning["fix"],
                    "cwe_id": learning["cwe_id"],
                    "owasp_ref": learning["owasp_ref"],
                })
                break  # One confirmed bypass is enough

        # Test header injection bypasses
        for bypass_headers in BYPASS_HEADERS:
            test_headers = dict(request.headers)
            if owner.token:
                test_headers.pop("Authorization", None)
            test_headers.update(bypass_headers)

            try:
                bypass_resp = await client.request(
                    method=request.method, url=request.url,
                    headers=test_headers, content=request.body,
                )
                if bypass_resp.status_code in {200, 201}:
                    learning = get_learning("AUTH_BYPASS")
                    findings.append({
                        "vuln_type": "AUTH_BYPASS",
                        "severity": "HIGH",
                        "endpoint": request.path,
                        "method": request.method,
                        "original_request": auth_req.to_raw(),
                        "modified_request": f"Injected headers: {bypass_headers}",
                        "original_response": f"HTTP {auth_status}\n\n{auth_body[:500]}",
                        "modified_response": f"HTTP {bypass_resp.status_code}\n\n{bypass_resp.text[:500]}",
                        "response_diff": "",
                        "similarity_score": 0.0,
                        "explanation": f"Header injection bypass using {bypass_headers}.\n\n{learning['explanation']}",
                        "fix_suggestion": learning["fix"],
                        "cwe_id": learning["cwe_id"],
                        "owasp_ref": learning["owasp_ref"],
                    })
            except httpx.RequestError:
                continue

    return findings
