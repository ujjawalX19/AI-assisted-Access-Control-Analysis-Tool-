"""
Privilege Escalation Attack Module — tests if low-privilege users can access
admin-level endpoints.
"""
import httpx
from typing import List
from app.scanner.request_parser import ParsedRequest, inject_token
from app.scanner.response_analyzer import analyze_privilege_escalation
from app.scanner.token_manager import TokenManager
from app.scanner.learning_mode import get_learning
from app.scanner.access_graph import AccessGraph

# Role-injection headers to test
ROLE_HEADERS = [
    {"X-Role": "admin"},
    {"X-User-Role": "admin"},
    {"X-Admin": "true"},
    {"X-Forwarded-User": "admin"},
    {"Role": "admin"},
]


async def run_privilege_escalation_scan(
    request: ParsedRequest,
    token_manager: TokenManager,
    access_graph: AccessGraph,
    timeout: float = 10.0,
) -> List[dict]:
    findings = []
    privileged = token_manager.get_privileged()
    unprivileged = token_manager.get_unprivileged()

    if not privileged or not unprivileged:
        return findings  # Need both roles

    async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
        # Baseline: admin request
        admin_req = inject_token(request, privileged.token)
        try:
            admin_resp = await client.request(
                method=admin_req.method, url=admin_req.url,
                headers=admin_req.headers, content=admin_req.body,
            )
            admin_status = admin_resp.status_code
            admin_body = admin_resp.text
        except httpx.RequestError as e:
            return [{"error": str(e), "module": "privilege_escalation"}]

        access_graph.add_edge(
            endpoint=request.path, method=request.method,
            persona=privileged.label, status="ALLOWED" if admin_status < 400 else "DENIED"
        )

        # Test with low-privilege user token
        user_req = inject_token(request, unprivileged.token)
        try:
            user_resp = await client.request(
                method=user_req.method, url=user_req.url,
                headers=user_req.headers, content=user_req.body,
            )
            user_status = user_resp.status_code
            user_body = user_resp.text
        except httpx.RequestError:
            return findings

        result = analyze_privilege_escalation(admin_status, admin_body, user_status, user_body)

        access_graph.add_edge(
            endpoint=request.path, method=request.method,
            persona=unprivileged.label,
            status="VULNERABLE" if result.is_vulnerable else "DENIED",
            vuln_type="PRIVILEGE_ESCALATION" if result.is_vulnerable else None,
        )

        if result.is_vulnerable:
            learning = get_learning("PRIVILEGE_ESCALATION")
            findings.append({
                "vuln_type": "PRIVILEGE_ESCALATION",
                "severity": result.severity,
                "endpoint": request.path,
                "method": request.method,
                "original_request": admin_req.to_raw(),
                "modified_request": user_req.to_raw(),
                "original_response": f"HTTP {admin_status}\n\n{admin_body[:2000]}",
                "modified_response": f"HTTP {user_status}\n\n{user_body[:2000]}",
                "response_diff": result.response_diff,
                "similarity_score": result.similarity_score,
                "explanation": f"{result.reason}\n\n{learning['explanation']}",
                "fix_suggestion": learning["fix"],
                "cwe_id": learning["cwe_id"],
                "owasp_ref": learning["owasp_ref"],
            })

        # Test role header injection (low-priv user + admin header)
        for role_header in ROLE_HEADERS:
            test_req = inject_token(request, unprivileged.token)
            test_headers = dict(test_req.headers)
            test_headers.update(role_header)

            try:
                header_resp = await client.request(
                    method=request.method, url=request.url,
                    headers=test_headers, content=request.body,
                )
                if header_resp.status_code in {200, 201} and admin_status in {200, 201}:
                    learning = get_learning("PRIVILEGE_ESCALATION")
                    findings.append({
                        "vuln_type": "PRIVILEGE_ESCALATION",
                        "severity": "CRITICAL",
                        "endpoint": request.path,
                        "method": request.method,
                        "original_request": admin_req.to_raw(),
                        "modified_request": f"Low-priv token + injected header: {role_header}",
                        "original_response": f"HTTP {admin_status}\n\n{admin_body[:500]}",
                        "modified_response": f"HTTP {header_resp.status_code}\n\n{header_resp.text[:500]}",
                        "response_diff": "",
                        "similarity_score": 0.0,
                        "explanation": f"Role header injection via {role_header} bypassed authorization.\n\n{learning['explanation']}",
                        "fix_suggestion": learning["fix"],
                        "cwe_id": learning["cwe_id"],
                        "owasp_ref": learning["owasp_ref"],
                    })
            except httpx.RequestError:
                continue

    return findings
