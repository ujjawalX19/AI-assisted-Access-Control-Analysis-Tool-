"""
Method Manipulation Attack Module — tests unintended HTTP methods on endpoints.
"""
import httpx
from typing import List
from app.scanner.request_parser import ParsedRequest, inject_token
from app.scanner.response_analyzer import analyze_method_manipulation
from app.scanner.token_manager import TokenManager
from app.scanner.learning_mode import get_learning
from app.scanner.access_graph import AccessGraph

ALL_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]


async def run_method_manipulation_scan(
    request: ParsedRequest,
    token_manager: TokenManager,
    access_graph: AccessGraph,
    timeout: float = 10.0,
) -> List[dict]:
    findings = []
    owner = token_manager.get_all()[0] if token_manager.get_all() else None
    if not owner:
        return findings

    methods_to_test = [m for m in ALL_METHODS if m != request.method]

    async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
        # Baseline with original method
        orig_req = inject_token(request, owner.token)
        try:
            orig_resp = await client.request(
                method=orig_req.method, url=orig_req.url,
                headers=orig_req.headers, content=orig_req.body,
            )
            orig_status = orig_resp.status_code
        except httpx.RequestError as e:
            return [{"error": str(e), "module": "method_manipulation"}]

        for method in methods_to_test:
            test_req = inject_token(request.clone_with(method=method), owner.token)
            try:
                test_resp = await client.request(
                    method=method, url=test_req.url,
                    headers=test_req.headers, content=test_req.body,
                )
                test_status = test_resp.status_code
                test_body = test_resp.text
            except httpx.RequestError:
                continue

            result = analyze_method_manipulation(
                original_method=request.method,
                original_status=orig_status,
                tested_method=method,
                tested_status=test_status,
                tested_body=test_body,
            )

            if result.is_vulnerable:
                learning = get_learning("METHOD_MANIPULATION")
                findings.append({
                    "vuln_type": "METHOD_MANIPULATION",
                    "severity": result.severity,
                    "endpoint": request.path,
                    "method": method,
                    "original_request": orig_req.to_raw(),
                    "modified_request": f"{method} {request.url}\n\n{request.body or ''}",
                    "original_response": f"HTTP {orig_status}",
                    "modified_response": f"HTTP {test_status}\n\n{test_body[:2000]}",
                    "response_diff": "",
                    "similarity_score": 0.0,
                    "explanation": f"{result.reason}\n\n{learning['explanation']}",
                    "fix_suggestion": learning["fix"],
                    "cwe_id": learning["cwe_id"],
                    "owasp_ref": learning["owasp_ref"],
                })

    return findings
