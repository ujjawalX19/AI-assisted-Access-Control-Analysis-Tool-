"""
IDOR Attack Module — Insecure Direct Object Reference detection.
Mutates resource IDs in URL paths and request bodies, tests with different tokens.
"""
import re
import json
import uuid
from typing import List, Optional
import httpx

from app.scanner.request_parser import ParsedRequest, extract_ids_from_path, inject_token
from app.scanner.response_analyzer import analyze_idor
from app.scanner.token_manager import TokenManager, Persona
from app.scanner.learning_mode import get_learning
from app.scanner.access_graph import AccessGraph


def _mutate_id(id_val: str, id_type: str) -> List[str]:
    """Generate mutations for a given ID."""
    mutations = []
    if id_type == "numeric":
        n = int(id_val)
        mutations = [str(n + 1), str(n - 1), str(n + 5), str(max(1, n - 5)), "1", "0", "9999"]
    elif id_type == "uuid":
        # Generate 3 random UUIDs as mutations
        mutations = [str(uuid.uuid4()) for _ in range(3)]
    return list(dict.fromkeys(mutations))  # deduplicate, preserve order


def _replace_id_in_url(url: str, old_id: str, new_id: str) -> str:
    return url.replace(f"/{old_id}", f"/{new_id}", 1)


async def run_idor_scan(
    request: ParsedRequest,
    token_manager: TokenManager,
    access_graph: AccessGraph,
    timeout: float = 10.0,
) -> List[dict]:
    """
    Run IDOR checks on a parsed request.
    Returns a list of finding dicts.
    """
    findings = []
    ids_in_path = extract_ids_from_path(request.path)

    if not ids_in_path:
        return findings

    personas = token_manager.get_all()
    if len(personas) < 2:
        # Need at least 2 personas for cross-user comparison
        return findings

    owner = personas[0]
    attackers = personas[1:]

    async with httpx.AsyncClient(timeout=timeout, verify=False) as client:
        # First, make the original request
        original_req = inject_token(request, owner.token)
        try:
            original_resp = await client.request(
                method=original_req.method,
                url=original_req.url,
                headers=original_req.headers,
                content=original_req.body,
            )
            original_body = original_resp.text
            original_status = original_resp.status_code
        except httpx.RequestError as e:
            return [{"error": str(e), "module": "idor"}]

        # Update access graph for owner
        access_graph.add_edge(
            endpoint=request.path, method=request.method, persona=owner.label,
            status="ALLOWED" if original_status < 400 else "DENIED"
        )

        # Test each ID mutation with each attacker token
        for id_info in ids_in_path[:2]:  # Limit to first 2 IDs for speed
            mutations = _mutate_id(id_info["value"], id_info["type"])

            for mutated_id in mutations[:5]:  # Max 5 mutations per ID
                mutated_url = _replace_id_in_url(request.url, id_info["value"], mutated_id)
                mutated_path = _replace_id_in_url(request.path, id_info["value"], mutated_id)

                for attacker in attackers:
                    attacker_req = inject_token(
                        request.clone_with(url=mutated_url, path=mutated_path),
                        attacker.token,
                    )

                    try:
                        attacker_resp = await client.request(
                            method=attacker_req.method,
                            url=attacker_req.url,
                            headers=attacker_req.headers,
                            content=attacker_req.body,
                        )
                        attacker_body = attacker_resp.text
                        attacker_status = attacker_resp.status_code
                    except httpx.RequestError:
                        continue

                    result = analyze_idor(
                        original_status, original_body,
                        attacker_status, attacker_body,
                        owner.label, attacker.label,
                    )

                    access_graph.add_edge(
                        endpoint=mutated_path, method=request.method, persona=attacker.label,
                        status="VULNERABLE" if result.is_vulnerable else "DENIED",
                        vuln_type="IDOR" if result.is_vulnerable else None,
                    )

                    if result.is_vulnerable:
                        learning = get_learning("IDOR")
                        findings.append({
                            "vuln_type": "IDOR",
                            "severity": result.severity,
                            "endpoint": mutated_path,
                            "method": request.method,
                            "original_request": original_req.to_raw(),
                            "modified_request": attacker_req.to_raw(),
                            "original_response": f"HTTP {original_status}\n\n{original_body[:2000]}",
                            "modified_response": f"HTTP {attacker_status}\n\n{attacker_body[:2000]}",
                            "response_diff": result.response_diff,
                            "similarity_score": result.similarity_score,
                            "explanation": f"{result.reason}\n\n{learning['explanation']}",
                            "fix_suggestion": learning["fix"],
                            "cwe_id": learning["cwe_id"],
                            "owasp_ref": learning["owasp_ref"],
                        })

    return findings
