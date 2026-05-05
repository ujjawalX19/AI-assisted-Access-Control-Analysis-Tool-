"""
Scan Engine Orchestrator — coordinates all attack modules and aggregates findings.
"""
import asyncio
from typing import List, Optional
from app.scanner.request_parser import ParsedRequest, parse_raw_request
from app.scanner.api_detector import detect_api_type
from app.scanner.token_manager import TokenManager
from app.scanner.access_graph import AccessGraph
from app.scanner.attack.idor import run_idor_scan
from app.scanner.attack.auth_bypass import run_auth_bypass_scan
from app.scanner.attack.privilege_escalation import run_privilege_escalation_scan
from app.scanner.attack.method_manipulation import run_method_manipulation_scan
from app.scanner.ai_risk_engine import enrich_with_ai_risk_score
import logging

logger = logging.getLogger(__name__)


async def run_scan(
    raw_request: str,
    user_tokens: List[dict],
    enabled_modules: List[str],
    progress_callback=None,
) -> dict:
    """
    Main scan orchestrator.
    
    Args:
        raw_request: Raw HTTP request string
        user_tokens: List of {label, token} dicts
        enabled_modules: Which modules to run
        progress_callback: Optional async callable(progress: int, message: str)
    
    Returns:
        {
          findings: [...],
          access_graph: {...},
          api_type: "REST" | "GraphQL",
          total_requests_sent: int,
        }
    """
    findings = []
    total_requests = 0

    async def report(progress: int, msg: str):
        if progress_callback:
            await progress_callback(progress, msg)
        logger.info(f"[SCAN {progress}%] {msg}")

    await report(5, "Parsing request...")
    request = parse_raw_request(raw_request)
    api_type = detect_api_type(request)
    token_manager = TokenManager(user_tokens)
    access_graph = AccessGraph()

    await report(10, f"Detected API type: {api_type}. Starting attack modules...")

    modules = {
        "idor": run_idor_scan,
        "auth_bypass": run_auth_bypass_scan,
        "privilege_escalation": run_privilege_escalation_scan,
        "method_manipulation": run_method_manipulation_scan,
    }

    total_modules = len([m for m in enabled_modules if m in modules])
    completed = 0

    for module_name in enabled_modules:
        if module_name not in modules:
            continue

        await report(
            10 + int((completed / max(total_modules, 1)) * 80),
            f"Running {module_name.replace('_', ' ').title()} scan..."
        )

        try:
            module_fn = modules[module_name]
            module_findings = await module_fn(request, token_manager, access_graph)
            findings.extend(module_findings)
            logger.info(f"Module {module_name}: {len(module_findings)} findings")
        except Exception as e:
            logger.error(f"Module {module_name} failed: {e}")
            findings.append({
                "vuln_type": "INFO",
                "severity": "INFO",
                "endpoint": request.path,
                "method": request.method,
                "explanation": f"Module {module_name} encountered an error: {str(e)}",
                "fix_suggestion": "",
                "cwe_id": "",
                "owasp_ref": "",
            })

        completed += 1

    await report(95, "Building access graph...")
    graph_data = access_graph.to_matrix()

    await report(98, "Applying AI Risk Intelligence Engine...")
    findings = enrich_with_ai_risk_score(findings)

    await report(100, f"Scan complete. {len(findings)} findings.")

    return {
        "findings": findings,
        "access_graph": graph_data,
        "api_type": api_type,
        "total_modules_run": completed,
    }
