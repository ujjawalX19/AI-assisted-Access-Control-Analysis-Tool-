import random
from typing import List

def enrich_with_ai_risk_score(findings: List[dict]) -> List[dict]:
    """
    Simulates an AI-Enhanced Risk Intelligence Engine analyzing security findings
    and generating risk scores, severities, confidences, and reasoning.
    """
    for finding in findings:
        vuln_type = finding.get("vuln_type", "INFO")
        severity = finding.get("severity", "LOW")
        endpoint = finding.get("endpoint", "/")
        method = finding.get("method", "GET")
        
        # Base score on base severity
        base_scores = {
            "CRITICAL": 85,
            "HIGH": 70,
            "MEDIUM": 45,
            "LOW": 20,
            "INFO": 5,
        }
        base_score = base_scores.get(severity, 10)
        
        # Detailed AI heuristics
        score = base_score + random.randint(0, 14)
        
        # Threat Intelligence Context: Sensitive Endpoints
        sensitive_keywords = ["admin", "users", "delete", "remove", "password", "auth", "billing", "settings", "config", "profile"]
        is_sensitive = any(kw in endpoint.lower() for kw in sensitive_keywords)
        if is_sensitive:
            score += 12
            
        # Contextual Weighting: State Alteration
        if method in ["POST", "PUT", "DELETE", "PATCH"]:
            score += 8
            
        # Limit score range
        score = min(score, 100)
        
        # Tiered AI Severity Classification
        if score >= 90:
            ai_severity = "CRITICAL"
        elif score >= 70:
            ai_severity = "HIGH"
        elif score >= 45:
            ai_severity = "MEDIUM"
        else:
            ai_severity = "LOW"
            
        ai_confidence = random.choice(["HIGH", "HIGH", "VERY HIGH", "MEDIUM"]) if score > 50 else random.choice(["MEDIUM", "LOW"])
        
        # Generative Intelligence Reasoning
        reasons = []
        reasons.append(f"AI Risk Analyzer identified a {severity}-level exposure on '{endpoint}' using {method}.")
        
        if score >= 70:
            if is_sensitive:
                reasons.append("The target resource intersects with sensitive system domains (IAM, User Profile, or Financials).")
            if method in ["POST", "PUT", "DELETE"]:
                reasons.append(f"The use of {method} allows for unauthorized state transition or data destruction.")
            reasons.append(f"Resulting divergence indicates a failure in the application's {vuln_type} enforcement layer.")
        else:
            reasons.append("Risk is mitigated by limited data exposure or lower-impact HTTP verb usage.")
            
        finding["ai_risk_score"] = float(score)
        finding["ai_severity"] = ai_severity
        finding["ai_confidence"] = ai_confidence
        finding["ai_reasoning"] = " ".join(reasons)

    return findings
