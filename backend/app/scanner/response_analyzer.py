"""
Response Analyzer — compares HTTP responses to identify access control violations.
"""
import json
import difflib
from dataclasses import dataclass
from typing import Optional


@dataclass
class AnalysisResult:
    is_vulnerable: bool
    severity: str          # CRITICAL, HIGH, MEDIUM, LOW, INFO
    similarity_score: float
    response_diff: str
    reason: str


STATUS_SUCCESS = {200, 201, 202, 204}
STATUS_AUTH_REQUIRED = {401, 403}


def compute_diff(original: str, modified: str) -> str:
    """Generate a unified diff between two response bodies."""
    orig_lines = original.splitlines(keepends=True)
    mod_lines = modified.splitlines(keepends=True)
    diff = difflib.unified_diff(
        orig_lines, mod_lines,
        fromfile="original_response",
        tofile="modified_response",
        lineterm=""
    )
    return "".join(diff)


def similarity(a: str, b: str) -> float:
    """SequenceMatcher ratio between two strings."""
    return difflib.SequenceMatcher(None, a, b).ratio()


def analyze_idor(
    original_status: int,
    original_body: str,
    modified_status: int,
    modified_body: str,
    owner_persona_label: str,
    attacker_persona_label: str,
) -> AnalysisResult:
    """
    Detect IDOR: attacker gets 2xx on a resource that should be owner-only,
    and the response contains owner-like data (different from attacker's own).
    """
    diff = compute_diff(original_body, modified_body)
    sim = similarity(original_body, modified_body)

    if modified_status in STATUS_SUCCESS:
        if sim > 0.85:
            # Very similar — might be two users with same data
            return AnalysisResult(
                is_vulnerable=True,
                severity="MEDIUM",
                similarity_score=sim,
                response_diff=diff,
                reason=f"Attacker ({attacker_persona_label}) received 200 accessing {owner_persona_label}'s resource (responses similar — possible shared data).",
            )
        else:
            return AnalysisResult(
                is_vulnerable=True,
                severity="CRITICAL",
                similarity_score=sim,
                response_diff=diff,
                reason=f"IDOR confirmed: {attacker_persona_label} accessed resource belonging to {owner_persona_label}. Status: {modified_status}.",
            )
    elif modified_status in STATUS_AUTH_REQUIRED:
        return AnalysisResult(
            is_vulnerable=False,
            severity="INFO",
            similarity_score=sim,
            response_diff=diff,
            reason=f"Properly blocked with {modified_status} for {attacker_persona_label}.",
        )
    else:
        return AnalysisResult(
            is_vulnerable=False,
            severity="LOW",
            similarity_score=sim,
            response_diff=diff,
            reason=f"Unusual status {modified_status} — may indicate partial protection.",
        )


def analyze_auth_bypass(
    auth_status: int,
    auth_body: str,
    no_auth_status: int,
    no_auth_body: str,
) -> AnalysisResult:
    """Check if removing authorization still returns success."""
    diff = compute_diff(auth_body, no_auth_body)
    sim = similarity(auth_body, no_auth_body)

    if no_auth_status in STATUS_SUCCESS:
        return AnalysisResult(
            is_vulnerable=True,
            severity="CRITICAL",
            similarity_score=sim,
            response_diff=diff,
            reason=f"Authentication bypass: endpoint returned {no_auth_status} with NO token. Expected 401/403.",
        )
    else:
        return AnalysisResult(
            is_vulnerable=False,
            severity="INFO",
            similarity_score=sim,
            response_diff=diff,
            reason=f"Properly requires authentication: no-token request returned {no_auth_status}.",
        )


def analyze_privilege_escalation(
    admin_status: int,
    admin_body: str,
    user_status: int,
    user_body: str,
) -> AnalysisResult:
    """Check if low-privilege user can access admin-only endpoint."""
    diff = compute_diff(admin_body, user_body)
    sim = similarity(admin_body, user_body)

    if user_status in STATUS_SUCCESS:
        return AnalysisResult(
            is_vulnerable=True,
            severity="CRITICAL",
            similarity_score=sim,
            response_diff=diff,
            reason=f"Privilege escalation: low-privilege user received {user_status} on an admin-level endpoint.",
        )
    elif user_status == 403:
        return AnalysisResult(
            is_vulnerable=False,
            severity="INFO",
            similarity_score=sim,
            response_diff=diff,
            reason="Properly enforced: low-privilege user correctly received 403.",
        )
    else:
        return AnalysisResult(
            is_vulnerable=False,
            severity="LOW",
            similarity_score=sim,
            response_diff=diff,
            reason=f"Unexpected status {user_status} for low-privilege user.",
        )


def analyze_method_manipulation(
    original_method: str,
    original_status: int,
    tested_method: str,
    tested_status: int,
    tested_body: str,
) -> AnalysisResult:
    """Detect unexpected HTTP method support."""
    if tested_status in STATUS_SUCCESS and tested_method != original_method:
        return AnalysisResult(
            is_vulnerable=True,
            severity="MEDIUM",
            similarity_score=0.0,
            response_diff="",
            reason=f"Method manipulation: {tested_method} returned {tested_status} but only {original_method} was intended.",
        )
    return AnalysisResult(
        is_vulnerable=False,
        severity="INFO",
        similarity_score=0.0,
        response_diff="",
        reason=f"{tested_method} correctly returned {tested_status}.",
    )
