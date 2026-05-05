"""
API Type Detector — classifies an HTTP request as REST or GraphQL.
"""
import json
from app.scanner.request_parser import ParsedRequest


def detect_api_type(request: ParsedRequest) -> str:
    """Returns 'GraphQL' or 'REST'."""
    # Path-based detection
    path_lower = request.path.lower()
    if "graphql" in path_lower or "gql" in path_lower:
        return "GraphQL"

    # Body-based detection
    if request.body:
        try:
            body = json.loads(request.body)
            if isinstance(body, dict) and ("query" in body or "mutation" in body):
                return "GraphQL"
        except (json.JSONDecodeError, TypeError):
            pass

    # Content-Type header check
    ct = request.headers.get("Content-Type", "")
    if "application/graphql" in ct:
        return "GraphQL"

    return "REST"


def is_graphql_introspection_enabled(request: ParsedRequest) -> bool:
    """Check if GraphQL introspection is allowed."""
    if request.body:
        try:
            body = json.loads(request.body)
            query = body.get("query", "")
            return "__schema" in query or "__type" in query
        except Exception:
            pass
    return False
