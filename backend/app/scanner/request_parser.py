"""
Request Parser — parses raw HTTP request strings (Burp Suite format) into
structured ParsedRequest objects.
"""
import re
from dataclasses import dataclass, field
from typing import Dict, Optional
from urllib.parse import urlparse, urljoin


@dataclass
class ParsedRequest:
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[str]
    host: str
    path: str
    query: str
    scheme: str = "http"

    def to_raw(self) -> str:
        """Reconstruct raw HTTP request string."""
        lines = [f"{self.method} {self.path}{'?' + self.query if self.query else ''} HTTP/1.1"]
        for k, v in self.headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        if self.body:
            lines.append(self.body)
        return "\r\n".join(lines)

    def clone_with(self, **kwargs) -> "ParsedRequest":
        """Return a shallow clone with overridden fields."""
        import copy
        cloned = copy.copy(self)
        for k, v in kwargs.items():
            setattr(cloned, k, v)
        return cloned


def parse_raw_request(raw: str, base_url: Optional[str] = None) -> ParsedRequest:
    """
    Parse a raw HTTP request string into a ParsedRequest.
    Supports both absolute and relative URLs.
    """
    raw = raw.strip()
    lines = raw.replace("\r\n", "\n").split("\n")

    # Request line
    request_line = lines[0]
    parts = request_line.split(" ")
    method = parts[0].upper()
    path_full = parts[1] if len(parts) > 1 else "/"

    # Parse headers
    headers: Dict[str, str] = {}
    body_start = None
    for i, line in enumerate(lines[1:], start=1):
        if line.strip() == "":
            body_start = i + 1
            break
        if ":" in line:
            key, _, val = line.partition(":")
            headers[key.strip()] = val.strip()

    body = None
    if body_start and body_start < len(lines):
        body = "\n".join(lines[body_start:]).strip() or None

    # Determine host and scheme
    host = headers.get("Host", headers.get("host", ""))
    scheme = "https" if "443" in host or base_url and base_url.startswith("https") else "http"

    # Build full URL
    if path_full.startswith("http"):
        full_url = path_full
        parsed = urlparse(full_url)
        host = parsed.netloc
        path = parsed.path
        query = parsed.query
        scheme = parsed.scheme
    elif base_url:
        full_url = urljoin(base_url.rstrip("/"), path_full)
        parsed = urlparse(full_url)
        path = parsed.path
        query = parsed.query
    else:
        # Patch for Docker environments: if a user pastes 'localhost:8001', route to 'demo-target:8001'
        if "localhost:8001" in host or "127.0.0.1:8001" in host:
            import os
            demo_target = os.getenv("DEMO_TARGET_URL", "http://demo-target:8001")
            parsed_demo = urlparse(demo_target)
            host = parsed_demo.netloc
            scheme = parsed_demo.scheme

        full_url = f"{scheme}://{host}{path_full}"
        parsed = urlparse(full_url)
        path = parsed.path
        query = parsed.query

    return ParsedRequest(
        method=method,
        url=full_url,
        headers=headers,
        body=body,
        host=host,
        path=path,
        query=query,
        scheme=scheme,
    )


def extract_ids_from_path(path: str) -> list[dict]:
    """
    Extract numeric IDs and UUIDs from a URL path.
    Returns list of { type, value, position } dicts.
    """
    ids = []
    # Numeric IDs
    for m in re.finditer(r"/(\d+)(?:/|$|\?)", path):
        ids.append({"type": "numeric", "value": m.group(1), "start": m.start(1), "end": m.end(1)})
    # UUIDs
    uuid_pattern = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    for m in re.finditer(uuid_pattern, path, re.IGNORECASE):
        ids.append({"type": "uuid", "value": m.group(0), "start": m.start(), "end": m.end()})
    return ids


def inject_token(request: ParsedRequest, token: str) -> ParsedRequest:
    """Return a new ParsedRequest with the given Bearer token injected."""
    new_headers = dict(request.headers)
    if token:
        new_headers["Authorization"] = f"Bearer {token}"
    elif "Authorization" in new_headers:
        del new_headers["Authorization"]
    return request.clone_with(headers=new_headers)
