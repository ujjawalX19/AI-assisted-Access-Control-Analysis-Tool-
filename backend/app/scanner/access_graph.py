"""
Access Graph Builder — constructs a role vs endpoint access matrix graph.
"""
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional


@dataclass
class AccessEdge:
    endpoint: str
    method: str
    persona: str
    status: str          # "ALLOWED", "DENIED", "VULNERABLE"
    vuln_type: Optional[str] = None


class AccessGraph:
    def __init__(self):
        self.edges: List[AccessEdge] = []
        self.endpoints: set = set()
        self.personas: set = set()

    def add_edge(self, endpoint: str, method: str, persona: str, status: str, vuln_type: Optional[str] = None):
        self.edges.append(AccessEdge(endpoint, method, persona, status, vuln_type))
        self.endpoints.add(f"{method} {endpoint}")
        self.personas.add(persona)

    def to_matrix(self) -> dict:
        """
        Returns a matrix structure for the frontend heatmap:
        {
          "endpoints": ["GET /api/users/1", ...],
          "personas": ["Admin", "User", "No Token"],
          "cells": [
            {"endpoint": "GET /api/users/1", "persona": "Admin", "status": "ALLOWED"},
            ...
          ]
        }
        """
        endpoints = sorted(self.endpoints)
        personas = sorted(self.personas)
        cells = []

        # Build a lookup
        lookup: Dict[tuple, AccessEdge] = {}
        for edge in self.edges:
            key = (f"{edge.method} {edge.endpoint}", edge.persona)
            # Prefer VULNERABLE > ALLOWED > DENIED
            existing = lookup.get(key)
            if not existing or self._priority(edge.status) > self._priority(existing.status):
                lookup[key] = edge

        for endpoint in endpoints:
            for persona in personas:
                edge = lookup.get((endpoint, persona))
                cells.append({
                    "endpoint": endpoint,
                    "persona": persona,
                    "status": edge.status if edge else "UNKNOWN",
                    "vuln_type": edge.vuln_type if edge else None,
                })

        return {
            "endpoints": endpoints,
            "personas": personas,
            "cells": cells,
        }

    def _priority(self, status: str) -> int:
        return {"VULNERABLE": 3, "ALLOWED": 2, "DENIED": 1, "UNKNOWN": 0}.get(status, 0)

    def to_json(self) -> str:
        return json.dumps(self.to_matrix(), indent=2)
