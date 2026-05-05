"""
Token Manager — manages multiple user personas with their Bearer tokens.
"""
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class Persona:
    label: str       # e.g. "Admin", "User Alice", "No Token"
    token: str       # Bearer token value, empty = unauthenticated


class TokenManager:
    def __init__(self, personas: List[dict]):
        """
        personas: list of {label: str, token: str}
        """
        self.personas: List[Persona] = []
        for p in personas:
            self.personas.append(Persona(label=p["label"], token=p.get("token", "")))

        # Always ensure we test with NO token
        labels = [p.label.lower() for p in self.personas]
        if "no token" not in labels and "unauthenticated" not in labels:
            self.personas.append(Persona(label="No Token", token=""))

    def get_all(self) -> List[Persona]:
        return self.personas

    def get_by_label(self, label: str) -> Optional[Persona]:
        for p in self.personas:
            if p.label.lower() == label.lower():
                return p
        return None

    def has_multiple_auth_levels(self) -> bool:
        """True if we have both authenticated and unauthenticated personas."""
        has_auth = any(p.token for p in self.personas)
        has_no_auth = any(not p.token for p in self.personas)
        return has_auth and has_no_auth

    def get_privileged(self) -> Optional[Persona]:
        """Return first persona with 'admin' or 'root' in label."""
        for p in self.personas:
            if any(kw in p.label.lower() for kw in ["admin", "root", "superuser", "manager"]):
                return p
        return None

    def get_unprivileged(self) -> Optional[Persona]:
        """Return first non-admin authenticated persona."""
        privileged = self.get_privileged()
        for p in self.personas:
            if p.token and p != privileged:
                return p
        return None
