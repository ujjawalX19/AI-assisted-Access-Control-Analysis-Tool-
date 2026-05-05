"""
app/models/__init__.py
──────────────────────
Exposes ORM models for convenient import via `from app.models import User`.

Why lazy imports (TYPE_CHECKING guard):
────────────────────────────────────────
Eagerly importing all four models at package load time forces Python to
fully resolve every model module *before* SQLAlchemy has finished
configuring its mapper relationships.  If any model's module triggers
an import of another model (directly or transitively) before the first
one finishes loading, Python raises ImportError or AttributeError.

The TYPE_CHECKING block lets type checkers (mypy, Pylance) see the
symbols for auto-complete and type safety, while at runtime the imports
only happen when callers explicitly request them — by which point all
modules have finished loading.

SQLAlchemy's `create_tables()` in database.py handles the explicit
local-import needed to register models with Base.metadata.
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models.user import User
    from app.models.project import Project
    from app.models.api_request import APIRequest
    from app.models.scan_result import ScanResult

__all__ = ["User", "Project", "APIRequest", "ScanResult"]
