"""
app/core/database.py
────────────────────
Async SQLAlchemy engine, session factory, and table initialisation.

Why models are imported inside create_tables()
───────────────────────────────────────────────
SQLAlchemy's `Base.metadata.create_all()` only creates tables whose model
classes have been *imported* at some point before the call — because model
classes register themselves with Base.metadata at class-definition time.

If no model module has been imported, `metadata.create_all()` is a no-op
and no tables are created, causing every subsequent DB query to fail with
"relation does not exist".

The explicit imports inside `create_tables()` guarantee that all four ORM
models are registered regardless of the import order in the rest of the
application.  Using local imports (inside the function) avoids circular
import problems at module load time.
"""

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings


class Base(DeclarativeBase):
    pass


engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    pool_pre_ping=True,   # validate connections before handing them out
    pool_size=10,
    max_overflow=20,
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,  # keep attributes accessible after commit
)


async def get_db():
    """
    FastAPI dependency that provides a transactional DB session.

    Design: route handlers are responsible for calling `await db.commit()`
    explicitly after mutations.  This dependency only handles rollback on
    exception and ensures the session is always closed.

    Why no auto-commit here:
    If this dependency committed AND the route handler also called commit(),
    the second commit would raise `InvalidRequestError` because the session
    would be in a post-commit state with no active transaction.  This is the
    most common source of 500 errors in FastAPI + SQLAlchemy async setups.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def create_tables():
    """
    Create all database tables that do not yet exist.

    IMPORTANT: all model modules are imported here (locally) to ensure
    their classes are registered with Base.metadata before create_all()
    is called.  Without these imports, create_all() would create zero
    tables because it only knows about models it has seen.
    """
    # Local imports — these must come before run_sync(Base.metadata.create_all)
    from app.models.user import User          # noqa: F401  registers `users`
    from app.models.project import Project    # noqa: F401  registers `projects`
    from app.models.api_request import APIRequest  # noqa: F401  registers `api_requests`
    from app.models.scan_result import ScanResult  # noqa: F401  registers `scan_results`

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
