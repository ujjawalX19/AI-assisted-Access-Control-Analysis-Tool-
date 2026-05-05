import asyncio
import logging
from app.core.database import engine, Base, create_tables

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

async def reset_database():
    logger.info("Dropping all tables...")
    async with engine.begin() as conn:
        # We need to import models so they are registered in Base.metadata
        from app.models.user import User
        from app.models.project import Project
        from app.models.api_request import APIRequest
        from app.models.scan_result import ScanResult
        
        await conn.run_sync(Base.metadata.drop_all)
    
    logger.info("Recreating all tables...")
    await create_tables()
    logger.info("Database reset complete.")

if __name__ == "__main__":
    asyncio.run(reset_database())
