import asyncio
from sqlalchemy import select
from app.core.database import AsyncSessionLocal
from app.models.user import User
from app.models.project import Project  # Keep these imports to ensure models are registered
from app.models.api_request import APIRequest
from app.models.scan_result import ScanResult
from app.core.security import hash_password

async def seed():
    async with AsyncSessionLocal() as db:
        # Check if admin exists
        stmt = select(User).where(User.email == "admin@demo.com")
        result = await db.execute(stmt)
        admin = result.scalar_one_or_none()
        
        if not admin:
            print("Creating admin user...")
            new_admin = User(
                email="admin@demo.com",
                hashed_password=hash_password("admin123"),
                full_name="System Admin",
                role="admin"
            )
            db.add(new_admin)
            await db.commit()
            print("Admin user created: admin@demo.com / admin123")
        else:
            print("Admin user already exists.")

        # Also check ujjawal@123.com
        stmt = select(User).where(User.email == "ujjawal@123.com")
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()
        if user:
            print("Confirmed user ujjawal@123.com exists.")
        else:
            print("Creating ujjawal@123.com...")
            new_user = User(
                email="ujjawal@123.com",
                hashed_password=hash_password("password123"),
                full_name="Ujjawal Shrivastava",
                role="user"
            )
            db.add(new_user)
            await db.commit()
            print("User ujjawal@123.com created with password: password123")

if __name__ == "__main__":
    asyncio.run(seed())
