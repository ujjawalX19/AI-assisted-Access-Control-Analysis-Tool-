from pydantic_settings import BaseSettings
from pydantic import AnyHttpUrl
from typing import List
import json


class Settings(BaseSettings):
    APP_NAME: str = "BAC Scanner"
    DEBUG: bool = True
    SECRET_KEY: str = "change-this-in-production-use-openssl-rand-hex-32"
    DATABASE_URL: str = "postgresql+asyncpg://bac:bac123@127.0.0.1:5433/bac_db"
    REDIS_URL: str = "redis://localhost:6379/0"
    CORS_ORIGINS: str = '["http://localhost:5173","http://localhost:3000"]'
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    ALGORITHM: str = "HS256"
    DEMO_TARGET_URL: str = "http://localhost:8001"

    @property
    def cors_origins_list(self) -> List[str]:
        return json.loads(self.CORS_ORIGINS)

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()