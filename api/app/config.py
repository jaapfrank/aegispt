from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="", case_sensitive=False, extra="ignore")

    app_name: str = "AegisPT"
    app_env: str = "development"
    api_prefix: str = "/api/v1"
    task_dispatch_mode: str = "manual"
    database_url: str = "sqlite+pysqlite:///./aegispt.db"
    redis_url: str = "redis://localhost:6379/0"
    artifacts_storage_mode: str = "inline"
    artifacts_s3_endpoint: str = "http://localhost:9000"
    artifacts_s3_bucket: str = "aegispt-artifacts"
    artifacts_s3_access_key: str = "minioadmin"
    artifacts_s3_secret_key: str = "change-me"
    zap_api_key: str = "change-me-zap-key"
    auto_create_tables: bool = True
    runner_timeout_seconds: float = 10.0
    execution_kill_switch: bool = False


@lru_cache
def get_settings() -> Settings:
    return Settings()
