from functools import lru_cache

from pydantic_settings import BaseSettings


class Config(BaseSettings):
    APP_URL: str = "http://localhost:8000"
    FULL_ACCESS_USERNAME: str | None = None
    FULL_ACCESS_TOKEN: str | None = None
    LFS_SERVER_HOST: str = "http://localhost:8080"

    # Github OAuth
    GITHUB_CLIENT_ID: str
    GITHUB_CLIENT_SECRET: str
    GITHUB_PERMISSIONS_CACHE_TTL_SECONDS: int = 60


@lru_cache()
def get_config():
    return Config()


config = get_config()
