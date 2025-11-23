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
    GITHUB_REPO_OWNER: str = "EPFL-ENAC"
    GITHUB_REPO_NAME: str = "git-lfs-proxy"


@lru_cache()
def get_config():
    return Config()


config = get_config()
