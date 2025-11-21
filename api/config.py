from functools import lru_cache

from pydantic_settings import BaseSettings


class Config(BaseSettings):
    LFS_SERVER_HOST: str = "http://localhost:8080"

    # Github OAuth
    GITHUB_CLIENT_ID: str = "changeme"
    GITHUB_CLIENT_SECRET: str = "changeme"
    GITHUB_REPO_OWNER: str = "EPFL-ENAC"
    GITHUB_REPO_NAME: str = "git-lfs-proxy"
    JWT_SECRET: str = "dev_secret"


@lru_cache()
def get_config():
    return Config()


config = get_config()
