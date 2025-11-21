from pydantic import BaseModel


class GitHubPermissions(BaseModel):
    pull: bool = False
    push: bool = False
    admin: bool = False


class User(BaseModel):
    username: str
    full_name: str
    email: str | None = None
    permissions: GitHubPermissions
