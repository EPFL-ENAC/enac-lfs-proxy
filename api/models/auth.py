from pydantic import BaseModel


class GitHubPermissions(BaseModel):
    pull: bool = False
    push: bool = False
    admin: bool = False
