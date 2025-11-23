import logging

import httpx
from fastapi import HTTPException

from api.config import config
from api.models.auth import GitHubPermissions

GITHUB_OAUTH_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_API_URL = "https://api.github.com/user"
GITHUB_REPO_API_URL = "https://api.github.com/repos/{owner}/{repo}"


async def generate_token(code: str):
    """Generate a GitHub token after validating the OAuth2 code with GitHub."""
    async with httpx.AsyncClient() as client:
        token_res = await client.post(
            GITHUB_OAUTH_URL,
            headers={"Accept": "application/json"},
            data={
                "client_id": config.GITHUB_CLIENT_ID,
                "client_secret": config.GITHUB_CLIENT_SECRET,
                "code": code,
                "redirect_uri": f"{config.APP_URL}/auth/callback",
            },
        )

        if token_res.status_code != 200:
            raise HTTPException(status_code=502, detail="GitHub OAuth token request failed")

        token_json = token_res.json()
        if "error" in token_json:
            error_msg = f"GitHub OAuth error: {token_json.get('error')}"
            if "error_description" in token_json:
                error_msg += f" - {token_json.get('error_description')}"
            raise HTTPException(status_code=400, detail=error_msg)

        token = token_json.get("access_token")
        if not token:
            raise HTTPException(status_code=400, detail="Failed OAuth token: missing access_token")

    return token


async def get_user_permissions(username: str, token: str, owner: str, repo: str) -> GitHubPermissions:
    # Admin access for internal API token
    if (
        config.FULL_ACCESS_USERNAME is not None
        and username == config.FULL_ACCESS_USERNAME
        and config.FULL_ACCESS_TOKEN is not None
        and token == config.FULL_ACCESS_TOKEN
    ):
        return GitHubPermissions(pull=True, push=True, admin=True)

    try:
        async with httpx.AsyncClient() as client:
            # Get user info
            user_res = await client.get(
                GITHUB_USER_API_URL,
                headers={"Authorization": f"token {token}"},
            )

            if user_res.status_code != 200:
                raise HTTPException(status_code=401, detail="Invalid or expired token")

            # Get repository permissions
            repo_res = await client.get(
                GITHUB_REPO_API_URL.format(owner=owner, repo=repo),
                headers={"Authorization": f"token {token}"},
            )

            if repo_res.status_code == 404:
                raise HTTPException(status_code=404, detail="Repository not found")
            elif repo_res.status_code != 200:
                raise HTTPException(status_code=403, detail="Access to repository denied")

            repo_data = repo_res.json()
            perm_data = repo_data.get("permissions", {})

        return GitHubPermissions(
            pull=perm_data.get("pull", False),
            push=perm_data.get("push", False),
            admin=perm_data.get("admin", False),
        )

    except httpx.RequestError as e:
        logging.exception("GitHub API request failed", e)
        raise HTTPException(status_code=502, detail="GitHub API error")


def check_repository_access(method: str, permissions: GitHubPermissions) -> bool:
    if method.upper() in ["GET", "HEAD", "OPTIONS"]:
        return permissions.pull or permissions.admin
    elif method.upper() in ["POST", "PUT", "PATCH", "DELETE"]:
        return permissions.push or permissions.admin
    else:
        return False
