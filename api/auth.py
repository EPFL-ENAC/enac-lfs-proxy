import logging
import time

import httpx
from fastapi import Cookie, HTTPException
from jose import jwt

from api.config import config
from api.models.auth import GitHubPermissions, User

GH_API_URL = "https://github.com/login/oauth/access_token"
GH_USER_API = "https://api.github.com/user"
GH_REPO_PERMISSION_API = "https://api.github.com/repos/{owner}/{repo}"
JWT_EXPIRY_SECONDS = 2592000  # 30 days


async def make_jwt(code: str):
    """Make a JWT token after validating the OAuth2 code with GitHub.
    Args:
        code: The OAuth2 code received from GitHub after user authorization.
    Returns:
        A JWT token as a string.
    Raises:
        HTTPException: If the OAuth token retrieval or user information fetch fails.
    """
    async with httpx.AsyncClient() as client:
        token_res = await client.post(
            GH_API_URL,
            headers={"Accept": "application/json"},
            data={
                "client_id": config.GITHUB_CLIENT_ID,
                "client_secret": config.GITHUB_CLIENT_SECRET,
                "code": code,
            },
        )

        token_json = token_res.json()
        token = token_json.get("access_token")
        if "error" in token_json:
            error_msg = f"GitHub OAuth error: {token_json.get('error')}"
            if "error_description" in token_json:
                error_msg += f" - {token_json.get('error_description')}"
            raise HTTPException(status_code=400, detail=error_msg)
        if not token:
            raise HTTPException(status_code=400, detail="Failed OAuth token: missing access_token")

        try:
            user_res = await client.get(GH_USER_API, headers={"Authorization": f"token {token}"})
            github_user = user_res.json()
            repo_res = await client.get(
                GH_REPO_PERMISSION_API.format(owner=config.GITHUB_REPO_OWNER, repo=config.GITHUB_REPO_NAME),
                headers={"Authorization": f"token {token}"},
            )
            repo_data = repo_res.json()
            perm_data = repo_data.get("permissions", {})
        except Exception as e:
            raise HTTPException(
                status_code=502,
                detail=f"GitHub user / repo permission request failed: {str(e)}",
            )

    current_time = int(time.time())
    jwt_token = jwt.encode(
        {
            "iss": "mmsdb",
            "id": github_user["id"],
            "sub": github_user["login"],
            "full_name": github_user.get("name"),
            "email": github_user.get("email"),
            "github_token": token,
            "iat": current_time,
            "exp": current_time + JWT_EXPIRY_SECONDS,
        },
        config.JWT_SECRET,
        algorithm="HS256",
    )
    return jwt_token


async def get_user_with_repo_permissions(owner: str, repo: str, github_token: str | None = None) -> User:
    """Get user and fetch their permissions for a specific repository using GitHub token.

    Args:
        owner: The repository owner.
        repo: The repository name.
        github_token: The GitHub personal access token to validate.

    Returns:
        The user with repository permissions.

    Raises:
        HTTPException: If the token is invalid or GitHub API call fails.
    """
    if not github_token:
        raise HTTPException(status_code=401, detail="missing_token")

    try:
        async with httpx.AsyncClient() as client:
            # Get user info
            user_res = await client.get(
                GH_USER_API,
                headers={"Authorization": f"token {github_token}"},
            )

            if user_res.status_code != 200:
                raise HTTPException(status_code=401, detail="invalid_github_token")

            user_data = user_res.json()

            # Get repository permissions
            repo_res = await client.get(
                GH_REPO_PERMISSION_API.format(owner=owner, repo=repo),
                headers={"Authorization": f"token {github_token}"},
            )

            if repo_res.status_code == 404:
                raise HTTPException(status_code=404, detail="repository_not_found")
            elif repo_res.status_code != 200:
                raise HTTPException(status_code=403, detail="access_denied")

            repo_data = repo_res.json()
            perm_data = repo_data.get("permissions", {})

        return User(
            username=user_data.get("login"),
            email=user_data.get("email", None),
            full_name=user_data.get("name", user_data.get("login")),
            permissions=GitHubPermissions(
                pull=perm_data.get("pull", False),
                push=perm_data.get("push", False),
                admin=perm_data.get("admin", False),
            ),
        )

    except httpx.RequestError as e:
        logging.exception("GitHub API request failed", e)
        raise HTTPException(status_code=502, detail="github_api_error")


def check_repository_access(method: str, user: User) -> bool:
    """Check if user has required permissions for the HTTP method.

    Args:
        method: HTTP method (GET, POST, PUT, etc.)
        user: User with repository permissions

    Returns:
        True if user has required permissions, False otherwise
    """
    if method.upper() in ["GET", "HEAD", "OPTIONS"]:
        return user.permissions.pull
    elif method.upper() in ["POST", "PUT", "PATCH", "DELETE"]:
        return user.permissions.push
    else:
        return False
