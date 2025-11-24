from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from api.config import config
from api.services.auth import clear_user_permissions_cache, generate_token

router = APIRouter()
security = HTTPBasic()


@router.get("/login")
async def login():
    """Redirects the user to the GitHub OAuth2 authorization page."""
    params = {
        "client_id": config.GITHUB_CLIENT_ID,
        "redirect_uri": f"{config.APP_URL}/auth/callback",
        "scope": "read:user read:repo",
    }
    github_authorize_url = f"https://github.com/login/oauth/authorize?{urlencode(params)}"
    return RedirectResponse(url=github_authorize_url)


@router.get("/callback")
async def callback(code: str):
    """Display the user's GitHub token for use with Git LFS."""
    token = await generate_token(code)
    return Response(
        content=f"Your GitHub token is:\n\n{token}\n\nUse this token as your password for Git LFS operations.",
        media_type="text/plain",
    )


@router.post("/clear_permissions_cache")
def clear_cache_endpoint(
    credentials: HTTPBasicCredentials = Depends(security),
):
    """Clear the user permissions cache. Requires HTTP Basic Auth with FULL_ACCESS_USERNAME and FULL_ACCESS_TOKEN."""
    if (
        config.FULL_ACCESS_USERNAME is None
        or config.FULL_ACCESS_TOKEN is None
        or credentials.username != config.FULL_ACCESS_USERNAME
        or credentials.password != config.FULL_ACCESS_TOKEN
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    clear_user_permissions_cache()
    return {"detail": "User permissions cache cleared."}
