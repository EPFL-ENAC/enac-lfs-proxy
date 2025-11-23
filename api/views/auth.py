from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import RedirectResponse

from api.config import config
from api.services.auth import generate_token

router = APIRouter()


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
