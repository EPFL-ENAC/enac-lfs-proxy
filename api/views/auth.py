from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from jose import jwt

from api.auth import JWT_EXPIRY_SECONDS, get_user_with_repo_permissions, make_jwt
from api.config import config
from api.models.auth import User

router = APIRouter()


@router.get("/login")
async def login():
    """Redirects to the URL from which the user can initiate the GitHub OAuth2 login flow.

    Returns:
        A JSON response containing the URL to redirect the user to for GitHub authentication.
    """
    redirect_uri = f"{config.APP_URL}/auth/callback"
    params = {
        "client_id": config.GITHUB_CLIENT_ID,
        "redirect_uri": redirect_uri,  # e.g. https://your.app/auth/callback
        "scope": "read:user read:repo",
    }
    github_authorize_url = f"https://github.com/login/oauth/authorize?{urlencode(params)}"
    return {"url": github_authorize_url}


@router.get("/callback")
async def callback(code: str, response: Response):
    jwt_token = await make_jwt(code)

    response = RedirectResponse(url=f"{config.APP_URL}/auth/token")
    response.set_cookie(
        key="token",
        value=jwt_token,
        httponly=True,
        secure=True if config.APP_URL.startswith("https") else False,
        samesite="lax",
        max_age=JWT_EXPIRY_SECONDS,
    )
    return response


# @router.get("/userinfo")
# async def userinfo(request: Request):
#     """Get user info. Note: This endpoint doesn't include repository-specific permissions."""
#     from api.auth import get_user_with_repo_permissions

#     # For userinfo, we'll use the configured repo as default
#     # In a real scenario, you might want to handle this differently
#     token = request.cookies.get("token")
#     user = await get_user_with_repo_permissions(config.GITHUB_REPO_OWNER, config.GITHUB_REPO_NAME, token)
#     return user


@router.get("/token")
async def get_token(request: Request):
    """Display the user's GitHub token for use with Git LFS."""
    token = request.cookies.get("token")
    if not token:
        raise HTTPException(status_code=401, detail="No active session. Please log in first.")

    # Extract GitHub token from JWT
    try:
        decoded = jwt.decode(token, config.JWT_SECRET, issuer="mmsdb", algorithms=["HS256"])
        github_token = decoded.get("github_token")
        username = decoded.get("sub")
        full_name = decoded.get("full_name", username)

        if not github_token:
            raise HTTPException(status_code=401, detail="Invalid session. Please log in again.")

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expired. Please log in again.")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid session. Please log in again.")

    instructions = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Git LFS Authentication Setup</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }}
        .token {{ background: #f4f4f4; padding: 15px; border-radius: 5px; font-family: monospace; word-break: break-all; }}
        .instructions {{ background: #e8f4fd; padding: 15px; border-radius: 5px; border-left: 4px solid #007acc; }}
        .warning {{ background: #fff3cd; padding: 15px; border-radius: 5px; border-left: 4px solid #ffc107; }}
        code {{ background: #f4f4f4; padding: 2px 4px; border-radius: 3px; }}
        .url-example {{ background: #d4edda; padding: 10px; border-radius: 4px; font-family: monospace; }}
    </style>
</head>
<body>
    <h1>Git LFS Authentication Setup</h1>
    <p>Hello <strong>{full_name or username}</strong>! Here's how to set up authentication for Git LFS:</p>

    <div class="token">
        <strong>Your GitHub Token:</strong><br>
        {github_token}
    </div>

    <div class="instructions">
        <h3>How to authenticate with Git LFS:</h3>

        <p><strong>Method 1: Configure Git credentials (Recommended)</strong></p>
        <ol>
            <li>Configure Git to store credentials: <code>git config --global credential.helper store</code></li>
            <li>When Git asks for credentials during <code>git push</code> or <code>git pull</code>:
                <ul>
                    <li><strong>Username:</strong> {username}</li>
                    <li><strong>Password:</strong> (paste the token above)</li>
                </ul>
            </li>
        </ol>

        <p><strong>Method 2: Use credentials in URL</strong></p>
        <div class="url-example">
            git clone http://{username}:{github_token}@your-lfs-proxy-domain/api/owner/repo.git
        </div>

        <p><strong>Method 3: Set remote URL with credentials</strong></p>
        <ol>
            <li><code>git remote set-url origin http://{username}:{github_token}@your-lfs-proxy-domain/api/owner/repo.git</code></li>
            <li>Now you can use <code>git push</code> and <code>git pull</code> without entering credentials each time</li>
        </ol>
    </div>

    <div class="warning">
        <strong>Security Note:</strong> This token provides access to your GitHub repositories. Keep it secure and don't share it. If you believe it's been compromised, revoke it in your GitHub settings and generate a new one.
    </div>

    <p><a href="/auth/login">Get a new token</a> | <a href="/auth/logout">Log out</a></p>
</body>
</html>
    """

    return Response(content=instructions, media_type="text/html")


@router.get("/logout")
async def logout():
    """Log out by clearing the session cookie."""
    response = RedirectResponse(url=f"{config.APP_URL}")
    response.delete_cookie(key="token")
    return response


@router.delete("/session")
async def delete_session(request: Request):
    token = request.cookies.get("token")
    response = Response()
    if token:
        response.delete_cookie(key="token")
    return response
