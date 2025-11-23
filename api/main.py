import base64
import logging
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import StreamingResponse

from api.config import config
from api.services.auth import check_repository_access, get_user_permissions
from api.views.auth import router as auth_router

logger = logging.getLogger("uvicorn.error")


client = httpx.AsyncClient(
    timeout=httpx.Timeout(300.0, connect=60.0),
    limits=httpx.Limits(max_keepalive_connections=20, max_connections=100),
    follow_redirects=False,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    yield
    # Shutdown
    await client.aclose()


app = FastAPI(title="Git LFS Proxy", lifespan=lifespan)


app.include_router(
    auth_router,
    prefix="/auth",
    tags=["Authentication"],
)


async def proxy_request(request: Request, method: str, path: str, query_params: str | None = None) -> Response:
    """
    Generic proxy function that forwards requests to the backend LFS server.
    """
    client_ip = request.client.host if request.client else "unknown"

    url = f"{config.LFS_SERVER_HOST}/{path.lstrip('/')}"
    if query_params:
        url = f"{url}?{query_params}"

    logger.info(f"Incoming request: {method} {path} from {client_ip}")
    logger.debug(f"Full URL: {url}")
    logger.debug(f"Request headers: {dict(request.headers)}")

    headers = dict(request.headers)
    headers.pop("host", None)

    if "accept" not in headers:
        headers["accept"] = "application/vnd.git-lfs+json"

    async def request_body():
        async for chunk in request.stream():
            yield chunk

    try:
        backend_response = await client.request(
            method=method,
            url=url,
            headers=headers,
            content=request_body(),
        )

        response_headers = dict(backend_response.headers)
        hop_by_hop_headers = [
            "connection",
            "keep-alive",
            "proxy-authenticate",
            "proxy-authorization",
            "te",
            "trailers",
            "transfer-encoding",
            "upgrade",
        ]
        for header in hop_by_hop_headers:
            response_headers.pop(header, None)

        logger.info(f"Response: {backend_response.status_code} for {method} {path} from {client_ip}")
        logger.debug(f"Response headers: {response_headers}")

        async def response_stream():
            async for chunk in backend_response.aiter_bytes():
                yield chunk

        return StreamingResponse(
            response_stream(),
            status_code=backend_response.status_code,
            headers=response_headers,
            media_type=response_headers.get("content-type"),
        )

    except Exception as e:
        logger.error(f"Error proxying request {method} {path} from {client_ip}: {str(e)}")
        return Response(content="Internal Server Error", status_code=500)


@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "HEAD", "PATCH", "DELETE", "OPTIONS"])
async def proxy_all(request: Request, full_path: str):
    """
    Catch-all route that proxies all HTTP methods to the backend.
    This handles all Git LFS API endpoints generically with GitHub authentication.
    """
    path_parts = full_path.strip("/").split("/")
    if len(path_parts) < 3 or path_parts[0] != "api":
        raise HTTPException(status_code=404, detail="Not Found")

    owner = path_parts[1]
    repo = path_parts[2]

    # Extract username and token from HTTP Basic Authentication
    username = None
    token = None
    auth_header = request.headers.get("authorization")

    if auth_header and auth_header.startswith("Basic "):
        try:
            # Decode Base64 credentials
            encoded_credentials = auth_header[6:]  # Remove "Basic " prefix
            decoded_credentials = base64.b64decode(encoded_credentials).decode("utf-8")
            username, token = decoded_credentials.split(":", 1)
        except (ValueError, UnicodeDecodeError):
            # Invalid Basic Auth format
            pass

    if not username or not token:
        logger.info(
            f"Unauthorized access attempt to {owner}/{repo} from {request.client.host if request.client else 'unknown'}"
        )
        return Response(
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="Git LFS Repository"'},
        )

    permissions = await get_user_permissions(username, token, owner, repo)

    if not check_repository_access(request.method, permissions):
        raise HTTPException(
            status_code=403, detail=f"Insufficient permissions to {request.method.upper()} in {owner}/{repo}"
        )

    query_string = str(request.query_params) if request.query_params else None

    return await proxy_request(request=request, method=request.method, path=full_path, query_params=query_string)
