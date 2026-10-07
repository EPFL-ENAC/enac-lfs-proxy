import base64
import logging
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import StreamingResponse
from starlette.background import BackgroundTask

from api.config import config
from api.models.auth import GitHubPermissions
from api.services.auth import check_repository_access, get_user_permissions
from api.services.ip import ensure_ip_allowed
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


@app.get("/healthz", tags=["Health"])
async def health_check():
    return {"status": "ok"}


async def proxy_request(request: Request, method: str, path: str, query_params: str | None = None) -> Response:
    """
    Generic proxy function that forwards requests to the backend LFS server.
    """
    client_ip = request.client.host if request.client else "unknown"

    url = f"{config.LFS_SERVER_HOST}/{path.lstrip('/')}"
    if query_params:
        url = f"{url}?{query_params}"

    logger.info(f"Proxying request: {method} {path} from {client_ip}")
    logger.debug(f"Full URL: {url}")
    logger.debug(f"Request headers: {dict(request.headers)}")

    # Hop-by-hop headers belong to the client's connection, not to the one to the backend.
    hop_by_hop = {"host", "connection", "keep-alive", "te", "trailers", "transfer-encoding", "upgrade"}
    headers = {k: v for k, v in request.headers.items() if k.lower() not in hop_by_hop}

    if "accept" not in headers:
        headers["accept"] = "application/vnd.git-lfs+json"

    async def request_body():
        async for chunk in request.stream():
            yield chunk

    try:
        # No body for GET/HEAD: an empty generator would go out as a chunked body.
        has_body = method.upper() not in ("GET", "HEAD", "OPTIONS")
        backend_request = client.build_request(
            method=method, url=url, headers=headers, content=request_body() if has_body else None
        )
        # stream=True: forward each object as it arrives, instead of holding it whole in memory.
        backend_response = await client.send(backend_request, stream=True)
    except Exception as e:
        logger.error(f"Error proxying request {method} {path} from {client_ip}: {e!r}")
        return Response(content="Internal Server Error", status_code=500)

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

    logger.info(f"Response from proxied service: {backend_response.status_code} for {method} {path} from {client_ip}")
    logger.debug(f"Response headers: {response_headers}")

    async def response_stream():
        sent = 0
        try:
            # Raw bytes: the Content-Length and Content-Encoding headers are passed on as they are.
            async for chunk in backend_response.aiter_raw():
                sent += len(chunk)
                yield chunk
        except Exception as e:
            # The 200 is already sent and logged: a body cut short only shows up here.
            logger.error(f"Body stream failed for {method} {path} from {client_ip} after {sent} bytes: {e!r}")
            raise

    return StreamingResponse(
        response_stream(),
        status_code=backend_response.status_code,
        headers=response_headers,
        media_type=response_headers.get("content-type"),
        background=BackgroundTask(backend_response.aclose),
    )


@app.api_route("/{full_path:path}", methods=["GET", "POST", "PUT", "HEAD", "PATCH", "DELETE", "OPTIONS"])
async def proxy_all(request: Request, full_path: str):
    """
    Catch-all route that proxies all HTTP methods to the backend.
    This handles all Git LFS API endpoints generically with GitHub authentication.
    The full access token always pass through. Other requests are filtered by IP and permissions.
    """
    logger.info(f"Received request for path: {full_path}")

    path_parts = full_path.strip("/").split("/")
    if len(path_parts) < 3 or path_parts[0] != "api":
        raise HTTPException(status_code=400, detail="Invalid path format")

    owner = path_parts[1]
    repo = path_parts[2]

    # Extract username and token from HTTP Basic Authentication
    username = None
    token = None
    auth_header = request.headers.get("authorization")

    scheme, _, encoded_credentials = (auth_header or "").partition(" ")
    # The scheme is case-insensitive (RFC 9110): git and actions/checkout send "basic".
    if scheme.lower() == "basic":
        try:
            # Decode Base64 credentials
            decoded_credentials = base64.b64decode(encoded_credentials).decode("utf-8")
            username, token = decoded_credentials.split(":", 1)
        except (ValueError, UnicodeDecodeError):
            logger.warning(
                f"Invalid Basic auth header format in access attempt to {owner}/{repo} from {request.client.host if request.client else 'unknown'}"
            )
            pass

    if not username or not token:
        logger.info(
            f"Missing basic auth info in access attempt to {owner}/{repo} from {request.client.host if request.client else 'unknown'}"
        )
        return Response(
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="Git LFS Repository"'},
        )

    # Admin access for internal API token
    if (
        config.FULL_ACCESS_USERNAME is not None
        and username == config.FULL_ACCESS_USERNAME
        and config.FULL_ACCESS_TOKEN is not None
        and token == config.FULL_ACCESS_TOKEN
    ):
        logger.info("Granting full access via internal API token")
        permissions = GitHubPermissions(pull=True, push=True, admin=True)
    else:
        await ensure_ip_allowed(request)
        permissions = await get_user_permissions(username, token, owner, repo)

    if not check_repository_access(request.method, permissions):
        logger.info(f"Forbidden access attempt to {owner}/{repo} by user {username} with insufficient permissions")
        raise HTTPException(
            status_code=403, detail=f"Insufficient permissions to {request.method.upper()} in {owner}/{repo}"
        )

    query_string = str(request.query_params) if request.query_params else None

    return await proxy_request(request=request, method=request.method, path=full_path, query_params=query_string)
