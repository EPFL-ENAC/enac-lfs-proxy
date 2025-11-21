import logging
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import StreamingResponse

from .config import config

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


async def proxy_request(request: Request, method: str, path: str, query_params: str | None = None) -> Response:
    """
    Generic proxy function that forwards requests to the backend LFS server.
    """
    client_ip = request.client.host if request.client else "unknown"

    url = f"{config.LFS_SERVER_HOST.rstrip('/')}/{path.lstrip('/')}"
    if query_params:
        url = f"{url}?{query_params}"

    # Log incoming request
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
    This handles all Git LFS API endpoints generically.
    """
    query_string = str(request.query_params) if request.query_params else None

    return await proxy_request(request=request, method=request.method, path=full_path, query_params=query_string)
