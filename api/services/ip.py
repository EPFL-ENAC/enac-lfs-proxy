import ipaddress
import logging

from fastapi import HTTPException, Request

from api.config import config

ALLOWED_NETWORKS = [ipaddress.ip_network(cidr) for cidr in config.PUSH_IP_RANGES]


logger = logging.getLogger("uvicorn.error")


async def ensure_ip_allowed(request: Request):
    if not request.client:
        logger.warning("Request missing client information, denying access")
        raise HTTPException(status_code=403, detail="Missing client information")

    client_ip_str = request.client.host

    try:
        ip = ipaddress.ip_address(client_ip_str)
        if not any(ip in net for net in ALLOWED_NETWORKS):
            logger.warning(f"Access attempt from disallowed IP: {client_ip_str}")
            raise HTTPException(status_code=403, detail="IP address not allowed")
    except ValueError:
        logger.warning(f"Invalid client IP address: {client_ip_str}")
        raise HTTPException(status_code=403, detail="Invalid client IP address")
