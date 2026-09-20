"""Network safety checks for the optional public scanning API.

The CLI is intentionally able to inspect operator-supplied internal hosts.
The HTTP API is different: when deployed, it must not become a proxy for
requests to an operator's private network.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


class UnsafeTargetError(ValueError):
    """Raised when an API target is not safe for public fetching."""


def validate_public_http_url(url: str) -> None:
    """Reject non-HTTP URLs and names resolving to non-public addresses.

    This is deliberately used only by the API.  It resolves every address a
    hostname currently has and rejects the target unless all are globally
    routable.  Deployments should also keep normal network egress controls in
    place as defence in depth against DNS rebinding.
    """
    parsed = urlparse(url)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise UnsafeTargetError("Only http and https targets are allowed.")
    if not parsed.hostname or parsed.username or parsed.password:
        raise UnsafeTargetError("Target must contain a hostname without credentials.")

    try:
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        addresses = {
            item[4][0]
            for item in socket.getaddrinfo(
                parsed.hostname, port, type=socket.SOCK_STREAM
            )
        }
    except (socket.gaierror, ValueError) as exc:
        raise UnsafeTargetError("Target hostname could not be resolved.") from exc

    if not addresses:
        raise UnsafeTargetError("Target hostname could not be resolved.")

    for address in addresses:
        if not ipaddress.ip_address(address).is_global:
            raise UnsafeTargetError("Private, local, and reserved targets are blocked.")
