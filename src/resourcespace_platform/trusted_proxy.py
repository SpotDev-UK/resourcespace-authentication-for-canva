"""Trusted-proxy helpers for client IP extraction."""
from __future__ import annotations

import ipaddress


def host_matches_trusted_proxy(host: str, patterns: list[str]) -> bool:
    """Return True when ``host`` (the transport peer) is a trusted proxy."""
    if not host or not patterns:
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host in patterns

    for pattern in patterns:
        if not pattern:
            continue
        try:
            if "/" in pattern:
                if address in ipaddress.ip_network(pattern, strict=False):
                    return True
            elif address == ipaddress.ip_address(pattern):
                return True
        except ValueError:
            if host == pattern:
                return True
    return False


def client_ip_from_x_forwarded_for(raw: str, trusted_proxies: list[str]) -> str | None:
    """Return the client IP from an ``X-Forwarded-For`` value.

    Walks the comma-separated chain right-to-left and returns the first hop
    that is not a trusted proxy. This resists spoofing when an edge proxy
    appends ``$remote_addr`` to an existing client-supplied header (nginx
    ``$proxy_add_x_forwarded_for``).
    """
    hops = [part.strip() for part in raw.split(",") if part.strip()]
    for hop in reversed(hops):
        if not host_matches_trusted_proxy(hop, trusted_proxies):
            return hop
    return None
