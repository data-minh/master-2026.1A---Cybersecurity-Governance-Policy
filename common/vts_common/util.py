"""Small shared helpers used across services."""
from __future__ import annotations

from urllib.parse import urlparse


def host_from_url(url: str) -> str:
    """Return the bare hostname of a URL (no scheme/port/userinfo/path).

    Centralised so every service parses targets the same way before a scope
    check (previously some services used ad-hoc string splitting). Falls back to
    a best-effort parse when the URL has no scheme.
    """
    if not url:
        return ""
    parsed = urlparse(url if "://" in url else f"//{url}", scheme="http")
    return (parsed.hostname or "").lower()
