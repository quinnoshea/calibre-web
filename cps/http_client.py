from __future__ import annotations

import ipaddress
import socket
from typing import Iterable, Optional, Tuple
from urllib.parse import urlparse

import requests

# Tolerate standalone import (e.g., tests), where cps.__init__ may pull Flask.
try:
    from . import logger as _cps_logger
    log = _cps_logger.create()
except Exception:  # pragma: no cover - fallback for test environments without Flask
    import logging
    log = logging.getLogger("cps.http_client")


class SafeRequestError(Exception):
    """Raised when a request is blocked or otherwise deemed unsafe."""


def _is_ip_private(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        return False


def _resolve_host(host: str) -> Iterable[str]:
    """Resolve a hostname to one or more IP addresses (string form).

    IDNA/punycode is handled implicitly by getaddrinfo.
    """
    try:
        infos = socket.getaddrinfo(host, None)
        for family, _, _, _, sockaddr in infos:
            if family == socket.AF_INET:
                yield sockaddr[0]
            elif family == socket.AF_INET6:
                yield sockaddr[0]
    except socket.gaierror:
        # Unresolvable host
        return []


def _host_in_allowlist(host: str, allowlist: Iterable[str]) -> bool:
    host = host.lower().rstrip(".")
    for allowed in allowlist:
        allowed = allowed.lower().strip().rstrip(".")
        if not allowed:
            continue
        if host == allowed or host.endswith("." + allowed):
            return True
    return False


def _validate_and_normalize_url(
    url: str,
    allowed_schemes: Tuple[str, ...] = ("http", "https"),
) -> Tuple[str, str, int, str]:
    """Validate basic URL structure and return (scheme, host, port, path).

    Raises SafeRequestError when invalid.
    """
    if not url:
        raise SafeRequestError("Empty URL")
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in allowed_schemes:
        raise SafeRequestError(f"Disallowed scheme: {scheme or '<none>'}")

    if not parsed.netloc or "@" in parsed.netloc:
        # Disallow userinfo and require host
        raise SafeRequestError("URL must contain a hostname without credentials")

    host = parsed.hostname or ""
    if not host:
        raise SafeRequestError("Missing hostname")

    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError:
        raise SafeRequestError("Invalid port in URL")

    path = parsed.path or "/"
    if len(path) > 4096:
        raise SafeRequestError("Path too long")

    return scheme, host, port, path


def is_blocked_destination(
    url: str,
    *,
    allowed_hosts: Optional[Iterable[str]] = None,
    allowed_schemes: Tuple[str, ...] = ("http", "https"),
) -> Tuple[bool, str]:
    """Return (blocked, reason) for a URL based on SSRF rules and allowlist.

    This function performs no network I/O beyond DNS resolution.
    """
    try:
        scheme, host, _, _ = _validate_and_normalize_url(url, allowed_schemes)
    except SafeRequestError as e:
        return True, str(e)

    # Literal IP check
    try:
        if _is_ip_private(host):
            return True, f"Blocked private/loopback IP literal: {host}"
    except Exception:
        pass

    # Resolve host and disallow private ranges
    ips = list(_resolve_host(host))
    if not ips:
        return True, f"Unresolvable host: {host}"
    for ip in ips:
        if _is_ip_private(ip):
            return True, f"Blocked private/loopback destination: {host} -> {ip}"

    # Optional host allowlist
    if allowed_hosts is not None and not _host_in_allowlist(host, allowed_hosts):
        return True, f"Host not in allowlist: {host}"

    # Scheme check (redundant; kept for clarity)
    if scheme not in allowed_schemes:
        return True, f"Disallowed scheme: {scheme}"

    return False, "ok"


def safe_request(
    url: str,
    *,
    method: str = "GET",
    headers: Optional[dict] = None,
    params: Optional[dict] = None,
    data: Optional[dict] = None,
    json: Optional[dict] = None,
    timeout: Tuple[int, int] = (10, 20),
    allow_redirects: bool = False,
    max_bytes: int = 2 * 1024 * 1024,
    allowed_hosts: Optional[Iterable[str]] = None,
    allowed_schemes: Tuple[str, ...] = ("http", "https"),
) -> requests.Response:
    """Perform an HTTP request with SSRF and size protections.

    - Blocks private/link-local/loopback/reserved destinations and unresolvable hosts.
    - Optionally enforces a host allowlist.
    - Disables redirects by default; if enabled, the caller should re-validate
      each Location target before following.
    - Enforces a max content size via Content-Length when available; callers
      should still stream and bound reads.
    """
    blocked, reason = is_blocked_destination(url, allowed_hosts=allowed_hosts, allowed_schemes=allowed_schemes)
    if blocked:
        log.warning("safe_request: blocked URL '%s' (%s)", url, reason)
        raise SafeRequestError(reason)

    hdrs = {"User-Agent": "Calibre-Web/safe_request"}
    if headers:
        hdrs.update(headers)

    resp = requests.request(
        method=method.upper(),
        url=url,
        headers=hdrs,
        params=params,
        data=data,
        json=json,
        timeout=timeout,
        allow_redirects=False,  # we handle redirects explicitly below
        stream=True,
    )

    # If caller asked for redirects, validate the target first and let them re-call
    if allow_redirects and 300 <= resp.status_code < 400 and resp.headers.get("Location"):
        location = resp.headers.get("Location")
        b, r = is_blocked_destination(location, allowed_hosts=allowed_hosts, allowed_schemes=allowed_schemes)
        if b:
            resp.close()
            raise SafeRequestError(f"Blocked redirect target: {r}")

    # Enforce simple size cap via Content-Length when present
    try:
        cl = int(resp.headers.get("Content-Length", "0"))
        if cl and cl > max_bytes:
            resp.close()
            raise SafeRequestError(f"Response too large: {cl} bytes > {max_bytes}")
    except ValueError:
        pass

    return resp


def fetch_bytes(
    url: str,
    *,
    method: str = "GET",
    max_bytes: int = 2 * 1024 * 1024,
    **kwargs,
) -> bytes:
    """Fetch a small resource as bytes under strict limits.

    Returns bytes or raises SafeRequestError.
    """
    resp = safe_request(url, method=method, max_bytes=max_bytes, **kwargs)
    try:
        total = 0
        chunks = []
        for chunk in resp.iter_content(chunk_size=64 * 1024):
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise SafeRequestError(f"Response exceeded max_bytes {max_bytes}")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        resp.close()


# Predefined allowlists for trusted domains by service type
METADATA_PROVIDER_ALLOWLIST = [
    "www.googleapis.com",
    "books.google.com",
    "www.goodreads.com",
    "comicvine.gamespot.com",
    "lubimyczytac.pl",
    "www.lubimyczytac.pl",
    "www.douban.com",
    "frodo.douban.com",
    "img2.doubanio.com",
    "img1.doubanio.com",
    "img3.doubanio.com",
    "www.amazon.com",
    "images-na.ssl-images-amazon.com",
    "m.media-amazon.com",
]

GITHUB_ALLOWLIST = [
    "api.github.com",
    "github.com",
]

GOOGLE_DRIVE_ALLOWLIST = [
    "drive.google.com",
    "docs.google.com",
]

# Combined allowlist for backward compatibility
DEFAULT_ALLOWLIST = METADATA_PROVIDER_ALLOWLIST + GITHUB_ALLOWLIST + GOOGLE_DRIVE_ALLOWLIST


def safe_metadata_request(*args, **kwargs):
    """Safe request for metadata providers with predefined allowlist."""
    kwargs.setdefault("allowed_hosts", METADATA_PROVIDER_ALLOWLIST)
    return safe_request(*args, **kwargs)


def safe_github_request(*args, **kwargs):
    """Safe request for GitHub API with predefined allowlist."""
    kwargs.setdefault("allowed_hosts", GITHUB_ALLOWLIST)
    return safe_request(*args, **kwargs)


def safe_gdrive_request(*args, **kwargs):
    """Safe request for Google Drive with predefined allowlist."""
    kwargs.setdefault("allowed_hosts", GOOGLE_DRIVE_ALLOWLIST)
    return safe_request(*args, **kwargs)


# Usage example (documented only; do not import here to avoid cycles):
# from cps.http_client import fetch_bytes, safe_metadata_request
# data = fetch_bytes("https://covers.example.com/cover.jpg", allowed_hosts=["covers.example.com"])
# resp = safe_metadata_request("https://www.googleapis.com/books/v1/volumes", params={"q": "title"})
