"""Bounded, redirect-free HTTP transport for intelligence providers."""

from __future__ import annotations

import ipaddress
import json
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlsplit

from .types import ProviderAuthError, ProviderError, ProviderTimeoutError


@dataclass(frozen=True)
class HttpResponse:
    status: int
    body: bytes
    headers: dict[str, str]
    latency_ms: float


class TransportError(ProviderError):
    code = "PROVIDER_TRANSPORT_ERROR"
    recoverable = True


class ResponseTooLargeError(ProviderError):
    code = "PROVIDER_RESPONSE_TOO_LARGE"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def http_error_301(self, req, fp, code, msg, headers):  # noqa: N802
        raise TransportError("provider redirects are not allowed", details={"status": int(code)})

    http_error_302 = http_error_301
    http_error_303 = http_error_301
    http_error_307 = http_error_301
    http_error_308 = http_error_301


def _is_loopback(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def _is_private(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        # A resolver must return literal addresses. Treat malformed results as
        # unsafe rather than allowing a test double or unusual resolver to
        # bypass the SSRF check.
        return True
    # ``is_private`` does not cover every non-routable/special-use range
    # (notably some shared/documentation ranges).  Cloud provider requests
    # must resolve only to globally routable addresses; local loopback is the
    # sole exception and is checked by the caller.
    return not ip.is_global


def _origin(url: str) -> str:
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower()
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        raise TransportError("provider URL is malformed") from None
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    if (parsed.scheme == "https" and port == 443) or (parsed.scheme == "http" and port == 80):
        return f"{parsed.scheme}://{host}"
    return f"{parsed.scheme}://{host}:{port}"


class JsonHttpTransport:
    """POST JSON with DNS/redirect/size/deadline safeguards.

    Tests can inject ``opener`` and ``resolver``; production never logs the
    body or response bytes.
    """

    def __init__(
        self,
        *,
        opener: Any | None = None,
        resolver: Callable[..., Any] | None = None,
        open_fn: Callable[..., Any] | None = None,
    ) -> None:
        self._opener = opener or urllib.request.build_opener(_NoRedirect())
        self._resolver = resolver or socket.getaddrinfo
        self._open_fn = open_fn

    def _validate_and_resolve(self, url: str, *, local_http: bool) -> None:
        try:
            parsed = urlsplit(url)
            host = parsed.hostname or ""
        except ValueError:
            raise TransportError("provider URL is malformed") from None
        if not host:
            raise TransportError("provider URL has no host")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise TransportError("provider URL contains credentials or query data")
        path = parsed.path or "/"
        if not path.startswith("/") or "//" in path or any(
            part in {".", ".."} for part in path.split("/")[1:]
        ):
            raise TransportError("provider URL path is malformed")
        if parsed.scheme not in {"http", "https"}:
            raise TransportError("provider URL must use http or https")
        if parsed.scheme == "http" and not (local_http and _is_loopback(host)):
            raise TransportError("HTTP provider connections are restricted to loopback")
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            if not 1 <= int(port) <= 65535:
                raise ValueError
        except ValueError:
            raise TransportError("provider URL has an invalid port") from None
        try:
            addresses = self._resolver(host, port, type=socket.SOCK_STREAM)
        except TypeError:
            # Small test doubles often expose the older two-argument shape.
            try:
                addresses = self._resolver(host, port)
            except OSError:
                raise TransportError("provider hostname could not be resolved") from None
        except OSError:
            raise TransportError("provider hostname could not be resolved") from None
        if not addresses:
            raise TransportError("provider hostname resolved to no addresses")
        for item in addresses:
            try:
                address = str(item[4][0])
            except (IndexError, TypeError):
                raise TransportError("provider DNS resolution returned malformed data") from None
            if parsed.scheme == "http":
                if not (local_http and _is_loopback(address)):
                    raise TransportError("HTTP provider connections are restricted to loopback")
            elif _is_private(address):
                raise TransportError("provider hostname resolved to a private or special-use address")

    def post_json(
        self,
        url: str,
        payload: dict[str, Any],
        *,
        headers: dict[str, str] | None = None,
        timeout_seconds: float = 60.0,
        max_response_bytes: int = 1_048_576,
        local_http: bool = False,
        allowed_origins: tuple[str, ...] | list[str] = (),
    ) -> HttpResponse:
        origin = _origin(url)
        if allowed_origins:
            try:
                allowed = {_origin(str(item)) for item in allowed_origins}
            except (ProviderError, ValueError):
                raise TransportError("provider origin allowlist is malformed") from None
            if origin not in allowed:
                raise TransportError("provider URL is not in the configured origin allowlist")
        self._validate_and_resolve(url, local_http=local_http)
        # Resolve again immediately before opening the socket. urllib does not
        # expose a portable way to pin the connected socket to the first DNS
        # answer; this second check closes the common safe-first/private-second
        # rebinding case and keeps redirect handling fail-closed.
        self._validate_and_resolve(url, local_http=local_http)
        try:
            body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        except (TypeError, ValueError):
            raise TransportError("provider request could not be encoded") from None
        if len(body) > 1_000_000:
            raise TransportError("provider request exceeds the transport limit")
        request_headers = {"Content-Type": "application/json", "Accept": "application/json"}
        for key, value in (headers or {}).items():
            if any(ord(char) < 0x20 for char in str(key)) or any(ord(char) < 0x20 for char in str(value)):
                raise TransportError("provider request header is malformed")
            request_headers[str(key)] = str(value)
        request = urllib.request.Request(url, data=body, headers=request_headers, method="POST")
        started = time.monotonic()
        deadline = started + max(0.1, float(timeout_seconds))
        try:
            opener = self._open_fn or self._opener.open
            response = opener(request, timeout=max(0.1, deadline - time.monotonic()))
            try:
                get_url = getattr(response, "geturl", None)
                response_url = get_url() if callable(get_url) else url
                if response_url and _origin(str(response_url)) != origin:
                    raise TransportError("provider redirects across origins are not allowed")
                raw = response.read(int(max_response_bytes) + 1)
                status = int(getattr(response, "status", getattr(response, "code", 200)))
                headers_out = {str(k).lower(): str(v) for k, v in getattr(response, "headers", {}).items()}
            finally:
                close = getattr(response, "close", None)
                if callable(close):
                    close()
        except urllib.error.HTTPError as exc:
            # Do not read or retain the error body: upstream responses can
            # reflect secrets or supplied binary context.
            if int(getattr(exc, "code", 0) or 0) in {408, 429, 500, 502, 503, 504, 529}:
                raise TransportError("provider returned a retryable HTTP status", details={"status": int(exc.code)}) from None
            if int(getattr(exc, "code", 0) or 0) in {401, 403}:
                raise ProviderAuthError("provider authentication was rejected", details={"status": int(exc.code)}) from None
            raise TransportError("provider returned an HTTP error", details={"status": int(exc.code)}) from None
        except TimeoutError:
            raise ProviderTimeoutError("provider request timed out") from None
        except urllib.error.URLError as exc:
            reason = str(getattr(exc, "reason", ""))
            if "timed out" in reason.lower() or "timeout" in reason.lower():
                raise ProviderTimeoutError("provider request timed out") from None
            raise TransportError("provider connection failed") from None
        except OSError:
            raise TransportError("provider connection failed") from None
        if len(raw) > int(max_response_bytes):
            raise ResponseTooLargeError("provider response exceeds the configured limit")
        if status in {401, 403}:
            raise ProviderAuthError("provider authentication was rejected", details={"status": status})
        if status in {408, 429, 500, 502, 503, 504, 529}:
            raise TransportError("provider returned a retryable HTTP status", details={"status": status})
        if status >= 400:
            raise TransportError("provider returned an HTTP error", details={"status": status})
        if time.monotonic() > deadline:
            raise ProviderTimeoutError("provider request exceeded its deadline")
        return HttpResponse(
            status=status,
            body=bytes(raw),
            headers=headers_out,
            latency_ms=(time.monotonic() - started) * 1000.0,
        )
