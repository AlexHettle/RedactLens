"""Browser-to-localhost security boundary for RedactLens's API.

The browser is not automatically trusted merely because the server binds to
loopback. A hostile website can still send requests to localhost, and DNS
rebinding can produce an attacker-controlled Host header. This module keeps
those checks in one place and never records request bodies or authorization
tokens in diagnostics.
"""

from __future__ import annotations

import os
import re
import secrets
from dataclasses import dataclass, field

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

AUTH_HEADER = "X-RedactLens-Token"
DEFAULT_MAX_REQUEST_BYTES = 256 * 1024
MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
API_PORTS = frozenset(range(8000, 8011))
DEVELOPMENT_ORIGINS = frozenset(
    {
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    }
)
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; base-uri 'none'; connect-src 'self'; font-src 'self'; "
    "form-action 'self'; frame-ancestors 'none'; img-src 'self' data:; "
    "object-src 'none'; script-src 'self'; style-src 'self'; "
    "style-src-attr 'unsafe-inline'"
)
ANTI_FRAMING_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Frame-Options": "DENY",
}
_HOST_AUTHORITY = re.compile(
    r"(?P<host>localhost|127\.0\.0\.1|\[::1\]):(?P<port>[0-9]{4})",
    flags=re.ASCII | re.IGNORECASE,
)


def _positive_int_from_environment(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


@dataclass(frozen=True)
class LaunchSecurity:
    """Security state generated once for the lifetime of one API process."""

    token: str = field(repr=False)
    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES

    @classmethod
    def from_environment(cls) -> LaunchSecurity:
        return cls(
            token=secrets.token_urlsafe(32),
            max_request_bytes=_positive_int_from_environment(
                "REDACTLENS_MAX_REQUEST_BYTES",
                DEFAULT_MAX_REQUEST_BYTES,
            ),
        )


def api_error(
    status_code: int,
    code: str,
    message: str,
    *,
    extra_headers: dict[str, str] | None = None,
) -> JSONResponse:
    """Return the stable error shape without echoing untrusted request data."""

    headers = {
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        **ANTI_FRAMING_HEADERS,
    }
    if extra_headers is not None:
        headers.update(extra_headers)
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": message}},
        headers=headers,
    )


def _host_parts(host_header: str) -> tuple[str | None, int | None]:
    match = _HOST_AUTHORITY.fullmatch(host_header)
    if match is None:
        return None, None

    authority_host = match.group("host").lower()
    port = int(match.group("port"))
    if port not in API_PORTS:
        return None, None
    hostname = "::1" if authority_host == "[::1]" else authority_host
    return hostname, port


def _allowed_host(host_header: str) -> bool:
    hostname, port = _host_parts(host_header)
    return hostname in LOOPBACK_HOSTS and port in API_PORTS


def _allowed_origin(origin: str, host_header: str) -> bool:
    if origin in DEVELOPMENT_ORIGINS:
        return True
    hostname, port = _host_parts(host_header)
    if hostname not in LOOPBACK_HOSTS or port not in API_PORTS:
        return False
    authority_host = f"[{hostname}]" if hostname == "::1" else hostname
    return origin == f"http://{authority_host}:{port}"


class SecurityBoundaryMiddleware:
    """Reject forged browser requests before they reach an endpoint."""

    def __init__(self, app: ASGIApp, *, security: LaunchSecurity) -> None:
        self.app = app
        self.security = security

    @staticmethod
    def _cors_error_headers(origin: str | None, host: str) -> dict[str, str] | None:
        """Allow an approved frontend to read errors produced at this boundary."""

        if origin is None or not _allowed_host(host) or not _allowed_origin(origin, host):
            return None
        return {
            "Access-Control-Allow-Origin": origin,
            "Vary": "Origin",
        }

    async def _reject(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
        *,
        status_code: int,
        code: str,
        message: str,
        origin: str | None = None,
        host: str = "",
    ) -> None:
        await api_error(
            status_code,
            code,
            message,
            extra_headers=self._cors_error_headers(origin, host),
        )(scope, receive, send)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)
        host = request.headers.get("host", "")
        if not _allowed_host(host):
            await self._reject(
                scope,
                receive,
                send,
                status_code=400,
                code="invalid_host",
                message="RedactLens only accepts loopback requests.",
            )
            return

        origin = request.headers.get("origin")
        if origin is not None and not _allowed_origin(origin, host):
            await self._reject(
                scope,
                receive,
                send,
                status_code=403,
                code="invalid_origin",
                message="This browser origin is not allowed to control RedactLens.",
            )
            return
        if origin is None and request.headers.get("sec-fetch-site") == "cross-site":
            await self._reject(
                scope,
                receive,
                send,
                status_code=403,
                code="invalid_origin",
                message="Cross-site browser requests are not allowed to control RedactLens.",
            )
            return

        replay_receive = receive
        if request.method in MUTATING_METHODS:
            supplied = request.headers.get(AUTH_HEADER, "")
            try:
                supplied_bytes = supplied.encode("ascii")
            except UnicodeEncodeError:
                supplied_bytes = b""
            if not supplied_bytes or not secrets.compare_digest(
                supplied_bytes,
                self.security.token.encode("ascii"),
            ):
                await self._reject(
                    scope,
                    receive,
                    send,
                    status_code=403,
                    code="invalid_launch_token",
                    message="Reload RedactLens to establish a valid local session.",
                    origin=origin,
                    host=host,
                )
                return

            content_length = request.headers.get("content-length")
            if content_length is not None:
                try:
                    declared_bytes = int(content_length)
                except ValueError:
                    await self._reject(
                        scope,
                        receive,
                        send,
                        status_code=400,
                        code="invalid_request",
                        message="The request size is invalid.",
                        origin=origin,
                        host=host,
                    )
                    return
                if declared_bytes < 0:
                    await self._reject(
                        scope,
                        receive,
                        send,
                        status_code=400,
                        code="invalid_request",
                        message="The request size is invalid.",
                        origin=origin,
                        host=host,
                    )
                    return
                if declared_bytes > self.security.max_request_bytes:
                    await self._reject(
                        scope,
                        receive,
                        send,
                        status_code=413,
                        code="request_too_large",
                        message="The request is larger than RedactLens accepts.",
                        origin=origin,
                        host=host,
                    )
                    return

            chunks: list[bytes] = []
            received_bytes = 0
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    await self._reject(
                        scope,
                        receive,
                        send,
                        status_code=400,
                        code="invalid_request",
                        message="The request was interrupted.",
                        origin=origin,
                        host=host,
                    )
                    return
                chunk = message.get("body", b"")
                received_bytes += len(chunk)
                if received_bytes > self.security.max_request_bytes:
                    await self._reject(
                        scope,
                        receive,
                        send,
                        status_code=413,
                        code="request_too_large",
                        message="The request is larger than RedactLens accepts.",
                        origin=origin,
                        host=host,
                    )
                    return
                chunks.append(chunk)
                if not message.get("more_body", False):
                    break

            body = b"".join(chunks)
            replayed = False

            async def replay_body() -> Message:
                nonlocal replayed
                if replayed:
                    return {"type": "http.request", "body": b"", "more_body": False}
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}

            replay_receive = replay_body

        async def secure_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in ANTI_FRAMING_HEADERS.items():
                    headers.setdefault(name, value)
                if request.url.path.startswith(("/scans", "/pick-path", "/launch-session")):
                    headers.setdefault("Cache-Control", "no-store")
                    headers.setdefault("X-Content-Type-Options", "nosniff")
            await send(message)

        await self.app(scope, replay_receive, secure_headers)
