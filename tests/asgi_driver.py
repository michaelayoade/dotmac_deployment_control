"""A minimal ASGI caller, so a browser test can plant a REAL request.

Starlette ships `TestClient`, and this repository deliberately does not use it:
`TestClient` needs `httpx`, `httpx` is a member of the `TRANSPORT_ROOTS` this
module's architecture guard exists to keep out, and adding it — even to the dev
group — would put a transport library in the dependency graph of the one
distribution whose defining property is that it performs no I/O. It would also
mean regenerating `poetry.lock` for a test helper.

So this drives the application object directly, which is what `TestClient`
ultimately does. It is a caller, never a server: no socket, no event loop
beyond `asyncio.run`, no lifespan. Routes are what these tests are about.

`stdlib only` is the whole design constraint. If this file ever needs a
dependency, the test it serves has outgrown the claim it is making.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode


@dataclass(frozen=True, slots=True)
class Response:
    """What the application sent back, flattened."""

    status: int
    headers: tuple[tuple[str, str], ...]
    body: bytes

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def header(self, name: str) -> str | None:
        wanted = name.lower()
        for key, value in self.headers:
            if key == wanted:
                return value
        return None


def call(
    app: Any,
    method: str,
    path: str,
    *,
    query: dict[str, str] | None = None,
    form: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
) -> Response:
    """Send one request into `app` and return what came out.

    Forms are sent `application/x-www-form-urlencoded`, which Starlette parses
    with the standard library. `multipart/form-data` would need
    `python-multipart`, and nothing in this surface uploads a file.
    """
    body = urlencode(form).encode("utf-8") if form is not None else b""
    urlencoded = "application/x-www-form-urlencoded"
    request_headers = {
        "host": "testserver",
        **(
            {}
            if form is None
            else {"content-type": urlencoded, "content-length": str(len(body))}
        ),
        **{key.lower(): value for key, value in (headers or {}).items()},
    }
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method.upper(),
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("utf-8"),
        "query_string": urlencode(query or {}).encode("utf-8"),
        "root_path": "",
        "headers": [
            (key.encode("latin-1"), value.encode("latin-1"))
            for key, value in request_headers.items()
        ],
        "client": ("127.0.0.1", 51234),
        "server": ("testserver", 80),
    }

    received: dict[str, Any] = {"status": 500, "headers": [], "body": b""}
    delivered = False

    async def receive() -> dict[str, Any]:
        nonlocal delivered
        if delivered:
            return {"type": "http.disconnect"}
        delivered = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.start":
            received["status"] = message["status"]
            received["headers"] = [
                (key.decode("latin-1").lower(), value.decode("latin-1"))
                for key, value in message.get("headers", [])
            ]
        elif message["type"] == "http.response.body":
            received["body"] += message.get("body", b"")

    asyncio.run(app(scope, receive, send))
    return Response(
        status=int(received["status"]),
        headers=tuple(received["headers"]),
        body=bytes(received["body"]),
    )
