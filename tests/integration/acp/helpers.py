"""
Shared test helpers for Stage 8.4 ACP integration tests.

Provides:
  UvicornThread      — run a FastAPI/ASGI app in a background daemon thread
  find_free_port     — ask the OS for an available ephemeral TCP port
  mint_exchange_token — mint a HS256 JWT for token-exchange tests
"""

from __future__ import annotations

import socket
import threading
import time
from typing import Optional

import jwt as pyjwt
import uvicorn


def find_free_port(host: str = "127.0.0.1") -> int:
    """Return an ephemeral port the OS has available on *host*.

    Uses SO_REUSEADDR to minimise the TOCTOU window between releasing the
    probe socket and uvicorn binding.  Suitable for test infrastructure on
    loopback; not appropriate for production use.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, 0))
        return s.getsockname()[1]


class UvicornThread(threading.Thread):
    """Run uvicorn in a background daemon thread.

    Usage::

        thread = UvicornThread(app, "127.0.0.1", find_free_port())
        thread.start()
        thread.wait_ready()   # blocks until the server accepts connections
        ...
        thread.stop()
    """

    def __init__(self, app, host: str, port: int) -> None:
        super().__init__(daemon=True)
        config = uvicorn.Config(app, host=host, port=port, log_level="warning")
        self.server = uvicorn.Server(config)
        self.host = host
        self.port = port

    def run(self) -> None:
        self.server.run()

    def stop(self) -> None:
        self.server.should_exit = True
        self.join(timeout=5)

    def wait_ready(self, timeout: float = 3.0) -> None:
        """Poll until the server is accepting connections or *timeout* expires."""
        import requests as _req

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                _req.get(f"http://{self.host}:{self.port}/docs", timeout=0.1)
                return
            except Exception:
                time.sleep(0.1)


def mint_exchange_token(
    sub: str,
    principal_kind: str = "human",
    agent_type: Optional[str] = None,
    act: Optional[dict] = None,
    ttl: int = 3600,
    *,
    secret: str,
    issuer: str,
) -> str:
    """Mint a HS256 JWT for token-exchange tests.

    Args:
        sub: Subject identifier.
        principal_kind: ``"human"`` or ``"agent"``.
        agent_type: Agent type string (e.g. ``"orchestrator"``); omitted if None.
        act: Pre-existing ``act`` claim dict; omitted if None.
        ttl: Token lifetime in seconds.
        secret: HMAC signing key.
        issuer: ``iss`` claim value.
    """
    now = int(time.time())
    payload: dict = {
        "sub": sub,
        "iss": issuer,
        "iat": now,
        "exp": now + ttl,
        "principal_kind": principal_kind,
    }
    if agent_type:
        payload["agent_type"] = agent_type
    if act:
        payload["act"] = act
    return pyjwt.encode(payload, secret, algorithm="HS256")
