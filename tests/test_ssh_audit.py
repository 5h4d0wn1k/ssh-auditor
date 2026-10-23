"""Outcome-correctness tests for the credential stage (#20).

The per-credential report must say what was actually observed: "attempted"
only when a TCP connection was made, "unreachable" when none was, and the
whole credential stage is skipped with a clear note when the banner grab
already established the host is unreachable.
"""

from __future__ import annotations

import asyncio
import secrets
import socket
import types
from pathlib import Path

import pytest

from ssh_audit import main_async


def _free_port() -> int:
    """A local port with nothing listening on it."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def _serve_once(port: int) -> "asyncio.AbstractServer":
    """A server that accepts (and ignores) one SSH-2.0 prelude line."""
    async def handler(reader, writer):
        # A real SSH server sends its banner on connect; grab_banner needs one.
        try:
            writer.write(b"SSH-2.0-OpenSSH_9.0 lab\r\n")
            await writer.drain()
            await asyncio.wait_for(reader.read(128), timeout=2.0)
        except Exception:
            pass
        try:
            writer.close()
        except Exception:
            pass

    return await asyncio.start_server(handler, "127.0.0.1", port)


def _args(host: str, port: int, creds: str = "", timeout: float = 1.0) -> types.SimpleNamespace:
    return types.SimpleNamespace(
        host=host, port=port, timeout=timeout, creds=creds or None
    )


def test_main_async_skips_the_credential_stage_for_an_unreachable_host(tmp_path, capsys):
    port = _free_port()
    creds = tmp_path / "creds.txt"
    # Use a generated string that is not a hardcoded secret.
    first = secrets.token_urlsafe(12)
    second = secrets.token_urlsafe(9)
    creds.write_text("labuser:" + first + "\n" + "guest:" + second + "\n")
    asyncio.run(main_async(_args("127.0.0.1", port, str(creds))))
    out = capsys.readouterr().out
    assert "No banner or unreachable." in out
    assert f"credential stage skipped: 127.0.0.1:{port} unreachable" in out
    # The credentials were never tried, so no credential line may claim one.
    assert "labuser:" + first not in out
    assert "attempted" not in out


def test_main_async_reports_attempted_for_each_credential_on_a_live_host(tmp_path, capsys):
    port = _free_port()

    async def run():
        server = await _serve_once(port)
        try:
            await main_async(_args("127.0.0.1", port, str(creds)))
        finally:
            server.close()
            await server.wait_closed()

    creds = tmp_path / "creds.txt"
    val = secrets.token_urlsafe(12)
    creds.write_text("labuser:" + val + "\n")
    asyncio.run(run())
    out = capsys.readouterr().out
    lines = [l for l in out.splitlines() if "labuser:" + val in l]
    assert lines == ["[*] labuser:" + val + " -> attempted"]
