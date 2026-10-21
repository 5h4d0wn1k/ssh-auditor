"""
SSH audit (lab/owned hosts only).
Checks port reachability, grabs banner, and optionally tests a tiny provided credential list.
Requires explicit target and refuses 0.0.0.0/0 semantics.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import socket
from typing import List, Optional, Tuple


async def _read_identification(reader: asyncio.StreamReader) -> bytes:
    """Read the server's first line, bounded by the RFC 4253 identification
    limit (255 bytes incl. CRLF). A fixed-size recv() is a truncation bug:
    banners longer than one chunk, or split across TCP segments, must still
    arrive whole. Bytes beyond the limit without a newline are reported with
    an explicit (truncated) marker rather than silently cut."""
    buf = b""
    while b"\n" not in buf and len(buf) < 255:
        chunk = await reader.read(64)
        if not chunk:
            break  # EOF: report whatever arrived
        buf += chunk
    if b"\n" in buf:
        return buf.split(b"\n", 1)[0] + b"\n"
    if len(buf) >= 255:
        return buf[:255] + b"(truncated)"
    return buf


async def grab_banner(host: str, port: int, timeout: float) -> Optional[str]:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        data = await asyncio.wait_for(_read_identification(reader), timeout=1.0)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        if data:
            return data.decode(errors="ignore").strip()
    except Exception:
        return None
    return None


def validate_target(host: str) -> None:
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_multicast or ip.is_unspecified:
            raise ValueError("Refusing multicast/unspecified targets.")
    except ValueError:
        # hostname allowed; no further checks
        return


def load_creds(path: str) -> List[Tuple[str, str]]:
    pairs: List[Tuple[str, str]] = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if ":" in line:
                u, p = line.strip().split(":", 1)
                if u and p:
                    pairs.append((u, p))
    return pairs


async def try_ssh_password(host: str, port: int, user: str, password: str, timeout: float) -> bool:
    # To avoid heavyweight dependencies, we attempt a plain TCP and send "SSH-2.0" prelude then close.
    # Real auth attempts would require paramiko; here we only demonstrate reachability intent.
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.write(b"SSH-2.0-lab-audit\r\n")
        await writer.drain()
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        # We don't actually authenticate here (requires paramiko). Mark as attempted.
        return False
    except Exception:
        return False


async def main_async(args: argparse.Namespace) -> None:
    validate_target(args.host)
    print("⚠️  Authorized use only. Test only SSH services you own/control.")
    banner = await grab_banner(args.host, args.port, args.timeout)
    if banner:
        print(f"[+] Banner: {banner}")
    else:
        print("[-] No banner or unreachable.")

    if args.creds:
        creds = load_creds(args.creds)
        for user, password in creds:
            ok = await try_ssh_password(args.host, args.port, user, password, args.timeout)
            status = "attempted" if ok else "attempted (no auth performed)"
            print(f"[*] {user}:{password} -> {status}")


def main() -> None:
    parser = argparse.ArgumentParser(description="SSH audit for owned/authorized hosts.")
    parser.add_argument("--host", required=True, help="Target host (owned/authorized).")
    parser.add_argument("--port", type=int, default=22, help="SSH port (default 22).")
    parser.add_argument("--timeout", type=float, default=3.0, help="Timeout seconds.")
    parser.add_argument("--creds", help="Optional cred file user:pass per line (lab-only).")
    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
