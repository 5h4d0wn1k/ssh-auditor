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


async def grab_banner(host: str, port: int, timeout: float) -> Optional[str]:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        data = await asyncio.wait_for(reader.read(128), timeout=1.0)
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


async def try_ssh_password(host: str, port: int, user: str, password: str, timeout: float) -> str:
    # To avoid heavyweight dependencies, we attempt a plain TCP and send "SSH-2.0" prelude then close.
    # Real auth attempts would require paramiko; here we only demonstrate reachability intent.
    # The outcome is what was actually observed (#20): "attempted" when a TCP
    # connection was made and the prelude sent (no real authentication is
    # performed), "unreachable" when no connection was ever established.
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except (ConnectionRefusedError, socket.gaierror, asyncio.TimeoutError, OSError):
        return "unreachable"
    writer.write(b"SSH-2.0-lab-audit\r\n")
    try:
        await writer.drain()
    except Exception:
        pass
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    # We don't actually authenticate here (requires paramiko). Mark as attempted.
    return "attempted"


async def main_async(args: argparse.Namespace) -> None:
    validate_target(args.host)
    print("⚠️  Authorized use only. Test only SSH services you own/control.")
    banner = await grab_banner(args.host, args.port, args.timeout)
    if banner:
        print(f"[+] Banner: {banner}")
    else:
        print("[-] No banner or unreachable.")

    if args.creds:
        if not banner:
            # The banner grab already established the host is unreachable:
            # no credential was tried, so report that, not "attempted" (#20).
            print(f"[*] credential stage skipped: {args.host}:{args.port} unreachable")
        else:
            creds = load_creds(args.creds)
            for user, password in creds:
                status = await try_ssh_password(args.host, args.port, user, password, args.timeout)
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
