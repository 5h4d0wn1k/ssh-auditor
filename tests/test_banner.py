"""Banner grabber reads the identification line whole (#17 in upstream review)."""
import asyncio
import threading
import time
import unittest

from ssh_audit import grab_banner


async def _make_server(handler, port_holder):
    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port_holder.append(server.sockets[0].getsockname()[1])
    async with server:
        await server.serve_forever()


def _serve(handler):
    """Start a loopback asyncio server in its own thread; return its port."""
    port_holder = []
    loop = asyncio.new_event_loop()

    def _thread():
        asyncio.set_event_loop(loop)
        loop.run_until_complete(_make_server(handler, port_holder))

    threading.Thread(target=_thread, daemon=True).start()
    while not port_holder:
        time.sleep(0.02)
    return port_holder[0]


class TestGrabBannerWholeLine(unittest.TestCase):
    def _banner(self, handler):
        port = _serve(handler)
        return asyncio.run(grab_banner("127.0.0.1", port, timeout=3.0))

    def test_long_identification_line_not_truncated(self):
        payload = ("SSH-2.0-OpenSSH_9.3\r\n"
                   "Restricted banner: authorized users only. " * 6).encode()
        self.assertGreater(len(payload), 128)

        async def handler(reader, writer):
            writer.write(payload)
            await writer.drain()
            writer.close()

        banner = self._banner(handler)
        self.assertEqual(banner, "SSH-2.0-OpenSSH_9.3")

    def test_banner_split_across_tcp_segments(self):
        async def handler(reader, writer):
            writer.write(b"SSH-2.0-OpenSS")
            await writer.drain()
            await asyncio.sleep(0.3)
            writer.write(b"H_9.3p2 Debian-4\r\n")
            await writer.drain()
            writer.close()

        banner = self._banner(handler)
        self.assertEqual(banner, "SSH-2.0-OpenSSH_9.3p2 Debian-4")

    def test_oversize_banner_is_marked_truncated(self):
        async def handler(reader, writer):
            writer.write(b"X" * 300)
            await writer.drain()
            writer.close()

        banner = self._banner(handler)
        self.assertIsNotNone(banner)
        self.assertTrue(banner.endswith("(truncated)"))
        self.assertEqual(banner, "X" * 255 + "(truncated)")

    def test_plain_greeting_still_reported(self):
        async def handler(reader, writer):
            writer.write(b"Welcome to the lab telnet service\r\n")
            await writer.drain()
            await asyncio.sleep(2.0)
            writer.close()

        banner = self._banner(handler)
        self.assertEqual(banner, "Welcome to the lab telnet service")

    def test_normal_banner_unchanged(self):
        async def handler(reader, writer):
            writer.write(b"SSH-2.0-OpenSSH_9.3p2 Debian-4\r\n")
            await writer.drain()
            writer.close()

        banner = self._banner(handler)
        self.assertEqual(banner, "SSH-2.0-OpenSSH_9.3p2 Debian-4")
