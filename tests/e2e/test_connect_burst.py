"""A logged-in client can send its connect burst without being paced."""

import asyncio

from lib.accounts import connect, register_account
from lib.container import IrcdContainer

CAPS = ["sasl", "message-tags", "echo-message", "batch", "server-time", "draft/chathistory"]
BURST = 40


async def test_logged_in_burst_is_not_paced():
    ircd = IrcdContainer()
    try:
        ircd.up()
        ircd.wait_ready()
        host, port = "127.0.0.1", ircd.host_port(6697)
        await register_account(host, port, "bursty", "burst-pass-1")
        client = await connect(host, port, "bursty", CAPS, "bursty", "burst-pass-1")
        try:
            await client.send("JOIN #burst")
            await client.expect(lambda line: " 366 " in line)
            for _ in range(BURST):
                await client.send("CHATHISTORY LATEST #burst * 50")
            loop = asyncio.get_running_loop()
            sent = loop.time()
            await client.send("PRIVMSG #burst :after the burst")
            await client.expect("PRIVMSG #burst :after the burst", timeout=30)
            assert loop.time() - sent < 2
        finally:
            await client.__aexit__()
    finally:
        ircd.down()
