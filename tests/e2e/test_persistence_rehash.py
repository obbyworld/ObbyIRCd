"""Multi-session keeps working after a REHASH.

Persistence is a permanent module: a REHASH reloads the modules that own
NICK, JOIN, MODE and the other commands it overrides for sessions, while
persistence itself stays loaded.
"""

import asyncio
import secrets

import pytest

from lib.accounts import connect, register_account
from lib.container import IrcdContainer

CAPS = ["sasl", "draft/persistence"]
PASSWORD = "testpw1234"
OPER_PASS = secrets.token_hex(8)


@pytest.fixture
def ircd():
    c = IrcdContainer(env={"OPER_PASSWORD": OPER_PASS}).up()
    try:
        c.wait_ready()
        yield c
    finally:
        c.down()


@pytest.fixture
async def account(ircd):
    host, port = "127.0.0.1", ircd.host_port(6697)
    await register_account(host, port, "multi", PASSWORD)
    head = await connect(host, port, "multi", CAPS, "multi", PASSWORD)
    await head.send("PERSISTENCE SET ON")
    await head.send("JOIN #room")
    await head.expect(lambda l: " 366 " in l, timeout=10)
    yield host, port, head
    await head.__aexit__(None, None, None)


async def test_session_keeps_the_account_nick_after_rehash(ircd, account):
    host, port, head = account
    session = await connect(host, port, "multi_", CAPS, "multi", PASSWORD)
    ircd.rehash()
    await asyncio.sleep(3)

    await session.send("NICK multi_")
    await session.send("PING nickdone")
    await session.expect(lambda l: "PONG" in l and "nickdone" in l, timeout=10)
    await head.send("WHOIS multi_")
    assert " 401 " in await head.expect(lambda l: " 311 " in l or " 401 " in l, timeout=10)
    await session.send("QUIT")
    await asyncio.sleep(1)
    assert ircd.is_running()

    await head.send("WHOIS multi")
    assert " 311 " in await head.expect(lambda l: " 311 " in l or " 401 " in l, timeout=10)


async def test_oper_session_leaves_the_oper_count_right(ircd, account):
    host, port, head = account
    await head.send(f"OPER admin {OPER_PASS}")
    await head.expect(lambda l: " 381 " in l, timeout=10)
    session = await connect(host, port, "multi_", CAPS, "multi", PASSWORD)
    await session.send("QUIT")
    await head.send("QUIT")
    await asyncio.sleep(1)

    assert "Operator count bug" not in ircd.logs()
