"""An oper can KILL a persistent ghost, and the account can log in again."""

import asyncio

from lib.accounts import connect, register_account, sasl_plain

CAPS = ["sasl", "draft/persistence"]
PASSWORD = "testpw1234"


async def wait_for_ghost(observer, nick):
    """A ghost answers WHOIS as away while offline, so we wait for that before killing it."""
    for _ in range(20):
        await observer.send(f"WHOIS {nick}")
        line = await observer.expect(
            lambda l: " 318 " in l or (" 301 " in l and "persistent" in l), timeout=5
        )
        if " 301 " in line:
            return
        await asyncio.sleep(0.25)
    raise AssertionError(f"{nick} never became a persistent ghost")


async def test_login_after_an_oper_killed_the_ghost(ircd):
    host, port = "127.0.0.1", ircd.host_port(6697)
    await register_account(host, port, "ghosted", PASSWORD)
    user = await connect(host, port, "ghosted", CAPS, "ghosted", PASSWORD)
    await user.send("PERSISTENCE SET ON")
    await user.send("JOIN #room")
    await user.expect(lambda l: " 366 " in l, timeout=10)
    await user.__aexit__(None, None, None)

    oper = await connect(host, port, "oper", ["message-tags"])
    await oper.send(f"OPER admin {ircd.env['OPER_PASSWORD']}")
    await oper.expect(lambda l: " 381 " in l)
    await wait_for_ghost(oper, "ghosted")
    await oper.send("KILL ghosted :gone")
    await oper.expect(lambda l: "ghosted" in l and "KILL" in l.upper(), timeout=10)

    late = await connect(host, port, "latecomer", ["sasl", "message-tags"])
    await sasl_plain(late, "ghosted", PASSWORD)
    await late.send("PING :alive")
    await late.expect(lambda l: "PONG" in l and "alive" in l, timeout=10)

    await oper.send("PING :still-up")
    await oper.expect(lambda l: "PONG" in l and "still-up" in l, timeout=10)
    await late.__aexit__(None, None, None)
    await oper.__aexit__(None, None, None)
