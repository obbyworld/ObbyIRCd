"""The account stays in its channels while any of its connections is up.

When the connection that holds the nick drops, another connection of the
same account takes it over, whether persistence is on or off.
"""

import asyncio

import pytest

from lib.accounts import connect, register_account

CAPS = ["sasl", "draft/persistence"]
PASSWORD = "testpw1234"


def sent_by(line: str, nick: str) -> bool:
    return f" :{nick}!" in f" {line}"


async def channel_with_head_and_observer(ircd, persistence):
    host, port = "127.0.0.1", ircd.host_port(6697)
    await register_account(host, port, "solo", PASSWORD)
    head = await connect(host, port, "solo", CAPS, "solo", PASSWORD)
    await head.send(f"PERSISTENCE SET {persistence}")
    await head.send("JOIN #room")
    await head.expect(lambda l: " 366 " in l, timeout=10)
    observer = await connect(host, port, "watcher", ["message-tags"])
    await observer.send("JOIN #room")
    await observer.expect(lambda l: " 366 " in l, timeout=10)
    return host, port, head, observer


async def assert_session_holds(observer, session, nick):
    await observer.send("NAMES #room")
    names = await observer.expect(lambda l: " 353 " in l, timeout=10)
    assert nick in names.split(":", 2)[-1].replace("@", "").split()
    assert not [l for l in observer.lines if " QUIT " in l and sent_by(l, nick)]

    await session.send("PRIVMSG #room :still here")
    line = await observer.expect(lambda l: "PRIVMSG #room" in l, timeout=10)
    assert sent_by(line, nick), line

    await session.send("JOIN #other")
    await observer.send("JOIN #other")
    await observer.send("NAMES #other")
    names = await observer.expect(lambda l: " 353 " in l and "#other" in l, timeout=10)
    assert nick in names.split(":", 2)[-1].replace("@", "").split()


@pytest.mark.parametrize("persistence", ["OFF", "ON"])
async def test_session_takes_over_when_the_canonical_drops(ircd, persistence):
    host, port, head, observer = await channel_with_head_and_observer(ircd, persistence)
    session = await connect(host, port, "solo", CAPS, "solo", PASSWORD)
    await session.expect(lambda l: " 366 " in l and "#room" in l, timeout=10)

    await head.__aexit__(None, None, None)
    await asyncio.sleep(2)

    await assert_session_holds(observer, session, "solo")
    await session.__aexit__(None, None, None)
    await observer.__aexit__(None, None, None)


async def test_session_takes_the_nick_the_canonical_changed_to(ircd):
    host, port, head, observer = await channel_with_head_and_observer(ircd, "OFF")
    await head.send("NICK solo_afk")
    await observer.expect(lambda l: " NICK " in l and "solo_afk" in l, timeout=10)
    session = await connect(host, port, "solo", CAPS, "solo", PASSWORD)
    await session.expect(lambda l: " 366 " in l and "#room" in l, timeout=10)

    await head.__aexit__(None, None, None)
    await asyncio.sleep(2)

    await assert_session_holds(observer, session, "solo_afk")
    await session.__aexit__(None, None, None)
    await observer.__aexit__(None, None, None)
