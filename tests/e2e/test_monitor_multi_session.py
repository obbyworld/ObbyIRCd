"""MONITOR follows an account's nick across all of its connections.

With multi-session and persistence one nick can be held by several clients,
or by a ghost while the user is away. Watchers hear "offline" only when the
nick is really gone.
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


async def _monitor_replies(watcher, seconds=1.5):
    """Collect what the watcher hears within a short window, as "online nick"
    or "offline nick"."""
    replies = []
    try:
        while True:
            line = await watcher.expect(lambda l: " 730 " in l or " 731 " in l, timeout=seconds)
            nick = line.rsplit(":", 1)[1].split("!", 1)[0]
            replies.append(("online " if " 730 " in line else "offline ") + nick)
    except TimeoutError:
        return replies


@pytest.fixture
async def setup(ircd):
    host, port = "127.0.0.1", ircd.host_port(6697)
    await register_account(host, port, "multi", PASSWORD)
    watcher = await connect(host, port, "watcher", CAPS)
    head = await connect(host, port, "multi", CAPS, "multi", PASSWORD)
    await head.send("PERSISTENCE SET ON")
    await head.send("JOIN #room")
    await head.expect(lambda l: " 366 " in l, timeout=10)
    await watcher.send("MONITOR + multi,renamed")
    assert await _monitor_replies(watcher) == ["online multi", "offline renamed"]
    yield host, port, watcher, head
    await watcher.__aexit__(None, None, None)


async def test_sessions_coming_and_going_keep_the_nick_online(setup):
    host, port, watcher, head = setup

    second = await connect(host, port, "multi_", CAPS, "multi", PASSWORD)
    assert await _monitor_replies(watcher) == []

    await second.send("QUIT")
    assert await _monitor_replies(watcher) == []

    third = await connect(host, port, "multi_", CAPS, "multi", PASSWORD)
    await head.send("QUIT")
    assert await _monitor_replies(watcher) == []
    await third.__aexit__(None, None, None)


async def test_nick_change_with_a_session_moves_the_watch(setup):
    host, port, watcher, head = setup
    session = await connect(host, port, "multi_", CAPS, "multi", PASSWORD)
    await _monitor_replies(watcher)

    await head.send("NICK renamed")
    assert sorted(await _monitor_replies(watcher)) == ["offline multi", "online renamed"]
    await session.__aexit__(None, None, None)
    await head.__aexit__(None, None, None)


async def test_reclaiming_a_renamed_ghost_frees_its_nick(setup):
    host, port, watcher, head = setup
    await head.send("NICK renamed")
    await _monitor_replies(watcher)
    await head.send("QUIT")
    assert await _monitor_replies(watcher) == []

    back = await connect(host, port, "multi", CAPS, "multi", PASSWORD)
    assert sorted(await _monitor_replies(watcher)) == ["offline renamed", "online multi"]
    await back.__aexit__(None, None, None)


async def test_ghost_keeps_the_nick_online_until_persistence_is_off(setup):
    host, port, watcher, head = setup

    await head.send("QUIT")
    assert await _monitor_replies(watcher) == []

    back = await connect(host, port, "multi", CAPS, "multi", PASSWORD)
    await _monitor_replies(watcher)
    await back.send("PERSISTENCE SET OFF")
    await asyncio.sleep(0.3)
    await back.send("QUIT")
    assert await _monitor_replies(watcher) == ["offline multi"]


async def test_erasing_a_ghost_takes_the_nick_offline(setup):
    host, port, watcher, head = setup
    await head.send("QUIT")
    assert await _monitor_replies(watcher) == []

    await register_account(host, port, "oper", PASSWORD)
    oper = await connect(host, port, "oper", CAPS, "oper", PASSWORD)
    await oper.send(f"OPER admin {OPER_PASS}")
    await oper.expect(lambda l: " 381 " in l, timeout=10)
    await oper.send("PERSISTENCE ERASE multi")
    note = await oper.expect(lambda l: "PERSISTENCE CONFIRM" in l, timeout=10)
    await oper.send(note.split("issue: ", 1)[1])
    assert await _monitor_replies(watcher) == ["offline multi"]
    await oper.__aexit__(None, None, None)


async def test_persistent_user_without_channels_goes_offline_on_quit(ircd):
    host, port = "127.0.0.1", ircd.host_port(6697)
    await register_account(host, port, "solo", PASSWORD)
    watcher = await connect(host, port, "watcher", CAPS)
    solo = await connect(host, port, "solo", CAPS, "solo", PASSWORD)
    await solo.send("PERSISTENCE SET ON")
    await watcher.send("MONITOR + solo")
    assert await _monitor_replies(watcher) == ["online solo"]

    await solo.send("QUIT")
    assert await _monitor_replies(watcher) == ["offline solo"]
    await watcher.__aexit__(None, None, None)
