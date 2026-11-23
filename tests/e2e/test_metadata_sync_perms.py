"""METADATA SYNC only returns what METADATA GET would."""

import asyncio

from lib.accounts import connect

CAPS = ["draft/metadata-2", "message-tags", "batch"]


async def client(port, nick):
    return await connect("127.0.0.1", port, nick, CAPS)


async def sync(c, target, keys):
    start = len(c.lines)
    await c.send(f"METADATA * SUB {keys}")
    await c.send(f"METADATA {target} SYNC")
    # Subscribers get queued values on a 1.5s timer, so we wait past it before the sentinel.
    await asyncio.sleep(4)
    await c.send("PING :synced")
    await c.expect("PONG")
    return "\n".join(c.lines[start:])


async def test_sync_leaks_nothing_to_strangers(ircd):
    port = ircd.host_port(6697)
    alice = await client(port, "alice")
    eve = await client(port, "eve")
    bob = await client(port, "bob")
    try:
        await alice.send("METADATA * SET u_displayname :SecretAlice")
        await alice.expect(lambda l: " 761 " in l)
        await alice.send("JOIN #secretbase")
        await alice.expect(lambda l: " 366 " in l)
        await alice.send("METADATA #secretbase SET topic-locked :SecretChan")
        await alice.expect(lambda l: " 761 " in l and "topic-locked" in l)

        user_sync = await sync(eve, "alice", "u_displayname")
        chan_sync = await sync(eve, "#secretbase", "topic-locked")
        assert "SecretAlice" not in user_sync + chan_sync
        assert "SecretChan" not in chan_sync
        assert "KEY_NO_PERMISSION" in user_sync and "KEY_NO_PERMISSION" in chan_sync

        await bob.send("JOIN #secretbase")
        await bob.expect(lambda l: " 366 " in l)
        member_sync = await sync(bob, "#secretbase", "u_displayname topic-locked")
        assert "SecretChan" in member_sync and "SecretAlice" in member_sync
    finally:
        for c in (alice, eve, bob):
            await c.__aexit__()
