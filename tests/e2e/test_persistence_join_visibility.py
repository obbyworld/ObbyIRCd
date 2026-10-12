"""
When a user with persistence OFF reconnects, observers in the channels
they're re-restored to must see a JOIN broadcast.  The prior bug was a
silent add via persist_account_login -> restore_channels' same_nick
branch, which only emitted a JOIN to the joining client itself.
"""

import asyncio

import pytest

from lib.accounts import drain_motd, register_account, sasl_plain
from lib.irc import IrcClient


async def _login(host, port, account, password, with_persistence: bool):
    c = IrcClient(host, port, nick=account)
    await c.__aenter__()
    caps = ["sasl", "draft/persistence", "account-tag"] if with_persistence else ["sasl", "account-tag"]
    await c.send("CAP LS 302")
    await c.send("CAP REQ :" + " ".join(caps))
    await c.expect(lambda l: " ACK " in l and "sasl" in l, timeout=10)
    await sasl_plain(c, account, password)
    await c.send("CAP END")
    await c.send(f"NICK {account}")
    await c.send(f"USER {account} 0 * :{account}")
    await drain_motd(c)
    return c


async def _close(c):
    try:
        await c.__aexit__(None, None, None)
    except Exception:
        pass


@pytest.mark.asyncio
async def test_persistence_off_reconnect_broadcasts_join(ircd):
    host = "127.0.0.1"
    port = ircd.host_port(6697)

    account = "valware"
    password = "testpw1234"
    channel = "#room"

    await register_account(host, port, account, password)

    # Observer joins channel first.
    obs = IrcClient(host, port, nick="watcher")
    await obs.__aenter__()
    await obs.register()
    await drain_motd(obs)
    await obs.send(f"JOIN {channel}")
    await obs.expect(lambda l: " 366 " in l and channel in l, timeout=10)

    # Valware logs in with persistence ON, joins, then disables persistence.
    a = await _login(host, port, account, password, with_persistence=True)
    await a.send(f"JOIN {channel}")
    await a.expect(lambda l: " 366 " in l and channel in l, timeout=10)
    # Observer should see Valware JOIN.
    await obs.expect(
        lambda l: f" JOIN " in l and channel in l and "valware" in l.lower(),
        timeout=10,
    )

    # Switch persistence OFF on Valware's account.
    await a.send("PERSISTENCE SET OFF")
    # Tolerate any reply -- the cmd ack varies.
    await asyncio.sleep(0.3)

    # Valware disconnects (simulates page refresh / connection drop).
    await _close(a)

    # Observer must see QUIT for Valware (because persistence was off).
    await obs.expect(
        lambda l: " QUIT " in l and "valware" in l.lower(),
        timeout=10,
    )

    # Valware reconnects.  with_persistence cap is still requested client-side;
    # the SERVER preference is OFF so the bug condition applies.
    b = await _login(host, port, account, password, with_persistence=True)

    # Send an explicit JOIN — the fix removes auto-restore for OFF'd
    # accounts (correct behaviour: the user is a regular non-persistent
    # IRC user again, so they must JOIN themselves and the JOIN must
    # broadcast). Pre-fix, restore_channels silently re-adds Valware
    # before this JOIN runs, and the subsequent explicit JOIN is a
    # no-op ("already on channel"), so the observer sees nothing.
    await b.send(f"JOIN {channel}")

    try:
        line = await obs.expect(
            lambda l: " JOIN " in l and "valware" in l.lower() and channel in l,
            timeout=8,
        )
    except TimeoutError:
        await _close(b)
        await _close(obs)
        pytest.fail(
            "Bug present: observer did not see JOIN broadcast for "
            "Valware's reconnect after persistence was disabled. "
            "Most-recent observer lines: " + "\n".join(obs.lines[-12:])
        )

    await _close(b)
    await _close(obs)
    assert channel in line, f"unexpected JOIN target: {line}"
