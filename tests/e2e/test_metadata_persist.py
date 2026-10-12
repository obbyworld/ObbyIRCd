"""metadata-db persistence + boot replay.

Two regressions guarded:

1. Channel + user metadata SET while running must survive a clean
   restart (the metadata-db module writes on shutdown, reads on boot).
2. The boot read must hit metadata_set_channel / metadata_set_user AFTER
   the metadata module's limit defaults are applied; otherwise restored
   entries silently drop on LIMIT_REACHED.
"""

import subprocess
import time

import pytest

from lib.accounts import connect, register_account
from lib.container import IrcdContainer
from lib.irc import IrcClient

CAP_LINE = "CAP REQ :draft/metadata-2 message-tags batch"
OPER_PASS = "testoper-fixed-pass"


@pytest.fixture
def persistent_ircd():
    c = IrcdContainer(bind_data=True, env={"OPER_PASSWORD": OPER_PASS}).up()
    try:
        c.wait_ready()
        yield c
    finally:
        c.down()


async def _set_channel_metadata(ircd: IrcdContainer, channel: str, kvs: dict[str, str]):
    port = ircd.host_port(6697)
    async with IrcClient("127.0.0.1", port, nick="setter") as c:
        await c.send(CAP_LINE)
        await c.register()
        await c.send("CAP END")
        await c.expect(lambda l: " 001 " in l, timeout=30)
        await c.send(f"OPER admin {OPER_PASS}")
        await c.expect(lambda l: " 381 " in l)
        await c.send(f"SAJOIN setter {channel}")
        await c.expect(lambda l: " 366 " in l and channel in l)
        await c.send(f"SAMODE {channel} +Pq setter")
        await c.expect(lambda l: "MODE" in l and "P" in l.split(":", 1)[0] and channel in l)
        for key, value in kvs.items():
            await c.send(f"METADATA {channel} SET {key} :{value}")
            await c.expect(lambda l: " 761 " in l and key in l)


async def _read_channel_metadata(ircd: IrcdContainer, channel: str) -> dict[str, str]:
    port = ircd.host_port(6697)
    async with IrcClient("127.0.0.1", port, nick="reader") as c:
        await c.send(CAP_LINE)
        await c.register()
        await c.send("CAP END")
        await c.expect(lambda l: " 001 " in l, timeout=30)
        await c.send(f"JOIN {channel}")
        await c.expect(lambda l: " 366 " in l and channel in l)
        await c.send(f"METADATA {channel} LIST")
        out: dict[str, str] = {}
        end_batch = None
        while True:
            line = await c.expect(lambda l: " 761 " in l or " BATCH " in l, timeout=10)
            if " BATCH " in line and end_batch is None:
                end_batch = "BATCH -" + line.split("BATCH +", 1)[1].split(" ", 1)[0]
                continue
            if end_batch and end_batch in line:
                break
            if " 761 " in line:
                trailing_idx = line.rfind(" :")
                if trailing_idx < 0:
                    continue
                value = line[trailing_idx + 2:]
                parts = line[:trailing_idx].split()
                idx = parts.index("761")
                out[parts[idx + 3]] = value
        return out


def _docker_logs(name: str) -> str:
    result = subprocess.run(
        ["docker", "logs", name], capture_output=True, text=True
    )
    return result.stdout + result.stderr


def _wait_for_marker(name: str, marker: str, min_count: int, timeout: int):
    deadline = time.time() + timeout
    while time.time() < deadline:
        log = _docker_logs(name)
        if log.count(marker) >= min_count:
            time.sleep(0.5)
            return
        time.sleep(1)
    raise TimeoutError(
        f"marker {marker!r} count < {min_count} (last 2000):\n{_docker_logs(name)[-2000:]}"
    )


def _restart_and_wait(c: IrcdContainer, timeout: int = 120):
    marker = "ObbyIRCd started."
    pre = _docker_logs(c.name).count(marker)
    subprocess.check_call(["docker", "stop", "-t", "15", c.name])
    subprocess.check_call(["docker", "start", c.name])
    _wait_for_marker(c.name, marker, pre + 1, timeout)


async def test_channel_metadata_survives_restart(persistent_ircd):
    channel = "#persist"
    avatar = "https://example.invalid/avatar.png"
    display = "Persisted Room"

    await _set_channel_metadata(persistent_ircd, channel, {
        "avatar": avatar,
        "display-name": display,
    })

    _restart_and_wait(persistent_ircd)

    md = await _read_channel_metadata(persistent_ircd, channel)
    assert md.get("avatar") == avatar, f"avatar lost after restart: {md}"
    assert md.get("display-name") == display, f"display-name lost: {md}"


async def test_no_double_replay_on_rehash(persistent_ircd):
    """sentinel guards against re-reading metadata.db on /REHASH."""
    channel = "#rehashtest"
    avatar = "https://example.invalid/x.png"

    await _set_channel_metadata(persistent_ircd, channel, {"avatar": avatar})

    _restart_and_wait(persistent_ircd)

    subprocess.check_call([
        "docker", "exec", persistent_ircd.name,
        "sh", "-c", "kill -HUP $(pgrep obbyircd)"
    ])
    time.sleep(3)

    log = _docker_logs(persistent_ircd.name)
    reads = log.count("metadata entries")
    assert reads == 1, f"metadata-db read fired {reads}x, want 1 (sentinel broken):\n{log[-2000:]}"

    md = await _read_channel_metadata(persistent_ircd, channel)
    assert md.get("avatar") == avatar, f"metadata lost after rehash: {md}"


PROFILE_CAPS = ["sasl", "draft/metadata-2", "draft/persistence", "message-tags", "batch"]
PROFILE_PASS = "testpw1234"


async def _profile_client(ircd: IrcdContainer, nick: str, account: str | None = None):
    return await connect("127.0.0.1", ircd.host_port(6697), nick, PROFILE_CAPS, account, PROFILE_PASS)


async def _register_account(ircd: IrcdContainer, account: str):
    await register_account("127.0.0.1", ircd.host_port(6697), account, PROFILE_PASS)


async def _profile_seen_by(observer: IrcClient, target: str, keys: list[str]) -> dict[str, str]:
    await observer.send(f"METADATA {target} GET {' '.join(keys)}")
    seen: dict[str, str] = {}
    for _ in keys:
        line = await observer.expect(lambda l: " 761 " in l or " 766 " in l, timeout=10)
        if line.startswith("@"):
            line = line.split(" ", 1)[1]
        parts = line.split(" :", 1)[0].split()
        numeric = "761" if " 761 " in line else "766"
        key = parts[parts.index(numeric) + 3]
        if numeric == "761":
            seen[key] = line.rsplit(" :", 1)[1]
    return seen


async def test_offline_persistent_user_keeps_profile(persistent_ircd):
    """A persistent user's ghost shows their saved profile, after they quit
    and after a restart, until they come back."""
    await _register_account(persistent_ircd, "ghostuser")
    user = await _profile_client(persistent_ircd, "ghostuser", "ghostuser")
    await user.send("PERSISTENCE SET ON")
    await user.send("JOIN #ghosts")
    await user.expect(lambda l: " 366 " in l, timeout=10)
    await user.send("METADATA * SET avatar :https://example.invalid/g.png")
    await user.expect(lambda l: " 761 " in l and "avatar" in l)
    await user.send("METADATA * SET display-name :Ghost User")
    await user.expect(lambda l: " 761 " in l and "display-name" in l)
    await user.__aexit__(None, None, None)

    profile = {"avatar": "https://example.invalid/g.png", "display-name": "Ghost User"}
    watcher = await _profile_client(persistent_ircd, "watcher")
    await watcher.send("JOIN #ghosts")
    await watcher.expect(lambda l: " 366 " in l, timeout=10)
    assert await _profile_seen_by(watcher, "ghostuser", list(profile)) == profile
    await watcher.__aexit__(None, None, None)

    _restart_and_wait(persistent_ircd)

    watcher = await _profile_client(persistent_ircd, "watcher")
    await watcher.send("JOIN #ghosts")
    await watcher.expect(lambda l: " 366 " in l, timeout=10)
    assert await _profile_seen_by(watcher, "ghostuser", list(profile)) == profile
    await watcher.__aexit__(None, None, None)


async def test_profile_keeps_keys_an_edit_did_not_touch(persistent_ircd):
    """Each edit changes only its own key in metadata.db: an overwritten key
    keeps its new value, a deleted key goes, and every other saved key stays
    through a restart."""
    await _register_account(persistent_ircd, "editor")
    user = await _profile_client(persistent_ircd, "editor", "editor")
    await user.send("JOIN #edits")
    await user.expect(lambda l: " 366 " in l, timeout=10)
    for key, value in {"avatar": "https://example.invalid/e.png", "color": "#ff0000", "status": "busy"}.items():
        await user.send(f"METADATA * SET {key} :{value}")
        await user.expect(lambda l, key=key: " 761 " in l and key in l)
    await user.send("METADATA * SET color :#00ff00")
    await user.expect(lambda l: " 761 " in l and "#00ff00" in l)
    await user.send("METADATA * SET status")
    await user.expect(lambda l: " 766 " in l and " status " in l)
    await user.__aexit__(None, None, None)

    _restart_and_wait(persistent_ircd)

    user = await _profile_client(persistent_ircd, "editor", "editor")
    watcher = await _profile_client(persistent_ircd, "watcher")
    for c in (user, watcher):
        await c.send("JOIN #edits")
        await c.expect(lambda l: " 366 " in l, timeout=10)
    seen = await _profile_seen_by(watcher, "editor", ["avatar", "color", "status"])
    assert seen == {"avatar": "https://example.invalid/e.png", "color": "#00ff00"}
    await user.__aexit__(None, None, None)
    await watcher.__aexit__(None, None, None)
