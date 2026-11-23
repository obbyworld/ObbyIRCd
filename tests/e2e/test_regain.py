"""REGAIN gives an account its nick back, IDENTIFY logs in over the account's
own ghost, and failed logins are rate limited."""

import asyncio
import base64
import hashlib
import hmac
import json
import struct
import time

from lib.accounts import connect, register_account, sasl_plain, wait_for_ghost

PERSIST_CAPS = ["sasl", "draft/persistence"]
PASSWORD = "testpw1234"


def totp(secret_b32: str) -> str:
    key = base64.b32decode(secret_b32.upper() + "=" * (-len(secret_b32) % 8))
    digest = hmac.new(key, struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
    offset = digest[-1] & 15
    code = (struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF) % 1_000_000
    return f"{code:06d}"


async def leave_a_ghost(host, port, account):
    await register_account(host, port, account, PASSWORD)
    user = await connect(host, port, account, PERSIST_CAPS, account, PASSWORD)
    await user.send("PERSISTENCE SET ON")
    await user.send("JOIN #room")
    await user.expect(lambda l: " 366 " in l, timeout=10)
    await user.__aexit__(None, None, None)
    observer = await connect(host, port, "observer", ["message-tags"])
    await wait_for_ghost(observer, account)
    return observer


async def test_identify_logs_in_over_your_own_ghost(ircd):
    host, port = "127.0.0.1", ircd.host_port(6697)
    observer = await leave_a_ghost(host, port, "owner")
    late = await connect(host, port, "late", ["message-tags"])

    await late.send(f"IDENTIFY owner {PASSWORD}")
    await late.expect(lambda l: "IDENTIFY SUCCESS owner" in l, timeout=10)

    await observer.send("WHOIS owner")
    assert " 401 " in await observer.expect(lambda l: " 401 " in l or " 311 " in l)


async def test_regain_takes_the_nick_back_from_your_ghost(ircd):
    host, port = "127.0.0.1", ircd.host_port(6697)
    await leave_a_ghost(host, port, "owner")
    late = await connect(host, port, "late", ["message-tags"])

    await late.send(f"REGAIN owner {PASSWORD}")
    await late.expect(lambda l: ":late" in l and " NICK " in l and "owner" in l, timeout=10)
    await late.expect(lambda l: "REGAIN SUCCESS owner" in l, timeout=10)


async def test_regain_renames_a_guest_on_your_nick(ircd):
    host, port = "127.0.0.1", ircd.host_port(6697)
    await register_account(host, port, "owner", PASSWORD)
    squatter = await connect(host, port, "owner", ["message-tags"])
    rightful = await connect(host, port, "rightful", ["message-tags"])

    await rightful.send(f"REGAIN owner {PASSWORD}")
    await squatter.expect(lambda l: "NICK" in l and "Guest" in l, timeout=10)
    await rightful.expect(lambda l: "REGAIN SUCCESS owner" in l, timeout=10)


async def test_regain_disconnects_your_session_on_the_nick(ircd):
    host, port = "127.0.0.1", ircd.host_port(6697)
    await register_account(host, port, "owner", PASSWORD)
    stuck = await connect(host, port, "owner", ["sasl", "message-tags"], "owner", PASSWORD)
    late = await connect(host, port, "late", ["message-tags"])

    await late.send(f"REGAIN owner {PASSWORD}")
    await stuck.expect(lambda l: l.startswith("ERROR") and "regained" in l, timeout=10)
    await late.expect(lambda l: "REGAIN SUCCESS owner" in l, timeout=10)


async def test_failed_logins_lock_the_account_for_every_login_path(ircd):
    """The test clients share Docker's private address, which counts as a
    proxy, so the account cap is what locks them out."""
    host, port = "127.0.0.1", ircd.host_port(6697)
    await register_account(host, port, "target", PASSWORD)
    guessers = [await connect(host, port, f"guess{i}", ["message-tags"]) for i in range(10)]
    for _ in range(3):
        for guesser in guessers:
            await guesser.send("IDENTIFY target wrongpass")
        for guesser in guessers:
            await guesser.expect(lambda l: "FAIL IDENTIFY INVALID_PASSWORD" in l, timeout=20)

    late = await connect(host, port, "late", ["sasl", "message-tags"])
    await late.send(f"IDENTIFY target {PASSWORD}")
    await late.expect(lambda l: "FAIL IDENTIFY RATE_LIMITED" in l, timeout=10)

    sasl = await connect(host, port, "viasasl", ["sasl", "message-tags"])
    await sasl_plain(sasl, "target", PASSWORD)
    assert any(" 904 " in l for l in sasl.lines)


async def test_regain_takes_over_your_live_persistent_session(ircd):
    host, port = "127.0.0.1", ircd.host_port(6697)
    await register_account(host, port, "owner", PASSWORD)
    desk = await connect(host, port, "owner", PERSIST_CAPS + ["message-tags"], "owner", PASSWORD)
    await desk.send("PERSISTENCE SET ON")
    await desk.send("JOIN #room")
    await desk.expect(lambda l: " 366 " in l, timeout=10)
    friend = await connect(host, port, "friend", ["message-tags"])
    await friend.send("JOIN #room")
    await friend.expect(lambda l: " 366 " in l, timeout=10)
    phone = await connect(host, port, "phone", ["message-tags"])

    await phone.send(f"REGAIN owner {PASSWORD}")
    await desk.expect(lambda l: l.startswith("ERROR") and "regained" in l, timeout=10)
    await phone.expect(lambda l: " JOIN " in l and "#room" in l, timeout=10)
    await phone.expect(lambda l: "REGAIN SUCCESS owner" in l, timeout=10)


async def test_password_logins_refuse_an_account_with_two_factor(ircd):
    host, port = "127.0.0.1", ircd.host_port(6697)
    await register_account(host, port, "secured", PASSWORD)
    user = await connect(host, port, "secured", ["sasl", "message-tags"], "secured", PASSWORD)
    await user.send("2FA CHALLENGE totp")
    line = await user.expect(lambda l: "REGISTRATION_CHALLENGE totp" in l, timeout=10)
    parts = line.split()
    encoded = parts[parts.index("totp") + 1]
    challenge = json.loads(base64.b64decode(encoded + "=" * (-len(encoded) % 4)))
    await user.send(f"2FA ADD totp phone {totp(challenge['secret'])}")
    await user.expect(lambda l: "2FA ADD SUCCESS totp" in l, timeout=10)
    await user.send("2FA ENABLE")
    await user.expect(lambda l: "2FA ENABLE SUCCESS" in l, timeout=10)

    other = await connect(host, port, "other", ["message-tags"])
    await other.send(f"IDENTIFY secured {PASSWORD}")
    await other.expect(lambda l: "FAIL IDENTIFY TWOFA_REQUIRED" in l, timeout=10)
    await other.send(f"REGAIN secured {PASSWORD}")
    await other.expect(lambda l: "FAIL REGAIN TWOFA_REQUIRED" in l, timeout=10)


async def test_regain_leaves_a_nick_another_account_holds(ircd):
    host, port = "127.0.0.1", ircd.host_port(6697)
    await register_account(host, port, "owner", PASSWORD)
    await register_account(host, port, "other", PASSWORD)
    holder = await connect(host, port, "other", ["sasl", "message-tags"], "other", PASSWORD)
    await holder.send("NICK owner")
    await holder.expect(lambda l: " NICK " in l and "owner" in l, timeout=10)

    late = await connect(host, port, "late", ["message-tags"])
    await late.send(f"REGAIN owner {PASSWORD}")
    await late.expect(lambda l: "FAIL REGAIN INVALID_ACCOUNT" in l, timeout=10)
