"""A +draft/react value with control bytes never reaches the /me fallback."""

from lib.accounts import connect

ATTACKS = ["x\x01ACTION", "\x01ACTION\\sx", "A\\rB", "A\\nB", "1\\n:x", "x\\n\\x01A"]


async def test_react_with_control_bytes_is_dropped(ircd):
    port = ircd.host_port(6697)
    # The victim lacks message-tags, so it only ever sees the /me fallback.
    victim = await connect("127.0.0.1", port, "victim", ["multi-prefix"])
    reactor = await connect("127.0.0.1", port, "reactor", ["message-tags"])
    try:
        await victim.send("JOIN #react")
        await victim.expect(lambda l: " 366 " in l)
        await reactor.send("JOIN #react")
        await victim.expect(lambda l: " JOIN " in l and "reactor" in l)

        start = len(victim.lines)
        for value in ATTACKS:
            await reactor.send(f"@+draft/react={value} TAGMSG #react")
        await reactor.send("@+draft/react=end TAGMSG #react")
        await victim.expect("reacted with end", timeout=10)

        assert len(victim.lines[start:]) == 1, victim.lines[start:]
    finally:
        for c in (victim, reactor):
            await c.__aexit__()
