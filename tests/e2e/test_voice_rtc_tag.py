"""A client's obsidianirc/rtc tag only reaches the voice bridge.

The tag carries voice signaling envelopes, so one relayed to another user
would let a client forge them. Only the server sends it to clients.
"""

import asyncio
import json

from lib.accounts import connect
from lib.bridge_stub import BridgeStub
from lib.container import IrcdContainer

CAPS = ["message-tags", "obsidianirc/voice"]
RTC = "obsidianirc/rtc"
ENVELOPE = json.dumps({"type": "ice", "candidate": "x"}, separators=(",", ":"))


async def _wait_signal(stub: BridgeStub) -> dict:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + 10
    while True:
        for frame in stub.received:
            if frame.get("op") == "signal":
                return frame
        assert loop.time() < deadline, stub.received
        await asyncio.sleep(0.2)


async def test_rtc_tag_only_reaches_voice_bridge():
    ircd = IrcdContainer(
        env={"VOICE_BRIDGE_SOCKET": "/run/obbyirc/voice.sock"}, with_voice_bridge=True
    )
    try:
        async with BridgeStub(ircd.voice_bridge_volume) as stub:
            ircd.up()
            ircd.wait_ready()
            await stub.wait_ircd_connected()
            host, port = "127.0.0.1", ircd.host_port(6697)
            alice = await connect(host, port, "alice", CAPS)
            bob = await connect(host, port, "bob", CAPS)
            try:
                for client in (alice, bob):
                    for channel in ("#lobby", "^vc"):
                        await client.send(f"JOIN {channel}")
                        await client.expect(lambda line: " 366 " in line)

                await alice.send(f"@{RTC}={ENVELOPE} TAGMSG ^vc")
                signal = await _wait_signal(stub)
                assert signal["from"] == "alice"
                assert signal["channel"] == "^vc"
                assert signal["payload"] == json.loads(ENVELOPE)

                await alice.send(f"@{RTC}={ENVELOPE} TAGMSG bob")
                await alice.send(f"@{RTC}={ENVELOPE} TAGMSG #lobby")
                await alice.send(f"@{RTC}={ENVELOPE} TAGMSG ^vc,bob")
                await alice.send(f"@{RTC}={ENVELOPE} PRIVMSG bob :hi")
                await alice.send(f"@{RTC}={ENVELOPE} NICK alice2")
                await alice.send("PRIVMSG bob :done")
                await bob.expect("PRIVMSG bob :done")
                assert not [line for line in bob.lines if RTC in line]

                await stub.send_frame(
                    {"op": "signal", "to": "bob", "payload": {"type": "joined"}}
                )
                line = await bob.expect(lambda line: RTC in line)
                assert line.startswith(f'@{RTC}={{"type":"joined"}} :')
                assert line.endswith(" TAGMSG bob")
            finally:
                await alice.__aexit__()
                await bob.__aexit__()
    finally:
        ircd.down()
