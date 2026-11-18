import base64
import hmac
import hashlib
import json
import time

from lib.bridge_stub import BridgeStub
from lib.container import IrcdContainer
from lib.irc import IrcClient


VOICE_SOCK_NAME = "voice.sock"
PLACEHOLDER_TURN = {
    "urls": ["turn:placeholder.example:3478?transport=udp"],
    "username": "0:placeholder",
    "password": "placeholderpw",
    "ttl": 60,
}
TURN_KEY = "turn"  # SFU envelope uses lowercase per voice.go json tag


def _ircd(env: dict | None = None) -> IrcdContainer:
    extra = {"VOICE_BRIDGE_SOCKET": f"/run/obbyirc/{VOICE_SOCK_NAME}"}
    if env:
        extra.update(env)
    return IrcdContainer(env=extra, with_voice_bridge=True)


def _parse_rtc_payload(line: str) -> dict:
    tag = "obsidianirc/rtc="
    start = line.index(tag) + len(tag)
    end = line.index(" ", start)
    raw = line[start:end]
    unescaped = (
        raw.replace("\\:", ";")
        .replace("\\s", " ")
        .replace("\\r", "\r")
        .replace("\\n", "\n")
        .replace("\\\\", "\\")
    )
    return json.loads(unescaped)


async def _push_joined(stub: BridgeStub, to_nick: str, turn=PLACEHOLDER_TURN):
    payload = {"type": "joined", "channel": "^vc", "account": to_nick, TURN_KEY: turn}
    await stub.send_frame({"op": "signal", "to": to_nick, "payload": payload})


async def test_passthrough_when_unconfigured():
    ircd = _ircd()
    try:
        async with BridgeStub(ircd.voice_bridge_volume) as stub:
            ircd.up()
            ircd.wait_ready()
            async with IrcClient("127.0.0.1", ircd.host_port(6697), nick="passt") as cli:
                await cli.register()
                await cli.expect(lambda line: " 001 " in line, timeout=30)
                await stub.wait_ircd_connected()
                await _push_joined(stub, "passt")
                line = await cli.expect(
                    lambda line: line.startswith("@obsidianirc/rtc="), timeout=15
                )
            payload = _parse_rtc_payload(line)
            assert payload[TURN_KEY] == PLACEHOLDER_TURN
    finally:
        ircd.down()


async def _run_rewrite_scenario(secret: str, nick: str):
    ttl = 600
    urls = [
        "turn:turn.test.example:3478?transport=udp",
        "turn:turn.test.example:3478?transport=tcp",
    ]
    ircd = _ircd({
        "VOICE_TURN_EXTERNAL_URLS": " ".join(urls),
        "VOICE_TURN_SHARED_SECRET": secret,
        "VOICE_TURN_TTL": str(ttl),
    })
    try:
        async with BridgeStub(ircd.voice_bridge_volume) as stub:
            ircd.up()
            ircd.wait_ready()
            async with IrcClient("127.0.0.1", ircd.host_port(6697), nick=nick) as cli:
                await cli.register()
                await cli.expect(lambda line: " 001 " in line, timeout=30)
                await stub.wait_ircd_connected()
                before = time.time()
                await _push_joined(stub, nick)
                line = await cli.expect(
                    lambda line: line.startswith("@obsidianirc/rtc="), timeout=15
                )
            payload = _parse_rtc_payload(line)
            t = payload[TURN_KEY]
            assert t["urls"] == urls
            assert t["ttl"] == ttl
            expiry_str, _, account = t["username"].partition(":")
            assert account == nick
            assert before + ttl - 5 <= int(expiry_str) <= before + ttl + 5
            expected_pw = base64.b64encode(
                hmac.new(secret.encode(), t["username"].encode(), hashlib.sha1).digest()
            ).decode()
            assert t["password"] == expected_pw
    finally:
        ircd.down()


async def test_external_turn_rewrites_envelope():
    await _run_rewrite_scenario("testsecret", "rewrite")


async def test_secret_with_single_quote():
    # ' is a legal byte in static-auth-secret; entrypoint must escape it
    # via 'sq\\''sq when rendering into single-quoted conf values, else
    # the IRCd parser truncates the secret at the embedded quote.
    await _run_rewrite_scenario("my'tricky'secret", "quoted")
