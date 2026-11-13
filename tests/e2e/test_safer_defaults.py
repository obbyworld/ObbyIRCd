import asyncio
import subprocess

import pytest
from websockets.exceptions import WebSocketException

from lib.container import IrcdContainer
from lib.irc import IrcClient
from lib.ws import WsIrcClient


@pytest.fixture
def proxied_ircd():
    """We trust the Docker bridge gateway because connections to published ports arrive from it."""
    gateway = subprocess.check_output(
        ["docker", "network", "inspect", "bridge", "-f", "{{(index .IPAM.Config 0).Gateway}}"],
        text=True,
    ).strip()
    container = IrcdContainer(env={"WS_TRUSTED_PROXIES": gateway}).up()
    try:
        container.wait_ready()
        yield container
    finally:
        container.down()


async def _welcome(client):
    await client.register()
    await client.expect(lambda line: " 001 " in line, timeout=30)


async def test_websocket_client_is_seen_with_its_forwarded_ip(proxied_ircd):
    port = proxied_ircd.host_port(8080)
    async with WsIrcClient("127.0.0.1", port, nick="fwd", forwarded_for="203.0.113.7") as client:
        await _welcome(client)
        await client.send("WHOIS fwd")
        await client.expect(lambda line: " 378 " in line and "203.0.113.7" in line)


async def test_websocket_handshake_flood_bans_only_the_flooder(proxied_ircd):
    port = proxied_ircd.host_port(8080)
    async with WsIrcClient("127.0.0.1", port, nick="bystander", forwarded_for="203.0.113.10") as bystander:
        await _welcome(bystander)

        async with WsIrcClient("127.0.0.1", port, forwarded_for="203.0.113.11") as flooder:
            for _ in range(3):
                await flooder.send("PING :" + "a" * 2000)
                await asyncio.sleep(1)
            with pytest.raises(EOFError):
                await flooder.expect(lambda line: False, timeout=30)

        await bystander.send("PING :still-here")
        await bystander.expect(lambda line: "PONG" in line and "still-here" in line)

        async with WsIrcClient("127.0.0.1", port, nick="newcomer", forwarded_for="203.0.113.12") as newcomer:
            await _welcome(newcomer)

        with pytest.raises((EOFError, WebSocketException)):
            async with WsIrcClient("127.0.0.1", port, nick="returner", forwarded_for="203.0.113.11") as returner:
                await _welcome(returner)


async def test_op_can_grant_and_remove_voice_halfop_and_op(ircd):
    port = ircd.host_port(6697)
    async with IrcClient("127.0.0.1", port, nick="chanop") as op, \
               IrcClient("127.0.0.1", port, nick="member") as member:
        await _welcome(op)
        await _welcome(member)
        await op.send("JOIN #roles")
        await op.expect(lambda line: " 353 " in line and "@chanop" in line)
        await member.send("JOIN #roles")
        await op.expect(lambda line: "JOIN" in line and "member" in line)

        for change in ("+v", "+h", "+o", "-o", "-h", "-v"):
            await op.send(f"MODE #roles {change} member")
            await op.expect(lambda line: f"MODE #roles {change} member" in line)

        await op.send("MODE #roles +a member")
        await op.expect(lambda line: " 482 " in line)


async def test_client_census_command_is_gone(ircd):
    port = ircd.host_port(6697)
    async with IrcClient("127.0.0.1", port, nick="nosy") as client:
        await _welcome(client)
        await client.send("DEBUGLMAO")
        await client.expect(lambda line: " 421 " in line)


async def test_example_script_is_not_loaded(ircd):
    port = ircd.host_port(6697)
    async with IrcClient("127.0.0.1", port, nick="scripts") as client:
        await _welcome(client)
        await client.send("REMINDER 1 hello")
        await client.expect(lambda line: " 421 " in line and "REMINDER" in line)
