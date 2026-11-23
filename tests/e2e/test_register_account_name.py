"""REGISTER only accepts account names that are valid nicks."""

from lib.accounts import drain_motd
from lib.irc import IrcClient


async def register(port, nick, account):
    async with IrcClient("127.0.0.1", port, nick=nick) as c:
        await c.register()
        await drain_motd(c)
        await c.send(f"REGISTER {account} evil@atk.test Phantom1!")
        return await c.expect(lambda l: " REGISTER " in l, timeout=10)


async def test_channel_like_account_name_is_refused(ircd):
    port = ircd.host_port(6697)
    assert "FAIL REGISTER BAD_ACCOUNT_NAME #phantom" in await register(port, "phantomer", "#phantom")
    assert "REGISTER SUCCESS goodname" in await register(port, "goodname", "goodname")
