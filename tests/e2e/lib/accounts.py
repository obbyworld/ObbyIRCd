import base64

from lib.irc import IrcClient


async def drain_motd(c):
    await c.expect(lambda l: " 376 " in l or " 422 " in l, timeout=20)


async def sasl_plain(c, account, password):
    await c.send("AUTHENTICATE PLAIN")
    await c.expect(lambda l: "AUTHENTICATE +" in l, timeout=10)
    payload = b"\0" + account.encode() + b"\0" + password.encode()
    await c.send("AUTHENTICATE " + base64.b64encode(payload).decode())
    await c.expect(lambda l: " 903 " in l or " 904 " in l or " 905 " in l, timeout=10)


async def register_account(host, port, account, password):
    """One-shot account creation."""
    async with IrcClient(host, port, nick=account) as c:
        await c.send("CAP LS 302")
        await c.send("CAP END")
        await c.register()
        await drain_motd(c)
        await c.send(f"REGISTER {account} {account}@test.local {password}")
        # 944 = REGISTER_SUCCESS or a fail numeric.  Tolerate "already
        # registered" so the test can rerun against a stateful container.
        await c.expect(
            lambda l: (
                " 944 " in l
                or "REGISTER " in l and ("SUCCESS" in l or "EXISTS" in l)
                or "ACCOUNT_EXISTS" in l
            ),
            timeout=10,
        )
