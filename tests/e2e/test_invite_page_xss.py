"""The invite page escapes channel names in every link it renders."""

import urllib.request

import pytest

from lib.accounts import connect, register_account
from lib.container import IrcdContainer

PASSWORD = "InvitePw1!"
REFLECTED = '"><script>alert(1)</script>'
STORED = '#c"><svg/onload=alert(3)>'


@pytest.fixture
def invite_ircd():
    # The container publishes 8080, so we serve the invite page there and move websockets aside.
    env = {"INVITE_PAGE_PORT": "8080", "WS_PORT": "8081", "INVITE_WEB_URL": "https://web.test/"}
    c = IrcdContainer(env=env).up()
    try:
        c.wait_ready()
        yield c
    finally:
        c.down()


def get_page(ircd, path):
    url = f"http://127.0.0.1:{ircd.host_port(8080)}{path}"
    with urllib.request.urlopen(url, timeout=10) as resp:
        return resp.read().decode()


def test_reflected_channel_is_escaped(invite_ircd):
    page = get_page(invite_ircd, "/c/%22%3E%3Cscript%3Ealert(1)%3C/script%3E")
    assert REFLECTED not in page
    # We compare lowercased pages because curl builds percent-encode in uppercase and the built-in url code in lowercase.
    encoded = "%23%22%3e%3cscript%3ealert%281%29%3c%2fscript%3e"
    assert f'href="ircs://irc.test.local:6697/{encoded}"' in page.lower()
    assert f"channel={encoded}" in page.lower()


async def create_invite(ircd, channel):
    host, port = "127.0.0.1", ircd.host_port(6697)
    await register_account(host, port, "invowner", PASSWORD)
    c = await connect(host, port, "invowner", ["sasl"], "invowner", PASSWORD)
    try:
        await c.send(f"INVITELINK CREATE {channel}")
        return await c.expect(lambda l: l.split()[1:2] in (["INVITELINK"], ["FAIL"]), timeout=10)
    finally:
        await c.__aexit__()


async def test_stored_channel_is_escaped(invite_ircd):
    reply = await create_invite(invite_ircd, STORED)
    assert reply.split()[1] == "INVITELINK", reply
    page = get_page(invite_ircd, "/i/" + reply.split()[2])
    assert STORED[2:] not in page
    assert 'href="ircs://irc.test.local:6697/%23c%22%3e%3csvg%2fonload%3dalert%283%29%3e"' in page.lower()


async def test_invalid_channel_is_refused(invite_ircd):
    reply = await create_invite(invite_ircd, "#a\x07b")
    assert "FAIL INVITELINK INVALID_CHANNEL" in reply
