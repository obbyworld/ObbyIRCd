"""CHATHISTORY replays a multiline message as a nested draft/multiline batch
opened by its sender, the way the message was delivered live."""

import pytest

from lib.accounts import connect, register_account
from lib.container import IrcdContainer

CAPS = ["sasl", "message-tags", "batch", "draft/multiline", "server-time", "draft/chathistory"]
PASSWORD = "testpw1234"


@pytest.fixture
def ircd():
    c = IrcdContainer().up()
    try:
        c.wait_ready()
        yield c
    finally:
        c.down()


def source_of(line):
    return line.split(" BATCH ")[0].split(" ")[-1]


async def lines_until_quiet(client):
    lines = []
    while True:
        try:
            lines.append(await client.expect(lambda l: True, timeout=2))
        except TimeoutError:
            return lines


async def test_a_replayed_multiline_batch_names_its_sender(ircd):
    host, port = "127.0.0.1", ircd.host_port(6697)
    await register_account(host, port, "poster", PASSWORD)
    poster = await connect(host, port, "poster", CAPS, "poster", PASSWORD)
    reader = await connect(host, port, "reader", CAPS)
    try:
        await poster.send("JOIN #room")
        await poster.expect(lambda l: " 366 " in l, timeout=10)
        await poster.send("MODE #room +H 100:1d")
        await reader.send("JOIN #room")
        await reader.expect(lambda l: " 366 " in l, timeout=10)
        await poster.send("BATCH +ml draft/multiline #room")
        for text in ["first", "second"]:
            await poster.send(f"@batch=ml PRIVMSG #room :{text}")
        await poster.send("BATCH -ml")
        await lines_until_quiet(poster)
        await lines_until_quiet(reader)

        await reader.send("CHATHISTORY LATEST #room * 10")
        replay = await lines_until_quiet(reader)
        opener = next(l for l in replay if " draft/multiline #room" in l)
        batch_id = opener.split(" BATCH +")[1].split(" ")[0]
        closer = next(l for l in replay if l.endswith(f" BATCH -{batch_id}"))

        assert source_of(opener).startswith(":poster!")
        assert source_of(closer).startswith(":poster!")
    finally:
        for c in (poster, reader):
            await c.__aexit__(None, None, None)
