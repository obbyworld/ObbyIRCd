import asyncio
import json
import re
import secrets
import subprocess
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from lib.accounts import connect, register_account
from lib.container import IrcdContainer
from lib.irc import IrcClient

BACKEND_HOST = "webpush.test"
VAPID_KEY = "BTestVapidPublicKey0123456789abcdefghijklmnopqrstuvwxyz_-"
KEYS = "p256dh=BPublicKeyOfTheBrowser;auth=AuthSecret"
PASSWORD = "testpw1234"
CONF = "/home/obbyircd/obby/conf"

BACKEND_SCRIPT = f"""
import json, os, ssl
from http.server import BaseHTTPRequestHandler, HTTPServer
open("/tmp/cert.pem", "w").write(os.environ["CERT"])
open("/tmp/key.pem", "w").write(os.environ["KEY"])
open("/tmp/pushes.log", "w").close()
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({{"publicKey": "{VAPID_KEY}"}}).encode()
        self.send_response(200 if self.path == "/push/vapid-key" else 404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def do_POST(self):
        payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        with open("/tmp/pushes.log", "a") as log:
            log.write(json.dumps(payload) + "\\n")
        body = json.dumps({{"status": 201}}).encode()
        self.send_response(200 if self.path == "/push/send" else 404)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/tmp/cert.pem", "/tmp/key.pem")
server = HTTPServer(("0.0.0.0", 443), Handler)
server.socket = ctx.wrap_socket(server.socket, server_side=True)
print("serving", flush=True)
server.serve_forever()
"""


def docker(*args, **kwargs):
    return subprocess.run(["docker", *args], check=True, capture_output=True, text=True, **kwargs).stdout


def self_signed_cert(host):
    with tempfile.TemporaryDirectory() as tmp:
        cert, key = Path(tmp) / "cert.pem", Path(tmp) / "key.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1",
             "-keyout", key, "-out", cert, "-subj", f"/CN={host}",
             "-addext", f"subjectAltName=DNS:{host}"],
            check=True, capture_output=True,
        )
        return cert.read_text(), key.read_text()


@pytest.fixture
def network():
    name = f"webpush-e2e-{secrets.token_hex(4)}"
    docker("network", "create", name)
    try:
        yield name
    finally:
        subprocess.run(["docker", "network", "rm", name], capture_output=True)


@pytest.fixture
def backend(network):
    cert, key = self_signed_cert(BACKEND_HOST)
    name = docker(
        "run", "-d", "--network", network, "--network-alias", BACKEND_HOST,
        "-e", f"CERT={cert}", "-e", f"KEY={key}",
        "python:3.12-alpine", "python", "-c", BACKEND_SCRIPT,
    ).strip()
    try:
        deadline = time.time() + 30
        while "serving" not in docker("logs", name):
            assert time.time() < deadline, "backend never started"
            time.sleep(0.5)
        yield SimpleNamespace(cert=cert, name=name)
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


@pytest.fixture
def configured_ircd(network, backend):
    env = {"WEBPUSH_BACKEND_URL": f"https://{BACKEND_HOST}", "WEBPUSH_BACKEND_KEY": "k"}
    c = IrcdContainer(network=network, env=env).up()
    try:
        c.wait_ready()
        # The https client loads its CA bundle once at boot, so we restart for it to trust the backend.
        c.append_file(f"{CONF}/tls/curl-ca-bundle.crt", backend.cert)
        c.restart()
        yield c
    finally:
        c.down()


async def cap_ls(port):
    async with IrcClient("127.0.0.1", port, nick="caps") as c:
        await c.send("CAP LS 302")
        await c.expect(lambda l: " LS " in l and " LS * " not in l)
        return " ".join(c.lines)


async def send_batch(client, target, lines, tag):
    await client.send(f"BATCH +{tag} draft/multiline {target}")
    for line in lines:
        await client.send(f"@batch={tag} PRIVMSG {target} :{line}")
    await client.send(f"BATCH -{tag}")


async def test_webpush_is_hidden_without_a_backend(ircd):
    assert "draft/webpush" not in await cap_ls(ircd.host_port(6697))


async def test_webpush_offers_the_backend_key_and_registers_https_endpoints(configured_ircd):
    host, port = "127.0.0.1", configured_ircd.host_port(6697)
    await register_account(host, port, "pusher", PASSWORD)
    c = await connect(host, port, "pusher", ["sasl", "cap-notify"], "pusher", PASSWORD)
    try:
        if not any(f"VAPID={VAPID_KEY}" in l for l in c.lines):
            await c.expect(f"VAPID={VAPID_KEY}", timeout=20)
        assert "draft/webpush" in await cap_ls(port)

        await c.send(f"WEBPUSH REGISTER https://push.example/sub1 {KEYS}")
        assert "FAIL" not in await c.expect(lambda l: "WEBPUSH" in l, timeout=10)

        await c.send(f"WEBPUSH REGISTER http://push.example/sub2 {KEYS}")
        assert "FAIL WEBPUSH INVALID_PARAMS REGISTER" in await c.expect(lambda l: "WEBPUSH" in l, timeout=10)
    finally:
        await c.__aexit__(None, None, None)


def pushed_requests(backend):
    log = docker("exec", backend.name, "cat", "/tmp/pushes.log")
    return [json.loads(line) for line in log.splitlines()]


def pushed_payloads(backend):
    return [request["payload"] for request in pushed_requests(backend)]


async def pushes_after_settling(backend, count, timeout=10):
    deadline = time.time() + timeout
    while len(pushed_payloads(backend)) < count and time.time() < deadline:
        await asyncio.sleep(0.2)
    # We wait a moment longer so the backend also logs any duplicate push.
    await asyncio.sleep(1)
    return pushed_payloads(backend)


async def test_an_account_with_several_sessions_gets_one_push_per_message(configured_ircd, backend):
    host, port = "127.0.0.1", configured_ircd.host_port(6697)
    caps = ["sasl", "draft/persistence"]
    await register_account(host, port, "multi", PASSWORD)
    head = await connect(host, port, "multi", caps, "multi", PASSWORD)
    second = await connect(host, port, "multi", caps, "multi", PASSWORD)
    sender = await connect(host, port, "sender", ["message-tags"])
    try:
        await head.send(f"WEBPUSH REGISTER https://push.example/one {KEYS}")
        assert "FAIL" not in await head.expect(lambda l: "WEBPUSH" in l, timeout=10)
        for c in (head, sender):
            await c.send("JOIN #room")
            await c.expect(lambda l: " 366 " in l, timeout=10)

        await sender.send("PRIVMSG #room :multi: are you there")
        assert len(await pushes_after_settling(backend, 1)) == 1

        await sender.send("PRIVMSG multi :hello in private")
        payloads = await pushes_after_settling(backend, 2)
        assert len(payloads) == 2
        assert "hello in private" in payloads[1]
    finally:
        for c in (head, second, sender):
            await c.__aexit__(None, None, None)


async def test_a_multiline_batch_pushes_once(configured_ircd, backend):
    host, port = "127.0.0.1", configured_ircd.host_port(6697)
    await register_account(host, port, "batched", PASSWORD)
    await register_account(host, port, "batcher", PASSWORD)
    target = await connect(host, port, "batched", ["sasl"], "batched", PASSWORD)
    sender = await connect(
        host, port, "batcher", ["sasl", "message-tags", "batch", "draft/multiline"], "batcher", PASSWORD,
    )
    try:
        await target.send(f"WEBPUSH REGISTER https://push.example/batch {KEYS}")
        assert "FAIL" not in await target.expect(lambda l: "WEBPUSH" in l, timeout=10)
        for c in (target, sender):
            await c.send("JOIN #room")
            await c.expect(lambda l: " 366 " in l, timeout=10)

        await send_batch(sender, "#room", ["batched: first line", "batched: second line", "third line"], "chan")
        payloads = await pushes_after_settling(backend, 1)
        assert len(payloads) == 1
        assert "batched: second line" in payloads[0]

        await send_batch(sender, "batched", ["", "two", "three"], "dm")
        payloads = await pushes_after_settling(backend, 2)
        assert len(payloads) == 2
        assert payloads[1].endswith(":two")

        long_lines = ["x" * 340 for _ in range(14)] + ["batched: at the end"]
        await send_batch(sender, "#room", long_lines, "long")
        assert len(await pushes_after_settling(backend, 3)) == 3
    finally:
        for c in (target, sender):
            await c.__aexit__(None, None, None)


async def test_pushes_from_one_chat_share_a_topic(configured_ircd, backend):
    host, port = "127.0.0.1", configured_ircd.host_port(6697)
    await register_account(host, port, "topical", PASSWORD)
    target = await connect(host, port, "topical", ["sasl"], "topical", PASSWORD)
    talker = await connect(host, port, "talker", ["message-tags"])
    other = await connect(host, port, "other", ["message-tags"])
    try:
        await target.send(f"WEBPUSH REGISTER https://push.example/topic {KEYS}")
        assert "FAIL" not in await target.expect(lambda l: "WEBPUSH" in l, timeout=10)
        for c in (target, talker):
            await c.send("JOIN #room")
            await c.expect(lambda l: " 366 " in l, timeout=10)

        await talker.send("PRIVMSG #room :topical: one")
        await talker.send("PRIVMSG #room :topical: two")
        await other.send("PRIVMSG topical :a private hello")
        await pushes_after_settling(backend, 3)
        topics = {r["payload"].rsplit(":", 1)[1]: r["topic"] for r in pushed_requests(backend)}
        room_first, room_second, private = topics[" one"], topics[" two"], topics["a private hello"]

        assert room_first == room_second
        assert private != room_first
        assert all(re.fullmatch(r"[A-Za-z0-9_-]{1,32}", t) for t in (room_first, private))
    finally:
        for c in (target, talker, other):
            await c.__aexit__(None, None, None)
