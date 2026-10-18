import secrets
import subprocess
import tempfile
import time
from pathlib import Path

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
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({{"publicKey": "{VAPID_KEY}"}}).encode()
        self.send_response(200 if self.path == "/push/vapid-key" else 404)
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
        yield cert
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


@pytest.fixture
def configured_ircd(network, backend):
    env = {"WEBPUSH_BACKEND_URL": f"https://{BACKEND_HOST}", "WEBPUSH_BACKEND_KEY": "k"}
    c = IrcdContainer(network=network, env=env).up()
    try:
        c.wait_ready()
        # The https client loads its CA bundle once at boot, so we restart for it to trust the backend.
        c.append_file(f"{CONF}/tls/curl-ca-bundle.crt", backend)
        c.restart()
        yield c
    finally:
        c.down()


async def cap_ls(port):
    async with IrcClient("127.0.0.1", port, nick="caps") as c:
        await c.send("CAP LS 302")
        await c.expect(lambda l: " LS " in l and " LS * " not in l)
        return " ".join(c.lines)


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
