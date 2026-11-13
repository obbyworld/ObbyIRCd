"""Link previews are on by default, can be turned off, and never fetch internal addresses."""

import asyncio
import secrets
import subprocess

import pytest

from lib.container import IrcdContainer
from lib.irc import IrcClient

CONF = "/home/obbyircd/obby/conf"
HITS = "/tmp/ssrf-hits"
LISTENER = f"""
import socket
s = socket.socket(socket.AF_INET6)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("::", 9443))
s.listen(16)
while True:
    conn, addr = s.accept()
    open("{HITS}", "a").write(repr(addr) + "\\n")
    conn.close()
"""
REDIRECTOR = f"""
import http.server, ssl
class Redirect(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        open("{HITS}-redirector", "a").write(self.path + "\\n")
        self.send_response(302)
        self.send_header("Location", "https://127.0.0.1:9443/redirected")
        self.send_header("Content-Length", "0")
        self.end_headers()
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/tmp/redir.pem", "/tmp/redir.key")
server = http.server.HTTPServer(("0.0.0.0", 9444), Redirect)
server.socket = ctx.wrap_socket(server.socket, server_side=True)
server.serve_forever()
"""
INTERNAL_URLS = [
    "https://127.0.0.1:9443/ip",
    "https://127.1:9443/short",
    "https://2130706433:9443/decimal",
    "https://[::1]:9443/v6",
    "https://localhost:9443/localhost",
    "https://evil@127.0.0.1:9443/userinfo",
    "https://a:b@127.0.0.1:9443/userinfo-password",
    "https://a:b@169.254.169.254/metadata",
    "https://example.com#@127.0.0.1:9443/fragment",
]


def docker_exec(ircd, *cmd, detach=False):
    flags = ["-d"] if detach else []
    return subprocess.run(
        ["docker", "exec", *flags, ircd.name, *cmd], capture_output=True, text=True
    ).stdout


def hits(ircd, log=HITS):
    return docker_exec(ircd, "sh", "-c", f"cat {log} 2>/dev/null")


async def post(ircd, urls):
    async with IrcClient("127.0.0.1", ircd.host_port(6697), nick="linker") as c:
        await c.register()
        await c.expect(lambda l: " 001 " in l, timeout=30)
        await c.send("JOIN #links")
        await c.expect(lambda l: " 366 " in l)
        for url in urls:
            await c.send(f"PRIVMSG #links :look {url}")
        await c.send("PING :done")
        await c.expect("PONG")
        await asyncio.sleep(5)


PREVIEWS_OFF = "\nfilehosts { link-previews no; };\n"
# A documentation range the fetcher treats as public, so we can serve a public address without internet.
PUBLIC_SUBNET = "203.0.113.0/24"


def trust_redirector_cert(ircd):
    # The https client loads its CA bundle once at boot, so this runs before the restart.
    docker_exec(
        ircd, "openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048", "-days", "1",
        "-keyout", "/tmp/redir.key", "-out", "/tmp/redir.pem", "-subj", f"/CN={ircd.name}",
        "-addext", f"subjectAltName=DNS:{ircd.name}",
    )
    docker_exec(ircd, "sh", "-c", f"cat /tmp/redir.pem >> {CONF}/tls/curl-ca-bundle.crt")


def ircd_with_listener(subnet=None, conf_extra=""):
    # On a user network the container name resolves through Docker DNS to the container's own address.
    network = f"ssrf-e2e-{secrets.token_hex(4)}"
    subnet_args = ["--subnet", subnet] if subnet else []
    subprocess.run(["docker", "network", "create", *subnet_args, network], check=True, capture_output=True)
    c = IrcdContainer(network=network).up()
    try:
        c.wait_ready()
        if conf_extra:
            c.append_file(f"{CONF}/obbyircd.conf", conf_extra)
        trust_redirector_cert(c)
        c.restart()
        docker_exec(c, "python3", "-c", LISTENER, detach=True)
        docker_exec(c, "python3", "-c", REDIRECTOR, detach=True)
        yield c
    finally:
        c.down()
        subprocess.run(["docker", "network", "rm", network], capture_output=True)


@pytest.fixture
def public_ircd():
    yield from ircd_with_listener(PUBLIC_SUBNET)


@pytest.fixture
def public_previews_off():
    yield from ircd_with_listener(PUBLIC_SUBNET, PREVIEWS_OFF)


@pytest.fixture
def private_ircd():
    yield from ircd_with_listener()


async def test_previews_are_on_by_default(public_ircd):
    await post(public_ircd, [f"https://{public_ircd.name}:9443/default"])
    assert hits(public_ircd) != ""


async def test_previews_can_be_turned_off(public_previews_off):
    await post(public_previews_off, [f"https://{public_previews_off.name}:9443/off"])
    assert hits(public_previews_off) == ""


async def test_internal_addresses_are_never_fetched(private_ircd):
    resolves_to_private = f"https://{private_ircd.name}:9443/dns"
    await post(private_ircd, INTERNAL_URLS + [resolves_to_private])
    assert hits(private_ircd) == ""


async def test_long_public_hostname_is_fetched(public_ircd):
    long_name = "a" * 40 + "." + "b" * 40
    network = f"ssrf-e2e-{secrets.token_hex(4)}"
    subprocess.run(["docker", "network", "create", "--subnet", "198.51.100.0/24", network], check=True, capture_output=True)
    try:
        subprocess.run(
            ["docker", "network", "connect", "--alias", long_name, network, public_ircd.name],
            check=True, capture_output=True,
        )
        await post(public_ircd, [f"https://{long_name}:9443/long"])
        assert "198.51.100." in hits(public_ircd)
    finally:
        subprocess.run(["docker", "network", "disconnect", "-f", network, public_ircd.name], capture_output=True)
        subprocess.run(["docker", "network", "rm", network], capture_output=True)


async def test_redirect_to_internal_address_is_not_followed(public_ircd):
    await post(public_ircd, [f"https://{public_ircd.name}:9444/redirect"])
    assert "/redirect" in hits(public_ircd, f"{HITS}-redirector")
    assert hits(public_ircd) == ""
