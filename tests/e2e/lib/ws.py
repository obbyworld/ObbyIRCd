from websockets.asyncio.client import connect
from websockets.exceptions import ConnectionClosed

from lib.irc import IrcClient


class WsIrcClient(IrcClient):
    """IRC over a plain-text WebSocket, one IRC line per frame."""

    def __init__(self, host: str, port: int, nick: str = "tester", forwarded_for: str | None = None):
        super().__init__(host, port, nick)
        self.headers = {"X-Forwarded-For": forwarded_for} if forwarded_for else {}

    async def __aenter__(self):
        self.ws = await connect(f"ws://{self.host}:{self.port}/", additional_headers=self.headers)
        return self

    async def __aexit__(self, *_):
        await self.ws.close()

    async def send(self, line: str):
        await self.ws.send(line)

    async def readline(self) -> bytes:
        try:
            return (await self.ws.recv()).encode() + b"\n"
        except ConnectionClosed:
            return b""
