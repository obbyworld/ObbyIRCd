import os
import secrets
import shutil
import subprocess
import tempfile
import time
from pathlib import Path


class IrcdContainer:
    """One isolated obbyircd container for IRCd-only smoke tests."""

    def __init__(
        self,
        image: str | None = None,
        env: dict | None = None,
        bind_data: bool = False,
        with_voice_bridge: bool = False,
        network: str | None = None,
    ):
        self.image = image or os.environ.get("OBBYIRCD_IMAGE", "obbyircd:e2e")
        self.name = f"obbyircd-e2e-{secrets.token_hex(4)}"
        self.bind_data = bind_data
        self.with_voice_bridge = with_voice_bridge
        self.network = network
        self.voice_bridge_volume = (
            f"voicebridge-{secrets.token_hex(4)}" if with_voice_bridge else None
        )
        self.data_root = Path(tempfile.mkdtemp(prefix="obbyircd-e2e-")) if bind_data else None
        if self.data_root:
            for sub in ("conf", "data", "logs", "tls", "custom-modules"):
                (self.data_root / sub).mkdir(parents=True, exist_ok=True)
        self.env = self._build_env(env or {})

    def _build_env(self, extra: dict):
        env = {
            "SERVER_NAME": "irc.test.local",
            "NETWORK_NAME": "TestNet",
            "ADMIN_EMAIL": "test@test.local",
            "MOTD_TEXT": "test",
            "OPER_NAME": "admin",
            "OPER_PASSWORD": secrets.token_hex(8),
            "SSL_PORT": "6697",
            "WS_PORT": "8080",
        }
        env.update(extra)
        return env

    def up(self):
        if self.voice_bridge_volume:
            subprocess.run(
                ["docker", "volume", "create", self.voice_bridge_volume],
                check=True, capture_output=True,
            )
        cmd = [
            "docker", "run", "-d", "--name", self.name,
            "-p", "127.0.0.1::6697",
            "-p", "127.0.0.1::8080",
        ]
        if self.bind_data and self.data_root:
            for sub in ("conf", "data", "logs", "tls", "custom-modules"):
                cmd += ["-v", f"{self.data_root}/{sub}:/home/obbyircd/obby/{sub}"]
        if self.voice_bridge_volume:
            cmd += ["-v", f"{self.voice_bridge_volume}:/run/obbyirc"]
        if self.network:
            cmd += ["--network", self.network]
        for k, v in self.env.items():
            cmd += ["-e", f"{k}={v}"]
        cmd.append(self.image)
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        return self

    def down(self):
        subprocess.run(["docker", "rm", "-f", self.name], capture_output=True)
        if self.voice_bridge_volume:
            subprocess.run(
                ["docker", "volume", "rm", "-f", self.voice_bridge_volume],
                capture_output=True,
            )
        if self.data_root:
            shutil.rmtree(self.data_root, ignore_errors=True)

    def host_port(self, container_port: int) -> int:
        out = subprocess.check_output(
            ["docker", "port", self.name, str(container_port)], text=True
        ).strip()
        return int(out.splitlines()[0].rsplit(":", 1)[1])

    def logs(self) -> str:
        result = subprocess.run(
            ["docker", "logs", self.name],
            capture_output=True, text=True,
        )
        return result.stdout + result.stderr

    def append_file(self, path: str, text: str):
        subprocess.run(
            ["docker", "exec", "-i", self.name, "sh", "-c", f'cat >> "{path}"'],
            input=text, check=True, capture_output=True, text=True,
        )

    def restart(self, timeout=120):
        starts = self.logs().count("ObbyIRCd started.")
        subprocess.run(["docker", "restart", self.name], check=True, capture_output=True)
        deadline = time.time() + timeout
        while self.logs().count("ObbyIRCd started.") <= starts:
            if time.time() > deadline or not self.is_running():
                raise TimeoutError(f"never restarted: {self.logs()[-2000:]}")
            time.sleep(1)

    def is_running(self) -> bool:
        out = subprocess.check_output(
            ["docker", "inspect", "-f", "{{.State.Running}}", self.name], text=True
        )
        return out.strip() == "true"

    def wait_ready(self, timeout=120):
        deadline = time.time() + timeout
        while time.time() < deadline:
            log = self.logs()
            if "ObbyIRCd started." in log or "is now listening" in log:
                return
            time.sleep(1)
        raise TimeoutError(f"never ready: {self.logs()[-2000:]}")
