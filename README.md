# ObbyIRCd

ObbyIRCd is a fork of [UnrealIRCd](https://www.unrealircd.org/) — an open source IRC server with over 25 years of history. It builds on UnrealIRCd's advanced, modular, and secure foundation and extends it with native account registration, JavaScript scripting, WebRTC voice channels, and a REST/JWT backend — all batteries-included.

> UnrealIRCd is © its respective authors. ObbyIRCd carries the same GPLv2 license. Respect and credit go to the UnrealIRCd team for the extraordinary foundation this fork builds on.

---

## What ObbyIRCd adds

| Module | Description |
|---|---|
| `account-registration` | Native NickServ-style account system backed by SQLite (Argon2id hashed passwords) |
| `account-recovery` | Password recovery flow with email verification |
| `account-notify` / `account-tag` | IRCv3 account-notify and account-tag extensions |
| `authtoken` | Token-based IRC authentication |
| `metadata` | IRCv3 METADATA storage for users and channels |
| `persistence` | Channel and user state persistence across restarts |
| `filehost` | Built-in temporary image/file hosting endpoint |
| `smtp` | Transactional email support (registration, verification) |
| `obbyscript` | Embed JavaScript logic directly into the IRCd (QuickJS) |
| `voice-channels` | `^`-prefixed voice channels bridged to a WebRTC SFU + TURN server |
| **hosted-backend** | Go REST/JWT API server that powers account management, channel metadata, and image hosting |

All inherited [UnrealIRCd features](https://www.unrealircd.org/docs/About_UnrealIRCd) are included: full IRCv3, SSL/TLS, cloaking, JSON-RPC, anti-flood/anti-spam, GeoIP, remote includes, and more.

---

## Versions

- ObbyIRCd 6 is based on **UnrealIRCd 6** (stable since December 2021).
- Current version: **6.2.5-git**
- Upstream release notes: [UnrealIRCd releases](https://www.unrealircd.org/docs/UnrealIRCd_releases)

---

## Installing from source (Linux / macOS)

### 1. Prerequisites

Install the required libraries for your distribution before building.

**Debian / Ubuntu**
```bash
sudo apt-get install build-essential libssl-dev libpcre2-dev \
    libargon2-dev libsodium-dev libjansson-dev libcurl4-openssl-dev \
    libsqlite3-dev pkg-config
```

**RHEL / Fedora / AlmaLinux**
```bash
sudo dnf install gcc make openssl-devel pcre2-devel libargon2-devel \
    libsodium-devel jansson-devel libcurl-devel sqlite-devel pkgconf
```

**Alpine Linux**
```bash
apk add build-base openssl-dev pcre2-dev argon2-dev libsodium-dev \
    jansson-dev curl-dev sqlite-dev pkgconf
```

**macOS (Homebrew)**
```bash
brew install openssl pcre2 argon2 libsodium jansson curl sqlite pkg-config
```

### 2. Create a dedicated user

Running the IRCd as a non-root user is strongly recommended.

```bash
useradd -r -m -d /home/obbyircd -s /bin/bash obbyircd
```

### 3. Clone the repository

```bash
git clone https://github.com/your-org/obbyircd.git
cd obbyircd
```

### 4. Run the configuration wizard

The interactive `./Config` script lets you set installation paths, enable optional features, and generate TLS certificates.

```bash
./Config
```

For an unattended build (uses safe defaults and installs to `~/obby`):

```bash
./Config -quick
```

### 5. Build and install

```bash
make
make install
```

### 6. Configure

Navigate to your installation and copy the example config:

```bash
cd ~/obby
cp conf/examples/example.conf conf/obbyircd.conf
$EDITOR conf/obbyircd.conf
```

At minimum set `me::name`, `me::info`, and your `listen` blocks. The [UnrealIRCd configuration docs](https://www.unrealircd.org/docs/Configuration) apply — all directives work the same way.

To load ObbyIRCd's extra modules, add them to `conf/modules.default.conf` or your main config:

```
loadmodule "account-registration";
loadmodule "metadata";
loadmodule "obbyscript";
loadmodule "voice-channels";
/* ... etc */
```

### 7. Start the server

```bash
./bin/obbyircd
```

To keep it running in the foreground (useful behind a process supervisor):

```bash
./bin/obbyircd -F
```

### 8. Optional: systemd service

A ready-made unit file is included in `extras/startup/`:

```bash
sudo cp extras/startup/obbyircd.service /etc/systemd/system/
# Edit the User=/ExecStart= lines if your install path differs
sudo systemctl daemon-reload
sudo systemctl enable --now obbyircd
```

---

## Docker / container deployment

ObbyIRCd ships a production-ready Docker image that builds everything from source.

### Quick start

```bash
cp .env.example .env          # edit SERVER_NAME, NETWORK_NAME, ADMIN_EMAIL, etc.
docker compose up -d
docker compose logs -f obbyircd
```

On first run the container:
1. Populates the `conf` volume with default config files.
2. Renders `obbyircd.conf` from environment variables.
3. Issues a self-signed TLS certificate (replace before production traffic).
4. Generates random cloak keys if `CLOAK_KEY1/2/3` are not set.

### Key ports

| Port | Protocol | Purpose |
|---|---|---|
| `6697` | TLS IRC | Standard IRC-over-TLS |
| `8080` | WebSocket | Plain WS — front with TLS proxy in production |
| `8600` | JSON-RPC | UnrealIRCd RPC (internal) |

### Environment variables

| Variable | Default | Notes |
|---|---|---|
| `SERVER_NAME` | `irc.example.com` | Hostname clients connect to |
| `NETWORK_NAME` | `ObbyNetwork` | Shown in MOTD / `005` |
| `ADMIN_EMAIL` | `admin@example.com` | Used in `admin {}` block |
| `OPER_NAME` | `admin` | Network admin oper login |
| `OPER_PASSWORD` | *(generated)* | Printed once to container log on first run |
| `CLOAK_KEY1/2/3` | *(generated)* | Set explicitly for stable cloaks across restarts |
| `SSL_PORT` | `6697` | Internal TLS port |
| `WS_PORT` | `8080` | Internal WebSocket port |
| `FILEHOST_URL` | *(unset)* | Set to enable the `filehost {}` block |
| `RPC_PASSWORD` | *(unset)* | Set to enable JSON-RPC |

### Volumes

| Volume | Container path | Purpose |
|---|---|---|
| `obbyircd_conf` | `/home/obbyircd/obby/conf` | Configuration files |
| `obbyircd_data` | `/home/obbyircd/obby/data` | Persistent state (account DB, bans, channel DB) |
| `obbyircd_logs` | `/home/obbyircd/obby/logs` | Server logs |
| `obbyircd_tls` | `/home/obbyircd/obby/tls` | TLS certificate and key |
| `obbyircd_custom_modules` | `/home/obbyircd/obby/custom-modules` | Drop `.c` files here to compile extra modules without rebuilding the image |

See [docker/README.md](docker/README.md) for the full Docker reference.

---

## Hosted backend

The hosted-backend (Go REST/JWT API + WebRTC SFU + TURN that works alongside the IRCd for account management, channel metadata, and image hosting) lives in its own repository: <https://github.com/obbyworld/hosted-backend>. The published image `obbyworld/obby-api:latest` is pulled by this repo's `compose.yaml`, so `docker compose up -d` brings up the full stack with no extra steps.

To build the backend from source, clone its repo separately and follow the build instructions there.

---

## Supported systems

ObbyIRCd targets all major *NIX platforms. Tested configurations include:

- **Linux:** Debian 10–13, Ubuntu 18.04–26.04, Alpine 3.19
- **macOS:** Recent releases via Homebrew
- **Architecture:** x86_64, arm64

Windows is not a supported target at this time.

---

## Documentation and support

- **UnrealIRCd docs** (configuration, modules, protocol): https://www.unrealircd.org/docs/
- **UnrealIRCd FAQ**: https://www.unrealircd.org/docs/FAQ
- **UnrealIRCd bug tracker**: https://bugs.unrealircd.org
- **IRC support** (upstream): [#unreal-support on irc.unrealircd.org](ircs://irc.unrealircd.org:6697/unreal-support)

* [SECURITY.md](https://github.com/unrealircd/unrealircd/blob/unreal60_dev/SECURITY.md#security-policy) - How to report security issues
* [LICENSE](https://github.com/unrealircd/unrealircd/blob/unreal60_dev/LICENSE) - LICENSE: GPLv2 or later
* [Contributing](https://www.unrealircd.org/docs/Contributing) - How to help: report bugs, test, write or translate documentations, ..
For ObbyIRCd-specific issues and contributions, open an issue or pull request in this repository.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Upstream UnrealIRCd contributions are welcome at https://www.unrealircd.org/docs/Contributing.
