# ObbyIRCd Architecture

ObbyIRCd is an [UnrealIRCd 6](https://www.unrealircd.org/) fork maintained
by [obbyworld](https://github.com/obbyworld). It tracks
`unreal60_dev` upstream and adds a coherent stack of modules, an embedded
scripting layer (JavaScript + Python), a sibling Go hosted-backend that
handles WebRTC SFU + TURN + REST/JWT, and a migration toolchain for
importing accounts and channels from Ergo / Anope / Atheme.

This document describes the code, the runtime, and the deployment
topology — specifically the Coolify deployment targeting the arm64 h4ks
VPS as a successor to the existing UnrealIRCd installation there.

## 1. Lineage and positioning

| Layer | Comes from | Notes |
|-------|------------|-------|
| Core IRCd | UnrealIRCd 6.2.5 (`unreal60_dev`) | Periodically merged from `upstream/unreal60_dev` |
| obbyworld modules | `src/modules/*.c`, `include/obsidian.h` | First-class in the tree, not third-party |
| Vendored from `valware/unrealircd-contrib` | `react.c`, `redact.c`, `channel-rename.c` | Imported in-tree, kept in sync manually |
| Hosted services | [`obbyworld/hosted-backend`](https://github.com/obbyworld/hosted-backend) (Go, separate repo) | Separate binary, talks to the IRCd over JSON-RPC + an AF_UNIX socket. Published as `obbyworld/obby-api:latest` and pulled by this repo's compose. |
| Migration tooling | `tools/obbyircd-migrate/` (Go) | Stand-alone CLI; reads Ergo/Anope/Atheme → writes ObbyIRCd stores |

GPLv2, inherited from upstream. UnrealIRCd authorship and credit are
preserved everywhere.

## 2. Repository layout

```
.
├── Config, configure, configure.ac, autogen.sh
├── Makefile.in, BSDmakefile, Makefile.windows
├── obbyircd.in              (init wrapper template, substituted at build)
├── compose.yaml             (full stack: obbyircd built locally + obby-api pulled from obbyworld/obby-api + obby web pulled from obbyworld/obby, frontend opt-in)
├── docker/
│   ├── Dockerfile           (single Alpine stage, builds from this checkout)
│   ├── docker-entrypoint.sh (first-run template render + custom-module build)
│   ├── obbyircd.conf.template
│   └── README.md
├── src/
│   ├── *.c                  (core IRCd: dispatch, parser, networking, TLS, ...)
│   └── modules/*.c          (205 modules; ~20 obbyworld-specific)
├── include/                 (public headers; `obsidian.h` carries the fork's types)
├── doc/
│   ├── conf/
│   │   ├── modules.default.conf
│   │   ├── operclass.default.conf
│   │   ├── snomasks.default.conf
│   │   ├── rpc.modules.default.conf
│   │   └── examples/example.conf*
│   ├── scripts/             (obbyscript example .js shipped as scripts/example.js)
│   └── RELEASE-NOTES.md, tao.of.irc, ...
├── extras/
│   ├── argon2/, c-ares/, jansson/, libsodium/, pcre2/, geoip/   (vendored tarballs)
│   ├── build-tests/         (CI nix harness)
│   └── startup/             (systemd unit, init script)
├── tools/
│   └── obbyircd-migrate/    (Go: Ergo/Anope/Atheme → obbyircd)
├── autoconf/                (m4 macros)
├── .github/                 (CI workflows)
├── .env.example
└── .dockerignore
```

`src/modules/` is the centre of fork gravity — the 20-or-so files
beyond a vanilla UnrealIRCd 6 install make ObbyIRCd what it is.

## 3. Build system

GNU autoconf. Driven by the interactive `./Config` wrapper, which writes
`config.settings` and then invokes `./configure`. `./Config -quick`
takes defaults and is the path the Docker build uses.

Detected optional libs: OpenSSL, PCRE2, Argon2, libsodium, Jansson,
libcurl, SQLite, libcares. `make` builds the IRCd binary plus every
`src/modules/*.c` as a separate `.so`. `make install` lays the tree
into `$PREFIX` (default `~/obby` for interactive, configurable in
`config.settings` for Docker).

### Runtime layout (post `make install`)

```
$PREFIX/
├── bin/obbyircd            (binary)
├── bin/unrealircdctl       (control helper)
├── bin/mkpasswd            (password hashing utility)
├── conf/                   (modules.default.conf, operclass.default.conf, motd.txt, ...)
├── conf/scripts/           (obbyscript autoloads *.js)
├── conf/scripts/python/    (obbypy autoloads *.py)
├── data/
│   ├── obsidian.db         (sqlite — accounts, 2FA, metadata)
│   ├── channel.db          (UnrealDB v101 — persistent channels)
│   ├── tkldb.db            (UnrealDB v4999 — TKL bans)
│   ├── ircd.tune           (tuning)
│   ├── persistence/        (draft/persistence ghost records)
│   └── .oper_password      (auto-generated, mode 600)
├── logs/ircd.log
├── modules/                (compiled core .so)
├── modules/third/          (out-of-tree .so)
├── tls/server.cert.pem, tls/server.key.pem
└── tmp/obbyircd.pid + crash dumps + ephemeral sockets
```

The `obbyircd.in` template substitutes `@BINDIR@`, `@CONFDIR@`,
`@MODULESDIR@`, `@TMPDIR@`, `@PIDFILE@` at `make install` time.

## 4. obbyworld delta vs vanilla UnrealIRCd 6

### 4.1 Modules unique to ObbyIRCd

| Module | Purpose |
|--------|---------|
| `account-registration` | Native NickServ-equivalent: SQLite store, SASL PLAIN/SCRAM-SHA-256, OAuth (GitHub etc.), TOTP 2FA, WebAuthn-BIO. Exposes `obsidianirc.accounts.*` RPC. Fires custom `HOOKTYPE_ACCOUNT_REGISTER` (hook id 133). Argon2id is the only password scheme currently verifiable for live login. |
| `account-recovery` | `draft/account-recovery` (RECOVER + SETPASS) |
| `authtoken` | `draft/authtoken`. Persistent service tokens. `authtoken.validate` RPC method consumed by hosted-backend for IRC ↔ HTTP token auth. |
| `metadata-db` | Persists `draft/metadata-2` keys for authenticated users and `+P` channels to `obsidian.db` across restarts. Pair with the upstream `metadata` module. |
| `persistence` | `draft/persistence`. On disconnect, parks a ghost client in `data/persistence/`; on reconnect (same account) proxies TAGMSG/PRIVMSG/JOIN through the canonical client. |
| `obbyscript` | Embedded Duktape JS VM. `~30 hooks (LOCAL_CONNECT, CHANMSG, NICK_CHANGE, ...), command registration, send/find APIs, full message-tag manipulation. Autoloads `conf/scripts/*.js`. |
| `obbypy` | Embedded CPython 3 via `libpython3-embed`. Feature parity with `obbyscript` — same hook surface, same send/find APIs. Autoloads `conf/scripts/python/*.py`. Both modules can be loaded simultaneously. |
| `filehost` | `draft/FILEHOST`. Server-side link preview metadata tags for URLs in channel PRIVMSGs; queries the hosted-backend for OG metadata. |
| `smtp` | Async SMTP client backing account-registration verification + account-recovery reset mails. Async primitives borrowed from `src/url_unreal.c`. |
| `voice-channels` | `^`-prefix voice channels bridged to the hosted-backend SFU. AF_UNIX socket at `/run/obbyirc/voice.sock`. Clients send RTC frames using the `+obsidianirc/rtc` message tag. Streamer vs. viewer membership is modelled internally but invisible to IRC. |
| `read-marker` | `draft/read-marker` (MARKREAD per-buffer state) |
| `emoji` | Network-level custom emoji pack URL via `draft/custom-emoji` ISUPPORT |
| `react` | `draft/react` (emoji reactions). Imported from `valware/unrealircd-contrib`. |
| `redact` | `draft/message-redaction` (REDACT). Imported from `valware/unrealircd-contrib`. |
| `channel-rename` | Server-side channel renaming, RPC + command. Imported from `valware/unrealircd-contrib`. |

Upstream modules `account-notify`, `account-tag`, `metadata`,
`chathistory`, `multiline`, `named-modes`, `member-roles` are loaded by
default — they pair with the modules above to provide a complete
IRCv3 + obbyworld profile out of the box.

### 4.2 Headers

`include/obsidian.h` declares the fork-wide types — `Account`,
`Metadata`, `TwoFACredential`, the persistence ghost record, plus the
SQLite handle accessors. Every fork module includes this header; vanilla
UnrealIRCd modules do not.

### 4.3 Message tags advertised

Server-side support for the following IRCv3 draft tags is shipped in
this fork (full list grepped from `src/modules/`):

```
draft/account-registration   draft/account-2fa     draft/account-recovery
draft/authtoken              draft/channel-rename  draft/chathistory
draft/extended-isupport      draft/message-redaction
draft/metadata-2             draft/metadata-notify-2
draft/multiline              draft/multiline-concat
draft/named-modes            draft/no-implicit-names
draft/persistence            draft/read-marker
draft/webauthn-rp-id         +obsidianirc/rtc
```

These are the "vendored tags" — they are what makes the obbyworld web
client coherent with this server and not interchangeable with vanilla
UnrealIRCd at the protocol surface.

### 4.4 JSON-RPC methods unique to ObbyIRCd

Routed through the same RPC subsystem upstream documents. Configured
via `rpc.modules.default.conf`.

| Method | Module | Purpose |
|--------|--------|---------|
| `obsidianirc.accounts.list` | account-registration | Paged account enumeration |
| `obsidianirc.accounts.find` | account-registration | Lookup by name |
| `authtoken.validate` | authtoken | Hosted-backend uses this to mint authoritative session bindings |
| `rpc.stats` | rpc (extended) | Historical snapshots (commit `99d705443`) |

## 5. Hosted-backend

Separate Go binary, source at [obbyworld/hosted-backend](https://github.com/obbyworld/hosted-backend), published as `obbyworld/obby-api:latest`. The image is pulled (not built) by this repo's `compose.yaml`. Two integration channels:

1. **JSON-RPC over TCP** (typically `127.0.0.1:8600`, opt-in via
   `RPC_PASSWORD`). The backend authenticates as an RPC user and calls
   `authtoken.validate`, `obsidianirc.accounts.find`, channel RPCs.
2. **AF_UNIX socket** at `/run/obbyirc/voice.sock`. Bidirectional
   JSON: voice-channels.c writes signalling frames (join/leave/streamer
   state), the backend writes ICE candidate negotiation back. Both
   sides share the `obbyircd_voice_bridge` named volume so the socket
   inode survives container restarts.

The backend also runs:

- HTTP REST API on `:8080` (gated by JWT issued from IRC `extjwt`-like
  flow against `authtoken.validate`)
- Coturn-compatible TURN server on `:3478/udp` (REST-secret scheme
  using `VOICE_TURN_SECRET`)
- A small in-process SFU for voice/video

`VOICE_PUBLIC_IP` is advertised in WebRTC ICE candidates and must be
the externally-reachable address of the host (the Coolify host's
public IP).

## 6. Scripting layer

`obbyscript` (JavaScript via Duktape) and `obbypy` (Python via
embedded CPython) are siblings. Same hook surface, same send/find
APIs, same message-tag manipulation. They coexist; pick the language
per script. The host module autoload mechanism is identical:

| Module | Script directory | File pattern |
|--------|------------------|--------------|
| obbyscript | `$CONFDIR/scripts/` | `*.js` |
| obbypy | `$CONFDIR/scripts/python/` | `*.py` |

API surface (both):

- Hook registration: ~30 hook types covering connect/quit, channel
  msg, user msg, nick change, mode change, join/part, server
  link, oper, sasl, rehash
- Command registration: register a new IRC command implemented in the
  script
- Sending: `notice`, `msg`, `raw`, `numeric`, `to_channel`,
  `wallops`
- Lookups: `find_client`, `find_channel`, `find_server`,
  `all_clients`, `all_channels`
- ModData get/set on clients/channels (string-keyed scratch space)
- Message-tag manipulation: `createMtag`, `addMtag`, `findMtag`,
  `mtagsToString`

A reference example ships at `doc/conf/scripts/example.js` and is
copied to `$CONFDIR/scripts/` on first run; it registers a `/JSINFO`
command and exercises a handful of hooks.

## 7. Persistence model

Everything stateful lives in `$DATADIR` (the `obbyircd_data` volume in
Docker, the host bind target on a Coolify deploy with `DATA_BIND`
set).

| File | Format | Owner module | Notes |
|------|--------|--------------|-------|
| `obsidian.db` | SQLite 3 | account-registration, metadata-db, authtoken | Phase-0 schema, PRAGMA-introspected by the migration writer. Tables include `accounts`, `account_metadata`, `auth_tokens`, `twofa_credentials`. |
| `channel.db` | UnrealDB v101 (binary) | channeldb (upstream) | Persistent channels, modes, ban/except/invex lists, topics. Round-trip-verified by the migration tool's mirror parser. |
| `tkldb.db` | UnrealDB v4999 (binary) | tkldb (upstream) | K/G/Z/Q-lines (no X-lines — migration drops with warning). |
| `ircd.tune` | binary | core | Tuning |
| `persistence/` | per-account JSON | persistence | Ghost session records |

## 8. Migration tool — `obbyircd-migrate`

Go binary at `tools/obbyircd-migrate/`. CLI subcommands `tui` /
`read` / `run`. Architecture is reader → intermediate representation
→ writer:

```
┌──────────┐   ┌──────────────┐   ┌──────────┐
│ reader   │ → │ intermediate │ → │ writer   │
│ (per src)│   │     (IR)     │   │ (per dst)│
└──────────┘   └──────────────┘   └──────────┘
```

| Source | Reader | Status |
|--------|--------|--------|
| Atheme `services.db` (opensex) | `internal/readers/atheme` | Fixture + live tested |
| Anope `anope.db` (db_flatfile) | `internal/readers/anope` | Fixture tested |
| Ergo `ircd.db` (BuntDB) | `internal/readers/ergo` | Live-tested against ergochat/ergo |

| Target | Writer | Status |
|--------|--------|--------|
| `obsidian.db` | `internal/writer/obsidian.go` | Schema-introspecting via PRAGMA; writes Phase-0 columns |
| `channel.db` (UnrealDB v101) | `internal/writer/channeldb.go` | Mirror-parser verified |
| `tkldb.db` (UnrealDB v4999) | `internal/writer/tkldb.go` | K/G/Z/Q-line types; X drops with warning |

ACL encoding: founder, account ACL grant, mask ACL grant, akick all
map to `+e ~automode:<modes>:~account:<name>` /
`+e ~automode:<modes>:<n!u@h>` / `+b ~account:<name>` /
`+b <n!u@h>` extbans. Founder also gets an
`obsidianirc/channel-registration` ModData stamp.

Password compatibility: hashes are copied verbatim into
`accounts.password` with the scheme family in
`accounts.password_scheme`. `argon2id` is the only scheme currently
verifiable for live login; `bcrypt` / `pbkdf2v2` / `crypt-sha*`
verifier paths are not yet implemented in `account-registration.c`.
Until then those accounts can be migrated but a password reset is
required to log in.

SCRAM-SHA-256 from Ergo transfers verbatim into `accounts.scram_*`
columns and works for SASL SCRAM auth immediately.

## 9. Docker stack

### 9.1 Image

`docker/Dockerfile` is a single Alpine 3.19 stage. Build deps stay in
the runtime image so the entrypoint can compile dropped-in custom
modules. The source tree is preserved at `/tmp/obbyircd-source/` for
the same reason.

Build flow:

1. `apk add` build deps (build-base, openssl-dev, pcre2-dev,
   argon2-dev, libsodium-dev, jansson-dev, curl-dev, sqlite-dev,
   pkgconf, gettext, su-exec, netcat-openbsd)
2. `adduser -D obbyircd`
3. `COPY . /tmp/obbyircd-source` (governed by `.dockerignore`)
4. Pre-seed `config.settings` so `./Config -quick` runs
   non-interactively against `/home/obbyircd/obby/*`
5. `./Config -quick && make -j$(nproc) && make install`
6. Snapshot the installed conf tree into `/etc/obbyircd/conf-defaults/`
   for the first-run population trick
7. Pre-create the runtime dirs

### 9.2 Entrypoint behaviour

`docker/docker-entrypoint.sh` runs as root, drops to `obbyircd` via
`su-exec` for the server itself.

Per-restart unconditional work:

- Render `${WS_CONFIG}` / `${FILEHOST_CONFIG}` / `${RPC_CONFIG}`
  fragments based on env vars
- Generate persistent random `CLOAK_KEY1/2/3` if not supplied
- Issue a self-signed TLS cert into `$TLS_DIR` if missing (validity
  1 day — replace before exposing the box)
- Generate a random `OPER_PASSWORD` if not supplied, persist to
  `$DATA_DIR/.oper_password` mode 600
- Compile every `.c` in `$CUSTOM_MOD_DIR` against the in-image source
  tree and install as `modules/third/<name>.so`. Failures warn but
  don't block startup.
- `configtest` the rendered conf; abort with a clear error if it
  fails *before* writing the first-run marker, so the operator can
  fix env vars and restart

First-run only (gated on absence of `$CONF_DIR/.docker_initialized`):

- `cp -r /etc/obbyircd/conf-defaults/. $CONF_DIR/` to seed the volume
- `envsubst < obbyircd.conf.template > obbyircd.conf` to render the
  user-controllable bits
- After a successful `configtest`, `touch
  $CONF_DIR/.docker_initialized` to suppress regeneration on future
  starts

To force regeneration: delete `.docker_initialized` (or wipe the
conf volume entirely).

### 9.3 Volumes

| Volume | Path | Lifecycle |
|--------|------|-----------|
| `obbyircd_conf` | `/home/obbyircd/obby/conf` | Rendered on first run, owned by operator afterwards |
| `obbyircd_data` | `/home/obbyircd/obby/data` | `obsidian.db`, `channel.db`, `tkldb.db`, `persistence/`, `.oper_password` |
| `obbyircd_logs` | `/home/obbyircd/obby/logs` | Server log |
| `obbyircd_tls` | `/home/obbyircd/obby/tls` | Cert + key |
| `obbyircd_custom_modules` | `/home/obbyircd/obby/custom-modules` | Drop `.c` here, restart container |
| `obbyircd_voice_bridge` | `/run/obbyirc` | AF_UNIX socket; **shared with hosted-backend** |

Each accepts a `${NAME}_BIND` env override (in `.env.example`) to swap
the named volume for a host bind mount — relevant for Coolify when
you want backup-target directories rather than docker-managed volumes.

### 9.4 Hosted-backend image

Multi-stage:

- builder: `golang:1.25-alpine`, `CGO_ENABLED=1`, `go build
  -trimpath -ldflags="-s -w"`
- runtime: `alpine:3.20` + `ca-certificates sqlite-libs tzdata`

Exposes `8080` (HTTP) and `3478/udp` (TURN). Mounts:
`obby_api_data`, `obby_api_images`, and `voice-bridge` (shared with
the IRCd).

## 10. Out-of-scope, but useful to know

- **WebSocket transport is plain TCP inside the container** — TLS is
  terminated at Traefik. Don't expose `:8080` publicly without
  TLS in front.
- **The hosted-backend handles the TURN secret HMAC scheme** — if a
  coturn instance is added later, share the same `VOICE_TURN_SECRET`
  and the existing clients will work without code changes.
- **Module ABI is per-IRCd-major-version**. Custom modules dropped
  into `custom-modules/` must be recompiled when the image base is
  bumped (i.e. whenever the IRCd's compile-time module ABI changes,
  which happens on every release). The entrypoint does this
  automatically — operators just need to know that a kernel-style
  "drop a .so and forget" doesn't work; the `.c` must be present so
  recompile happens.
- **Coolify build server pattern**: Coolify pushes the built image to
  a registry, h4ks pulls. Both sides are arm64, so VM 106's existing
  builder pairing already works.
