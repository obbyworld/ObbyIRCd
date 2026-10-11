# syntax=docker/dockerfile:1.27
#
# ObbyIRCd Docker image.  Builds the IRCd straight from this repository,
# so every native module shipped with the fork (account-registration,
# persistence, metadata, filehost, authtoken, smtp, obbyscript, ...) is
# available out of the box.
#
# Build:   docker build -f docker/Dockerfile -t obbyircd .
# Compose: docker compose up -d

FROM debian:bookworm-slim

# Build + runtime dependencies.  glibc + libxcrypt-compat give us
# bcrypt support in crypt_r() out of the box, which the Alpine/musl
# image did not -- migrated bcrypt-hashed accounts could not
# SASL-login on the old base.  libsqlite3-dev backs account-
# registration; libpython3-dev backs obbypy's embedded CPython.
# gettext-base ships envsubst for the entrypoint conf rendering.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        libssl-dev openssl \
        libpcre2-dev \
        libargon2-dev \
        libsodium-dev \
        libjansson-dev \
        libcurl4-openssl-dev \
        libsqlite3-dev \
        libpython3-dev python3-dev \
        pkg-config \
        wget \
        tar \
        gettext-base \
        netcat-openbsd \
        gosu \
        procps \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /bin/sh obbyircd

# Copy the entire repository in.  .dockerignore keeps build artifacts,
# the obbyworld client checkout, and other dev junk out.
WORKDIR /tmp/obbyircd-source
COPY --chown=obbyircd:obbyircd . .

# Pre-seed config.settings so ./Config -quick can build non-interactively.
RUN install -d -o obbyircd -g obbyircd \
        /home/obbyircd/obby \
        /home/obbyircd/obby/bin \
        /home/obbyircd/obby/data \
        /home/obbyircd/obby/conf \
        /home/obbyircd/obby/modules \
        /home/obbyircd/obby/logs \
        /home/obbyircd/obby/cache \
        /home/obbyircd/obby/doc \
        /home/obbyircd/obby/tmp \
        /home/obbyircd/obby/lib \
    && cat > /tmp/obbyircd-source/config.settings <<'EOF'
BASEPATH="/home/obbyircd/obby"
BINDIR="/home/obbyircd/obby/bin"
DATADIR="/home/obbyircd/obby/data"
CONFDIR="/home/obbyircd/obby/conf"
MODULESDIR="/home/obbyircd/obby/modules"
LOGDIR="/home/obbyircd/obby/logs"
CACHEDIR="/home/obbyircd/obby/cache"
DOCDIR="/home/obbyircd/obby/doc"
TMPDIR="/home/obbyircd/obby/tmp"
PRIVATELIBDIR="/home/obbyircd/obby/lib"
MAXCONNECTIONS_REQUEST="auto"
NICKNAMEHISTORYLENGTH="2000"
GEOIP="none"
DEFPERM="0600"
SSLDIR=""
REMOTEINC=""
CURLDIR=""
NOOPEROVERRIDE=""
OPEROVERRIDEVERIFY=""
GENCERTIFICATE="0"
SANITIZER=""
EXTRAPARA=""
ADVANCED=""
EOF

RUN chmod +x Config \
    && chown -R obbyircd:obbyircd /tmp/obbyircd-source /home/obbyircd

USER obbyircd

# CI passes the commit SHA via --build-arg so BuildKit can never serve a
# stale make/install layer for a different revision. Without this, an
# observed regression: the source-tree COPY changed but BuildKit reused
# the previous build's compiled .so files, shipping pre-fix binaries with
# post-fix sources. The CACHE_KEY value is intentionally consumed by the
# RUN below (echoed before the build) so a different SHA invalidates the
# layer; default value lets local `docker build` work without --build-arg.
ARG CACHE_KEY=local

# UnrealIRCd's bundled argon2 (extras/argon2.tar.gz) builds with -march=native
# by default, baking the build host's CPU instructions into the binary; the
# image then SIGILLs on any host with a smaller instruction set (e.g. an
# AVX2-only machine running an AVX-512-built lib).  Pin a portable per-arch
# baseline so the image runs on every CPU of its architecture.
RUN echo "Building for CACHE_KEY=${CACHE_KEY}" \
    && ARCH="$(uname -m)" \
    && case "$ARCH" in \
        x86_64)  OPTTARGET="x86-64" ;; \
        aarch64) OPTTARGET="armv8-a" ;; \
        *)       OPTTARGET="native" ;; \
    esac \
    && export OPTTARGET \
    && find src -name '*.o' -delete 2>/dev/null \
    && find src -name '*.so' -delete 2>/dev/null \
    && ./Config -quick && make -j"$(nproc)" && make install

USER root

# Snapshot the freshly-installed conf tree somewhere outside the volume
# mount points so first-run can repopulate a fresh volume.  `make
# install` doesn't ship doc/conf/scripts/, so copy the obbyscript
# example separately -- the entrypoint also `mkdir -p`s the scripts
# directory on every start in case the operator wiped it.
RUN mkdir -p /etc/obbyircd/conf-defaults \
    && cp -r /home/obbyircd/obby/conf/. /etc/obbyircd/conf-defaults/ \
    && mkdir -p /etc/obbyircd/conf-defaults/scripts \
    && cp -n /tmp/obbyircd-source/doc/conf/scripts/*.js \
            /etc/obbyircd/conf-defaults/scripts/ 2>/dev/null || true \
    && chmod -R a+rX /etc/obbyircd

RUN mkdir -p /home/obbyircd/obby/conf \
             /home/obbyircd/obby/data \
             /home/obbyircd/obby/logs \
             /home/obbyircd/obby/tls \
             /home/obbyircd/obby/tmp \
             /home/obbyircd/obby/custom-modules \
    && chown -R obbyircd:obbyircd /home/obbyircd

COPY docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY docker/obbyircd.conf.template /etc/obbyircd/obbyircd.conf.template
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENV SERVER_NAME=irc.example.com \
    NETWORK_NAME=ObbyNetwork \
    ADMIN_EMAIL=admin@example.com \
    SSL_PORT=6697 \
    WS_PORT=8080 \
    RPC_PORT=8600 \
    MOTD_TEXT="Welcome to ObbyIRCd!"

EXPOSE 6697 8080 8600

VOLUME ["/home/obbyircd/obby/conf", \
        "/home/obbyircd/obby/data", \
        "/home/obbyircd/obby/logs", \
        "/home/obbyircd/obby/tls", \
        "/home/obbyircd/obby/custom-modules"]

WORKDIR /home/obbyircd/obby

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["./bin/obbyircd", "-F"]
