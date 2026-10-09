ARG CHEF_IMAGE=chef

FROM ${CHEF_IMAGE} AS builder

ARG TARGETARCH
ARG RUST_PROFILE=profiling
ARG RUST_FEATURES="asm-keccak,jemalloc,otlp"
ARG VERGEN_GIT_SHA
ARG VERGEN_GIT_SHA_SHORT
ARG EXTRA_RUSTFLAGS=""

COPY . .

# Build ALL binaries in one pass - they share compiled artifacts.
#
# `--locked` is a supply-chain guard, not an optimisation: without it cargo is
# free to re-resolve a dependency to a newer version than the one in the
# committed Cargo.lock, so the bytes that ship would not be the bytes that were
# reviewed. The lockfile is authoritative; a stale one must fail the build
# rather than be silently updated inside an image nobody inspects.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked,id=cargo-registry-${TARGETARCH} \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked,id=cargo-git-${TARGETARCH} \
    RUSTFLAGS="-C link-arg=-fuse-ld=mold ${EXTRA_RUSTFLAGS}" \
    cargo build --locked --profile ${RUST_PROFILE} \
        --bin tempo --features "${RUST_FEATURES},localnet" \
        --bin tempo-localnet --features "${RUST_FEATURES},localnet" \
        --bin tempo-sidecar \
        --bin tempo-xtask

FROM debian:bookworm-slim@sha256:4724b8cc51e33e398f0e2e15e18d5ec2851ff0c2280647e1310bc1642182655d AS base

# Fixed ids so a Kubernetes `runAsUser`/`runAsGroup`/`fsGroup`, a pre-chowned
# host path, and the image all name the same identity. Deliberately high and
# outside Debian's system range so it cannot collide with a distro account.
ARG TEMPO_UID=10001
ARG TEMPO_GID=10001

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates; \
    rm -rf /var/lib/apt/lists/*; \
    # Nothing in these images is ever meant to escalate privilege, so drop
    # every setuid/setgid bit the base layer ships (su, mount, chsh, ...).
    # Defence in depth: it removes the usual local-escalation primitives from
    # the filesystem even if a process is somehow compromised.
    find / -xdev -perm /6000 -type f -exec chmod a-s {} +; \
    groupadd --gid "${TEMPO_GID}" tempo; \
    useradd --uid "${TEMPO_UID}" --gid "${TEMPO_GID}" \
        --home-dir /data --no-create-home --shell /usr/sbin/nologin tempo

WORKDIR /data
RUN chown "${TEMPO_UID}:${TEMPO_GID}" /data

# The node resolves a few paths (account store, extension registry) from $HOME
# via `dirs_next`. Root's default of /root is unwritable once the image drops
# to an unprivileged user, so point it at the data directory the image already
# owns. Deployments that pass an explicit --datadir are unaffected; without
# one the chain moves from /root/.local/share/reth to /data/.local/share/reth.
ENV HOME=/data

LABEL org.opencontainers.image.vendor="NVNM Chain" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0" \
      org.opencontainers.image.documentation="https://docs.tempo.xyz"

# Numeric, so `runAsNonRoot` can verify it; the stages below inherit it.
USER ${TEMPO_UID}:${TEMPO_GID}

# tempo
FROM base AS tempo
ARG RUST_PROFILE=profiling
ARG RETH_ENGINE_PERSISTENCE_THRESHOLD=7
ENV RETH_ENGINE_PERSISTENCE_THRESHOLD=${RETH_ENGINE_PERSISTENCE_THRESHOLD}
ARG RETH_ENGINE_NUM_STATE_MASKING_BLOCKS=0
ENV RETH_ENGINE_NUM_STATE_MASKING_BLOCKS=${RETH_ENGINE_NUM_STATE_MASKING_BLOCKS}
LABEL org.opencontainers.image.title="tempo"
# Binaries stay root-owned and world-executable: the runtime user may run them
# but may not rewrite them.
COPY --from=builder /app/target/${RUST_PROFILE}/tempo /usr/local/bin/tempo
ENTRYPOINT ["/usr/local/bin/tempo"]

# tempo-localnet
FROM base AS tempo-localnet
ARG RUST_PROFILE=profiling
LABEL org.opencontainers.image.title="tempo-localnet"
COPY --from=builder /app/target/${RUST_PROFILE}/tempo /usr/local/bin/tempo
COPY --from=builder /app/target/${RUST_PROFILE}/tempo-localnet /usr/local/bin/tempo-localnet
EXPOSE 8545
# Declared after /data is chowned, so a fresh named volume inherits the
# unprivileged ownership instead of being seeded root-owned.
VOLUME ["/data"]
HEALTHCHECK --interval=2s --timeout=2s --start-period=120s --retries=5 CMD ["/usr/local/bin/tempo-localnet", "--health"]
ENTRYPOINT ["/usr/local/bin/tempo-localnet"]

# tempo-sidecar
FROM base AS tempo-sidecar
ARG RUST_PROFILE=profiling
LABEL org.opencontainers.image.title="tempo-sidecar"
COPY --from=builder /app/target/${RUST_PROFILE}/tempo-sidecar /usr/local/bin/tempo-sidecar
ENTRYPOINT ["/usr/local/bin/tempo-sidecar"]

# tempo-xtask
FROM base AS tempo-xtask
ARG RUST_PROFILE=profiling
LABEL org.opencontainers.image.title="tempo-xtask"
COPY --from=builder /app/target/${RUST_PROFILE}/tempo-xtask /usr/local/bin/tempo-xtask
ENTRYPOINT ["/usr/local/bin/tempo-xtask"]
