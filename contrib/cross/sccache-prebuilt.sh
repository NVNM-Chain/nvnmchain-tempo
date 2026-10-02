#!/bin/bash

set -x
set -euo pipefail

# shellcheck disable=SC1091
. lib.sh

# Pinned sccache release. The previous version of this script resolved the
# newest tag at build time with `git ls-remote` and installed the tarball
# unverified, so whatever upstream published - or whatever a MITM or a
# compromised release asset served - became the RUSTC_WRAPPER for every cross
# build. Pin the version, verify the digest, and a change becomes a reviewable
# commit instead of a silent one.
#
# Checksums are from the upstream `.sha256` assets and were verified against a
# fresh download of each tarball. They are valid only for SCCACHE_VERSION
# below; bumping the version means bumping these too.
SCCACHE_VERSION="${SCCACHE_VERSION:-v0.18.0}"
SCCACHE_PINNED_VERSION="v0.18.0"

sccache_sha256() {
    case "${1}" in
        x86_64-unknown-linux-musl)
            echo 45f1447fbe231e3037bde351ef70677dd212216c8d62ae7ca409fecc4d6acc89 ;;
        aarch64-unknown-linux-musl)
            echo 2b3284d5da3b46a47dc4229e75bb7b88ac4aa99c8d754fb7d2f84997e5a4354a ;;
        *)
            return 1 ;;
    esac
}

main() {
    local triple
    local tag
    local sha
    local td
    local url="https://github.com/mozilla/sccache"
    triple="${1}"
    tag="${SCCACHE_VERSION}"

    if [ "${tag}" != "${SCCACHE_PINNED_VERSION}" ]; then
        if [ -z "${SCCACHE_SHA256:-}" ]; then
            echo "SCCACHE_VERSION=${tag} differs from the pinned ${SCCACHE_PINNED_VERSION};" >&2
            echo "set SCCACHE_SHA256 to the sha256 of sccache-${tag}-${triple}.tar.gz" >&2
            return 1
        fi
        sha="${SCCACHE_SHA256}"
    elif ! sha="$(sccache_sha256 "${triple}")"; then
        echo "no pinned sccache checksum for triple: ${triple}" >&2
        return 1
    fi

    install_packages unzip tar

    # Download our package, verify it against the pinned digest, then install
    # our binary. An unverified tarball is never unpacked.
    td="$(mktemp -d)"
    pushd "${td}"
    curl --proto '=https' --tlsv1.2 -LSfs --retry 3 --retry-all-errors \
        "${url}/releases/download/${tag}/sccache-${tag}-${triple}.tar.gz" \
        -o sccache.tar.gz
    echo "${sha}  sccache.tar.gz" | sha256sum -c -
    tar -xvf sccache.tar.gz
    rm sccache.tar.gz
    cp "sccache-${tag}-${triple}/sccache" "/usr/bin/sccache"
    chmod 0755 "/usr/bin/sccache"

    # clean up our install
    purge_packages
    popd
    rm -rf "${td}"
    rm "${0}"
}

main "${@}"
