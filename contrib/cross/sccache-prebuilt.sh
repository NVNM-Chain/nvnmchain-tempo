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
# The checksum is upstream's `.sha256` asset for this version and triple,
# verified against a fresh download; bump the three together.
SCCACHE_VERSION="v0.18.0"
SCCACHE_TRIPLE="x86_64-unknown-linux-musl"
SCCACHE_SHA256="45f1447fbe231e3037bde351ef70677dd212216c8d62ae7ca409fecc4d6acc89"

main() {
    local td
    local name="sccache-${SCCACHE_VERSION}-${SCCACHE_TRIPLE}"
    local url="https://github.com/mozilla/sccache"

    install_packages unzip tar

    # Download our package, verify it against the pinned digest, then install
    # our binary. An unverified tarball is never unpacked.
    td="$(mktemp -d)"
    pushd "${td}"
    # The base image's curl 7.68 has no --retry-all-errors: retry here, resuming a cut transfer.
    for _ in 1 2 3 4 5; do
        curl --proto '=https' --tlsv1.2 -LSfs -C - \
            "${url}/releases/download/${SCCACHE_VERSION}/${name}.tar.gz" -o sccache.tar.gz && break
    done
    echo "${SCCACHE_SHA256}  sccache.tar.gz" | sha256sum -c -
    tar -xvf sccache.tar.gz
    rm sccache.tar.gz
    cp "${name}/sccache" "/usr/bin/sccache"
    chmod 0755 "/usr/bin/sccache"

    # clean up our install
    purge_packages
    popd
    rm -rf "${td}"
    rm "${0}"
}

main
