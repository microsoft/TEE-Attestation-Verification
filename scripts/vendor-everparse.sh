#!/usr/bin/env bash
# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Vendors the EverParse CBOR Rust sources (upstream crates `cborrs` and
# `cborrs-nondet`) into cbor/vendor/everparse, byte-for-byte and at their
# upstream paths, so the CBOR crate has no git dependencies and can be
# published to crates.io.
#
# Usage: scripts/vendor-everparse.sh [rev]
#   rev defaults to the revision recorded in cbor/vendor/everparse/REVISION.
#
# Re-running with the recorded revision must leave the worktree unchanged.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="$ROOT/cbor/vendor/everparse"
UPSTREAM="https://github.com/project-everest/everparse.git"
PATHS=(
  LICENSE
  src/cbor/pulse/det/rust/src/cbordet.rs
  src/cbor/pulse/det/rust/src/cbordetver.rs
  src/cbor/pulse/det/rust/src/cbordetveraux.rs
  src/cbor/pulse/nondet/rust/src/cbornondet.rs
  src/cbor/pulse/nondet/rust/src/cbornondetalloc.rs
  src/cbor/pulse/nondet/rust/src/cbornondetallocimpl.rs
  src/cbor/pulse/nondet/rust/src/cbornondetver.rs
  src/cbor/pulse/nondet/rust/src/cbornondetveraux.rs
)

REV="${1:-$(cat "$DEST/REVISION")}"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

git -C "$tmp" init --quiet
git -C "$tmp" fetch --quiet --depth 1 --filter=blob:none "$UPSTREAM" "$REV"
REV="$(git -C "$tmp" rev-parse FETCH_HEAD)"

rm -rf "$DEST/LICENSE" "$DEST/src"
for path in "${PATHS[@]}"; do
  mkdir -p "$(dirname "$DEST/$path")"
  git -C "$tmp" show "FETCH_HEAD:$path" >"$DEST/$path"
done
echo "$REV" >"$DEST/REVISION"

echo "Vendored $UPSTREAM at $REV into ${DEST#"$ROOT"/}"
