#!/usr/bin/env bash
# Regenerates gen/ from this repo's proto/ and from the callee protos pinned in
# proto-refs.env. The callee protos are fetched into .protos/ (git-ignored) and
# never committed; only the generated stubs are.
#
# STEWARD_AUDIT_PROTO_DIR, STEWARD_CORE_PROTO_DIR, STEWARD_OBLIGATIONS_PROTO_DIR
# and STEWARD_WORKFLOW_PROTO_DIR point at a local proto/ directory instead, for trying an unmerged proto change.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
source "$root/proto-refs.env"

protos="$root/.protos"
rm -rf "$protos" "$root/gen/go/thirdparty"

# fetch <repo> <ref> <local proto dir> <proto package dir>...
fetch() {
  local repo="$1" ref="$2" local_dir="$3"
  shift 3
  local dest="$protos/$repo" pkg
  local patterns=()
  mkdir -p "$dest"
  if [[ -n "$local_dir" ]]; then
    echo "proto: $repo from $local_dir"
    for pkg in "$@"; do
      mkdir -p "$dest/$pkg"
      cp -R "$local_dir/$pkg/." "$dest/$pkg/"
    done
    return
  fi
  echo "proto: $repo at $ref"
  for pkg in "$@"; do
    patterns+=("*/proto/$pkg/*")
  done
  curl -sSfL "https://codeload.github.com/Steward-GRC/$repo/tar.gz/$ref" |
    tar -xz -C "$dest" --strip-components=2 --wildcards "${patterns[@]}"
}

fetch steward-audit "$STEWARD_AUDIT_REF" "${STEWARD_AUDIT_PROTO_DIR:-}" steward/audit
fetch steward-core "$STEWARD_CORE_REF" "${STEWARD_CORE_PROTO_DIR:-}" steward/core
fetch steward-obligations "$STEWARD_OBLIGATIONS_REF" "${STEWARD_OBLIGATIONS_PROTO_DIR:-}" steward/obligations
fetch steward-workflow "$STEWARD_WORKFLOW_REF" "${STEWARD_WORKFLOW_PROTO_DIR:-}" steward/workflow

cd "$root"
buf generate
