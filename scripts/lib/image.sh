#!/usr/bin/env bash
#
# image.sh — sourced helper for RooRecon's per-tool container images.
#
# Each tool has a docker/<tool>/Dockerfile. Images are built on demand and
# tagged with a hash of that Dockerfile, so editing it auto-rebuilds while
# unchanged tools start instantly. Both scripts/roo and scripts/vpn source this
# so the build logic lives in exactly one place.

# Repo root, derived from this file's location (scripts/lib/image.sh -> repo).
_roo_lib_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ROO_DOCKER_DIR="${ROO_DOCKER_DIR:-$_roo_lib_root/docker}"
ROO_IMAGE_PREFIX="${ROO_IMAGE_PREFIX:-roorecon}"

roo_dockerfile_hash() {
  # $1 = path to a Dockerfile -> 12 hex chars (portable across macOS/Linux).
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -c1-12
  else
    sha256sum "$1" | cut -c1-12
  fi
}

roo_image_ref() {
  # $1 = tool -> echoes "roorecon/<tool>:<hash>"; returns 1 if no Dockerfile.
  local tool="$1" df="$ROO_DOCKER_DIR/$1/Dockerfile"
  [ -f "$df" ] || return 1
  printf '%s/%s:%s\n' "$ROO_IMAGE_PREFIX" "$tool" "$(roo_dockerfile_hash "$df")"
}

roo_ensure_image() {
  # $1 = tool -> builds the image if missing, echoes its ref on stdout.
  # Progress/errors go to stderr so callers can capture the ref cleanly.
  local tool="$1" ref
  if ! ref="$(roo_image_ref "$tool")"; then
    printf '\033[31m[!]\033[0m no image defined for "%s" (expected %s/%s/Dockerfile)\n' \
      "$tool" "$ROO_DOCKER_DIR" "$tool" >&2
    return 1
  fi
  if ! docker image inspect "$ref" >/dev/null 2>&1; then
    printf '\033[36m[*]\033[0m building %s (first use or Dockerfile changed)…\n' "$ref" >&2
    docker build -q -t "$ref" "$ROO_DOCKER_DIR/$tool" >/dev/null
  fi
  printf '%s\n' "$ref"
}
