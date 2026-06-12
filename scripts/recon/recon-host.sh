#!/usr/bin/env bash
#
# recon-host.sh — phased host enumeration for authorized pentesting / CTF.
#
# Phase 1: full TCP port sweep to find every open port.
# Phase 2: service/version + default-script scan on the open ports only.
#
# nmap runs inside its container via scripts/roo, so results are identical
# across hosts (Linux, macOS, Windows+WSL2). For a VPN-only target, point roo
# at a VPN sidecar: ROO_NET=container:roorecon-vpn scripts/recon/recon-host.sh ...
#
# Usage:
#   scripts/recon/recon-host.sh <target> [output-root]
#
# Output:
#   <output-root>/<target>/all-ports.{nmap,gnmap,xml}
#   <output-root>/<target>/services.{nmap,gnmap,xml}
#   <output-root>/<target>/summary.txt
#
# Authorized use only: CTF boxes, lab ranges, or hosts in a signed engagement
# scope. Do not run against systems you do not have permission to test.

set -euo pipefail

err()  { printf '\033[31m[!]\033[0m %s\n' "$*" >&2; }
info() { printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[+]\033[0m %s\n' "$*"; }

usage() {
  cat >&2 <<EOF
Usage: $(basename "$0") <target> [output-root]

  <target>       single host/IP or hostname (e.g. 10.10.10.5)
  [output-root]  base dir for results, within the current dir (default: ./recon-results)

Example:
  $(basename "$0") 10.10.10.5
EOF
  exit 2
}

[ $# -ge 1 ] || usage
TARGET="$1"
OUT_ROOT="${2:-./recon-results}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROO="$SCRIPT_DIR/../roo"

OUTDIR="${OUT_ROOT%/}/${TARGET}"
mkdir -p "$OUTDIR"

# nmap runs as root with NET_RAW/NET_ADMIN inside the container, so we always
# SYN-scan. Common flags: -Pn (skip host discovery; CTF hosts often drop ping)
# and -n (no DNS).
SCAN_TYPE="-sS"
COMMON=(-Pn -n)

echo
info "Phase 1/2 — full TCP port sweep on ${TARGET} (this can take a few minutes)"
"$ROO" nmap "${COMMON[@]}" "$SCAN_TYPE" -p- --min-rate 1000 -T4 \
  -oA "${OUTDIR}/all-ports" "$TARGET" >/dev/null

# Parse open ports from greppable output: lines like "22/open/tcp//ssh///".
# `|| true` keeps a no-match grep from failing the pipeline (pipefail + set -e)
# on a fully-filtered target.
OPEN_PORTS="$( { grep -oE '[0-9]+/open' "${OUTDIR}/all-ports.gnmap" 2>/dev/null || true; } \
  | cut -d/ -f1 | sort -un | paste -sd, -)"

if [ -z "$OPEN_PORTS" ]; then
  err "no open TCP ports found on ${TARGET}."
  {
    echo "Target:     ${TARGET}"
    echo "Open ports: none found"
    echo "Scanned:    $(date)"
  } > "${OUTDIR}/summary.txt"
  cat "${OUTDIR}/summary.txt"
  exit 0
fi

ok "open ports: ${OPEN_PORTS}"

echo
info "Phase 2/2 — service/version + default scripts on open ports"
"$ROO" nmap "${COMMON[@]}" "$SCAN_TYPE" -sCV -p"$OPEN_PORTS" \
  -oA "${OUTDIR}/services" "$TARGET" >/dev/null

# Build a human-readable digest from the service scan.
{
  echo "Target:     ${TARGET}"
  echo "Scanned:    $(date)"
  echo "Open ports: ${OPEN_PORTS}"
  echo
  echo "== Services =="
  grep -E '^[0-9]+/(tcp|udp)\s+open' "${OUTDIR}/services.nmap" || true
} > "${OUTDIR}/summary.txt"

echo
ok "done. results in ${OUTDIR}/"
echo
cat "${OUTDIR}/summary.txt"
