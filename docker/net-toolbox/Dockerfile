# roorecon/net-toolbox — the operator's tools for the engagement network.
#
# One image, three run-modes, all sharing the VPN sidecar's network namespace
# (--network container:roorecon-vpn) so everything acts at the *tunnel IP*:
#   roo shell  — interactive: reverse-shell catchers, payload hosting, impacket,
#                pivots. /work is mounted, so loot lands on the host.
#   roo proxy  — detached microsocks: SOCKS5 egress so host tools (browser/Burp/
#                curl) reach the target through the tunnel.
#   roo fwd    — detached socat: bridge a tunnel port back to a host listener.
#
# This is a *tool* image. It deliberately does NOT own the tunnel — that's the
# openvpn "location" image's job. See ARCHITECTURE.md (location vs. tools).

# microsocks is a tiny single-binary SOCKS5 server (rofl0r/microsocks); built
# from source because Debian doesn't package it uniformly across releases.
FROM debian:stable-slim AS microsocks
# build-essential (not bare gcc) so libc headers like unistd.h are present.
RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential git ca-certificates \
 && git clone --depth 1 https://github.com/rofl0r/microsocks /src \
 && make -C /src

FROM debian:stable-slim
COPY --from=microsocks /src/microsocks /usr/local/bin/microsocks
# impacket via pip (not apt): the pip package installs the example CLIs an
# operator actually uses — smbserver.py, secretsdump.py, etc. — on PATH;
# Debian's python3-impacket ships only the library. --break-system-packages is
# safe in a throwaway tool image.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ncat netcat-traditional socat \
      python3 python3-pip \
      curl wget iproute2 tmux less vim-tiny ca-certificates \
 && pip3 install --no-cache-dir --break-system-packages impacket \
 && apt-get purge -y python3-pip \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /work
# No ENTRYPOINT: `roo shell` runs bash, `roo proxy` runs microsocks, `roo fwd`
# runs socat — the run-mode is chosen by the command roo passes.
CMD ["bash"]
