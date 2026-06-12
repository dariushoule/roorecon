# roorecon/openvpn — OpenVPN client sidecar.
#
# Runs as a long-lived container that holds the VPN tunnel. Tool containers then
# share its network namespace (ROO_NET=container:roorecon-vpn) so their traffic
# routes through the tunnel — works identically on Linux/macOS/Windows, where a
# container otherwise can't reach a VPN tun on the host.
#
# This is the "location" image: its only job is to own the tunnel and the
# network namespace that tool containers share. Keep it minimal — no operator
# tools live here (see ARCHITECTURE.md, "location vs. tools"). iproute2 is the
# one extra, so `roo vpn status` / `roo ip` can read the tun0 address.
FROM debian:stable-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openvpn iproute2 ca-certificates \
 && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["openvpn"]
