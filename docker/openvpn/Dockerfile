# roorecon/openvpn — OpenVPN client sidecar.
#
# Runs as a long-lived container that holds the VPN tunnel. Tool containers then
# share its network namespace (ROO_NET=container:roorecon-vpn) so their traffic
# routes through the tunnel — works identically on Linux/macOS/Windows, where a
# container otherwise can't reach a VPN tun on the host.
#
# iproute2 is included so `scripts/vpn status` can read the tun0 address.
FROM debian:stable-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends openvpn iproute2 ca-certificates \
 && rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["openvpn"]
