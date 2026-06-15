# roorecon/sqlmap — automated SQL injection detection + exploitation.
#
# Driven by `roo sqlmap [args...]` (a target-facing passthrough — honors ROO_NET,
# so it reaches a VPN-only target through the tunnel). sqlmap is pure Python; the
# upstream project is distributed as a git checkout (no pip package is official),
# so we clone it at build time and freeze it in the image layer. Like the `vuln`
# image baking the Exploit-DB index from a moving branch, the clone is pinned by
# RooRecon's build-context hash: it's frozen until this Dockerfile changes.

FROM debian:stable-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 git ca-certificates \
 && git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
 && rm -rf /opt/sqlmap/.git \
 && apt-get purge -y git && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /work
ENTRYPOINT ["python3", "/opt/sqlmap/sqlmap.py"]
