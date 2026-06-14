# volatility3 + pypykatz — offline memory-image forensics.
# Like hashcat, this analyzes loot (RAM dumps, VM memory, lsass minidumps) on the
# host side: it never touches the target or the VPN. It runs in a container for a
# reproducible toolchain, with the cwd mounted at /work and the image read from
# there. Symbol tables (PDBs) download from the public internet on first use, so
# `roo vol` runs it on the default docker network, never the tunnel.
FROM python:3.12-slim

# binutils → `strings` for the cleartext sweep; the rest is pip.
RUN apt-get update \
 && apt-get install -y --no-install-recommends binutils \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir volatility3 pypykatz

WORKDIR /work
# No ENTRYPOINT: `roo vol` passes the binary it wants (vol / pypykatz / sh -c …).
