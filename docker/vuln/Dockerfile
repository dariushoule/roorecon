# roorecon/vuln — keyless CVE + public-PoC lookup for recon fingerprints.
#
# Driven by `roo vulns <target>`. The worker (vuln_lookup.py, stdlib only) hits
# public sources — NVD, CISA KEV, EPSS, the Exploit-DB index (baked below), the
# GitHub PoC index, and Metasploit module metadata — and writes a ranked
# vulns.{md,json}. It egresses on the DEFAULT docker network (roo passes
# use_net=False): CVE research traffic is never forced through the VPN tunnel.
#
# Exploit-DB ships as the CSV *index only* (a few MB) — searchsploit-style CVE
# matching without baking the full exploit corpus; the worker prints the EDB URL
# to fetch a specific exploit on demand. The Dockerfile hash pins the build, so
# the index is frozen until this file changes (RooRecon's reproducibility model).

FROM debian:stable-slim
ARG EXPLOITDB_CSV=https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 ca-certificates curl \
 && mkdir -p /opt/exploitdb \
 && curl -fsSL "$EXPLOITDB_CSV" -o /opt/exploitdb/files_exploits.csv \
 && apt-get purge -y curl && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*
COPY vuln_lookup.py /usr/local/bin/vuln_lookup.py
ENTRYPOINT ["python3", "/usr/local/bin/vuln_lookup.py"]
