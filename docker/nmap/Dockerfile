# roorecon/nmap — minimal nmap on debian-slim.
# Built on demand by ./roo; tagged with a hash of this file so any edit
# triggers a rebuild. Keep it lean: no recommended extras, no apt cache.
FROM debian:stable-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap \
 && rm -rf /var/lib/apt/lists/*

# ENTRYPOINT is the tool itself, so `docker run <img> -sCV ...` == `nmap -sCV ...`
ENTRYPOINT ["nmap"]
