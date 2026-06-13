# roorecon/whatweb — web tech + version fingerprinting (sharper than nmap -sV).
#
# Driven by `roo fingerprint <url>`: detects server, framework, CMS, and version
# strings from headers, cookies, body markers, and meta tags. Target-facing, so
# it honors $ROO_NET (runs in the VPN tunnel namespace for VPN-only targets).
# whatweb is GPL; packaged by Debian. Source: https://github.com/urbanadventurer/WhatWeb

FROM debian:stable-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends whatweb ca-certificates \
 && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["whatweb"]
