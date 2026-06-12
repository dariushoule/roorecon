# roorecon/gobuster — gobuster + baked SecLists DNS wordlists, for vhost
# (internal) and DNS subdomain (external) enumeration.
#
# Wordlists are from SecLists (MIT-licensed), bundled here so the tool and its
# data are co-located in the image — no git submodule, no host install. Source:
# https://github.com/danielmiessler/SecLists  (Discovery/DNS/). The upstream
# LICENSE is copied to /wordlists/SecLists-LICENSE. See README "Credits".

FROM golang:bookworm AS build
# Pinned for reproducibility — gobuster reorganized its CLI flags across 3.x.
RUN go install github.com/OJ/gobuster/v3@v3.8.2

FROM debian:stable-slim
ARG SECLISTS=https://raw.githubusercontent.com/danielmiessler/SecLists/master
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && mkdir -p /wordlists \
 && for f in subdomains-top1million-5000.txt subdomains-top1million-20000.txt combined_subdomains.txt; do \
      curl -fsSL "${SECLISTS}/Discovery/DNS/${f}" -o "/wordlists/${f}"; \
    done \
 && curl -fsSL "${SECLISTS}/LICENSE" -o /wordlists/SecLists-LICENSE \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /go/bin/gobuster /usr/local/bin/gobuster
ENTRYPOINT ["gobuster"]
