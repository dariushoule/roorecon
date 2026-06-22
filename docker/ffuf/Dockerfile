# roorecon/ffuf — ffuf + baked SecLists Web-Content lists. Complements gobuster:
# ffuf can fuzz a FUZZ keyword *inside a request body/header/param* (e.g. an SSRF
# url= parameter) and filter on the response, which `gobuster dir` cannot. Use it
# for SSRF-wrapped internal-route discovery and parameter/vhost fuzzing.
#
# Wordlists are from SecLists (MIT-licensed), bundled so tool + data are co-located.
# Source: https://github.com/danielmiessler/SecLists  (Web-Content + DNS).

FROM golang:bookworm AS build
# Pinned for reproducibility.
RUN go install github.com/ffuf/ffuf/v2@v2.1.0

FROM debian:stable-slim
# Same SecLists release tag as the gobuster image so lists are consistent.
ARG SECLISTS=https://raw.githubusercontent.com/danielmiessler/SecLists/2026.1
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && mkdir -p /wordlists \
 && for f in common.txt raft-small-words.txt raft-medium-words.txt \
             raft-medium-directories.txt api/api-endpoints.txt; do \
      curl -fsSL --create-dirs "${SECLISTS}/Discovery/Web-Content/${f}" -o "/wordlists/${f}"; \
    done \
 && curl -fsSL "${SECLISTS}/LICENSE" -o /wordlists/SecLists-LICENSE \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /go/bin/ffuf /usr/local/bin/ffuf
ENTRYPOINT ["ffuf"]
