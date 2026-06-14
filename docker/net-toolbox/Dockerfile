# roorecon/net-toolbox — the operator's tools for the engagement network.
#
# One image, three run-modes, all sharing the VPN sidecar's network namespace
# (--network container:roorecon-vpn) so everything acts at the *tunnel IP*:
#   roo shell  — interactive: reverse-shell catchers, payload hosting, impacket,
#                AD tooling, pivots. /work is mounted, so loot lands on the host.
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

# RustHound-CE built from source so the Kerberos/GSSAPI feature is compiled in
# (the prebuilt release omits it; without it you can't seal LDAP and a hardened DC
# rejects the bind). GSSAPI is enabled by default once libclang/libkrb5 are present
# at build time. Only the binary is copied into the final image — the Rust
# toolchain stays in this stage.
FROM rust:slim-bookworm AS rusthound
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      pkg-config gcc clang libclang-dev libgssapi-krb5-2 libkrb5-dev \
      libsasl2-modules-gssapi-mit ca-certificates \
 && cargo install rusthound-ce \
 && rm -rf /var/lib/apt/lists/*

FROM debian:stable-slim
COPY --from=microsocks /src/microsocks /usr/local/bin/microsocks
COPY --from=rusthound /usr/local/cargo/bin/rusthound-ce /usr/local/bin/rusthound-ce

# pipx drops app shims in PIPX_BIN_DIR; point it at /usr/local/bin so `nxc` and
# `certipy` land on the PATH every run-mode already sees. OPENSSL_CONF activates
# the legacy provider image-wide (see the openssl-legacy.cnf step below).
ENV PIPX_HOME=/opt/pipx \
    PIPX_BIN_DIR=/usr/local/bin \
    OPENSSL_CONF=/etc/ssl/openssl-legacy.cnf

# Operator toolset for engagement-network work, in four groups:
#  - ad-hoc clients you'd reach for at the tunnel IP: smbclient, ldapsearch,
#    dig, curl/wget, nc/ncat/socat — the "jump box" basics.
#  - AD attack tooling: impacket example CLIs (secretsdump/GetUserSPNs/…),
#    NetExec (nxc), Certipy (AD CS), bloodyAD (LDAP read/write that *seals* — reads
#    DACLs and runs dMSA/BadSuccessor add/modify on signing-enforced DCs where the
#    ldap3 tools fail), and two WinRM shells kept on purpose for
#    manual cross-checking: evil-winrm (Ruby) + evil-winrm-py (Python, with the
#    [kerberos] extra so it speaks GSSAPI/-k against signing-enforced DCs).
#  - BloodHound collectors, standalone: bloodhound-python (legacy/BH4 JSON) +
#    bloodhound-ce-python (BH CE JSON). Unlike nxc's `--bloodhound` wrapper these
#    default to *plain* LDAP/389+GC/3268, so they collect against DCs that reset
#    LDAPS/636 — the only path that gets the graph on a hardened/2025 DC.
#  - Kerberos plumbing: krb5-user (kinit) + krb5-pkinit (cert-based PKINIT, for
#    the Certipy→cert→WinRM path and evil-winrm-py[kerberos]) + faketime. Clock
#    skew is the #1 Kerberos footgun on lab DCs (KRB_AP_ERR_SKEW); libfaketime
#    shifts the container clock to the DC's without root/CAP_SYS_TIME — see the
#    `ad` skill.
#  - quality-of-life: rlwrap (readline/history + arrow keys on raw reverse
#    shells — `roo shell rlwrap nc -lvnp 4444`), tmux, vim-tiny, less.
#
# build deps (build-essential, *-dev) are needed to compile native extensions
# for NetExec's deps and the gssapi gem evil-winrm pulls in; kept in the image
# (not purged) so a `pipx`/`gem` re-run by an operator doesn't break.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ncat netcat-traditional socat \
      python3 python3-pip python3-dev pipx \
      smbclient ldap-utils libsasl2-modules-gssapi-mit dnsutils iputils-ping \
      krb5-user krb5-pkinit faketime rlwrap \
      ruby ruby-dev \
      build-essential libffi-dev libssl-dev libkrb5-dev \
      git curl wget iproute2 tmux less vim-tiny ca-certificates \
 && pip3 install --no-cache-dir --break-system-packages impacket \
 && pipx install git+https://github.com/Pennyw0rth/NetExec \
 && pipx install certipy-ad \
 && pipx install bloodyAD \
 && pipx install 'evil-winrm-py[kerberos]' \
 && pipx install bloodhound \
 && pipx install bloodhound-ce \
 && gem install --no-document evil-winrm \
 && rm -rf /var/lib/apt/lists/*

# RustHound-CE: built from source (multi-stage, binary copied in above) — the
# prebuilt release ships WITHOUT GSSAPI, and NTLM can't seal, so only a
# Kerberos/GSSAPI build collects from a signing-enforced DC. Runtime libs
# (libgssapi-krb5, libkrb5) come from krb5-user/krb5-pkinit already installed.

# OpenSSL 3 dropped MD4 from the default provider, but NTLM auth still derives
# its key with MD4 — so every ldap3-based tool (NetExec, Certipy, badsuccessor)
# dies on "unsupported hash type MD4" the moment you bind with a password.
# Activate the legacy provider image-wide (additive — the default provider stays
# on) so password auth just works; Kerberos paths are unaffected.
RUN printf '%s\n' \
  'openssl_conf = openssl_init' \
  '[openssl_init]' \
  'providers = provider_sect' \
  '[provider_sect]' \
  'default = default_sect' \
  'legacy = legacy_sect' \
  '[default_sect]' \
  'activate = 1' \
  '[legacy_sect]' \
  'activate = 1' \
  > /etc/ssl/openssl-legacy.cnf

# Operator helper scripts:
#   clocksync — sync this shell's clock to a target (drives the libfaketime that
#               `roo shell` LD_PRELOADs) to beat KRB_AP_ERR_SKEW without touching
#               the host clock.
#   krbconf   — write /etc/krb5.conf for a target's realm (system-GSSAPI tools).
#   bhcollect — one-command BloodHound CE collection via rusthound-ce's Kerberos
#               seal (works on hardened DCs); ties krbconf+clocksync+getTGT+rusthound.
COPY --chmod=0755 clocksync krbconf bhcollect /usr/local/bin/

# Sealed LDAP over plain 389: the OpenLDAP clients (ldapsearch/ldapmodify/ldapadd)
# do SASL GSSAPI sign+seal (confidentiality) — the one channel that lets you read
# managed passwords and set/create passwords on a DC that requires confidentiality
# but resets LDAPS (where ldap3-based tools can't). `SASL_NOCANON on` makes SASL
# use the literal `-H` host as the SPN (no reverse-DNS canonicalisation, which on a
# lab `./hosts` picks the domain name and breaks the ticket). Pair with `krbconf`
# (sets rdns=false) + a TGT in KRB5CCNAME, then `ldapsearch -Y GSSAPI -H ldap://<dc-fqdn>`.
RUN mkdir -p /etc/ldap && printf 'SASL_NOCANON on\n' > /etc/ldap/ldap.conf

WORKDIR /work
# No ENTRYPOINT: `roo shell` runs bash, `roo proxy` runs microsocks, `roo fwd`
# runs socat — the run-mode is chosen by the command roo passes.
CMD ["bash"]
