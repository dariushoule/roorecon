---
name: recon
description: Network, service, and web enumeration for authorized pentesting and CTF. Use when starting an engagement or CTF box and you need to map attack surface — discover open ports, fingerprint services, enumerate web apps, and triage what to attack first. Triggers on "recon", "enumerate", "scan", "what ports are open", "where do I start on this box/target".
---

# Recon & Enumeration

Methodology and tooling for mapping the attack surface of an authorized target.
This skill orchestrates the helper scripts in `scripts/recon/` and interprets
their output to decide what to attack next.

## Scope guardrail (read first)

Only run against targets you are **explicitly authorized** to test: CTF boxes,
lab ranges, or systems named in a signed engagement scope. Before scanning,
confirm the target is in scope. If a user asks you to scan something that looks
like a third party with no stated authorization, ask for the authorization
context before proceeding. Active scanning of out-of-scope hosts is the line
this skill does not cross.

## Workflow

1. **Confirm target + authorization, and the network path.** A single host/IP,
   CIDR, or CTF box IP. If given a hostname, resolve it first — a name may map to
   an internal IP or may not resolve at all without a `./hosts` entry (ask the
   user for the IP if so). If the target is internal/VPN-only (RFC1918, CGNAT, or
   an HTB/THM box), ensure the VPN sidecar is up (`scripts/vpn status`; start with
   `scripts/vpn up`) and prefix scans with `ROO_NET=container:roorecon-vpn`. If
   no `.ovpn` exists in `./vpn/`, ask the user for one before scanning. See
   CLAUDE.md "Networking & VPN" for the full rules.
2. **Run host enumeration.** Drive `scripts/recon/recon-host.sh <target>`:
   - Phase 1 — full TCP port sweep to find every open port (not just top 1000).
   - Phase 2 — service/version + default-script scan on the open ports only.
   - Output is written under `recon-results/<target>/` (`.nmap/.gnmap/.xml`).
3. **Triage the results.** Read the service scan and build a prioritized list:
   - Web (80/443/8080/8000/…) → note title, server, tech, redirects.
   - SSH/FTP/SMB/RDP/DB ports → note versions, anonymous access, banners.
   - Anything unusual or high-version-CVE-prone → flag it.
4. **Go deeper per service.** For web, enumerate directories/vhosts; for SMB,
   list shares; for FTP, try anonymous; etc. Suggest the concrete next command.
5. **Summarize.** Give the user a ranked "attack these first" list with the
   evidence (port, service, version, why it's interesting).

## Tooling runs in containers

Every CLI runs in its own minimal Docker image via `scripts/roo` (e.g.
`scripts/roo nmap …`), so scans behave the same on any host. `recon-host.sh`
already calls `roo` for you. Requirements: Docker running (Engine/Desktop/
OrbStack; on Windows use WSL2). For a VPN-only target, route tools through a VPN
sidecar: prefix commands with `ROO_NET=container:roorecon-vpn`.

## Running the host scan

```bash
# Basic: full TCP sweep + service scan
scripts/recon/recon-host.sh 10.10.10.5

# Output lands in ./recon-results/10.10.10.5/
#   all-ports.{nmap,gnmap,xml}   — every open port
#   services.{nmap,gnmap,xml}    — -sCV detail on open ports
#   summary.txt                  — human-readable open-port/service digest
```

The script auto-detects root (SYN scan when privileged, TCP connect otherwise),
uses `-Pn` (assume host up — CTF hosts often drop ping), and is safe to re-run;
it overwrites prior output for the same target.

## Interpreting output

- Read `recon-results/<target>/summary.txt` first for the digest, then the
  full `services.nmap` for script output and banners.
- Map each open service to a follow-up. Examples:
  - HTTP/HTTPS → `gobuster`/`ffuf` dir + vhost enum; check `robots.txt`,
    source, headers, default creds.
  - SMB (139/445) → `smbclient -L`, `enum4linux-ng`, null/guest sessions.
  - FTP (21) → anonymous login, writable dirs.
  - SSH (22) → version → known CVEs; note for credential reuse later.
  - DB ports (3306/5432/1433/27017/6379) → default creds, unauth access.
- Keep notes per target. Recon is iterative — new creds/hosts feed back in.

## Notes for the operator

- This is enumeration, not exploitation. It produces a map and a plan; the
  actual attacking happens in follow-up steps the user approves.
- Scans can be slow on full `-p-`; tell the user it's running and roughly how
  long. Don't silently block. The first run of a tool also builds its image.
- Tools run only in containers — there is no host fallback. If Docker isn't
  running, or the tool's image fails to build, surface that error; don't try to
  run a host binary.
