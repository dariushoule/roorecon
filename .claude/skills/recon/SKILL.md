---
name: recon
description: Network, service, and web enumeration for authorized pentesting and CTF. Use when starting an engagement or CTF box and you need to map attack surface — discover open ports, fingerprint services, enumerate web apps, and triage what to attack first. Triggers on "recon", "enumerate", "scan", "what ports are open", "where do I start on this box/target".
---

# Recon & Enumeration

Methodology and tooling for mapping the attack surface of an authorized target.
This skill drives the `roo` CLI (`scripts/roo …`) and interprets its output to
decide what to attack next.

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
   an HTB/THM box), ensure the VPN sidecar is up (`scripts/roo vpn status`; start
   with `scripts/roo vpn up`) and prefix scans with `ROO_NET=container:roorecon-vpn`.
   If no `.ovpn` exists in `./vpn/`, ask the user for one before scanning. See
   CLAUDE.md "Networking & VPN" for the full rules.
2. **Pick a path.** For CTF speed use the **fast path** (streaming sweep +
   buckaroos) below. For a quick one-shot digest, the **simple path**
   (`roo recon`) is fine. Both write under `recon-results/<target>/`.
3. **Triage and go deeper as results land** — the fast path does this per port
   via buckaroos; the simple path after both phases finish.
4. **Summarize.** Give the user a ranked "attack these first" list with the
   evidence (port, service, version, why it's interesting). Generate the report
   artifact with `scripts/roo report <target>` → `recon-results/<target>/report.md`
   (open-ports/fingerprint table, hostnames, per-port facts + your notes).

**Surface findings as they land — don't gate on the report.** Every `roo` verb
streams high-value findings to the CLI the instant it has them: `sweep` prints
each open port, `buckaroo` prints the service fingerprint and discovered
hostnames, `dirbust` prints each path. Relay those to the user as they appear.
`roo report` is the *end-of-run aggregation*, not the delivery path for
time-sensitive results.

## Fast path — streaming sweep + buckaroos (default for CTF)

Time matters on a box, so don't wait for a full scan before enumerating:
discover ports and deep-dive each one in parallel.

1. **Launch the sweep in the background** (don't block on it):

   ```bash
   scripts/roo sweep <target>          # prefix ROO_NET=container:roorecon-vpn for VPN
   ```

   It runs a full TCP `-p-` SYN scan and a UDP top-200 scan concurrently and, the
   instant nmap reports an open port, drops a claim dir at
   `recon-results/<target>/ports/<proto>-<port>/` and prints `discovered …`.

2. **Watch the spool.** Poll `recon-results/<target>/ports/` for new
   `<proto>-<port>/` directories (and read the sweep's stdout). Each new dir is a
   freshly-found open port to work — long before the sweep finishes.

3. **Dispatch a buckaroo per new port — up to ~8–16 at once.** A buckaroo is
   *hybrid*: the script gathers facts, you interpret.

   ```bash
   scripts/roo buckaroo <target> <proto> <port>   # → ports/<proto>-<port>/facts.md
   ```

   Then read `facts.md`, identify the service/version and notable script output,
   and decide concrete follow-ups (web → dir/vhost brute, headers, robots; SMB →
   shares, null session; FTP → anon; DB → default creds). For unusual or unknown
   services, probe further yourself. Write findings to
   `ports/<proto>-<port>/notes.md`, and treat a port as handled once it has a
   `facts.md` + your notes so you don't dispatch it twice.

4. **Finish when** `recon-results/<target>/sweep.done` exists **and** every
   claimed port has a buckaroo result. Cap concurrency (~8–16) so a port-dense
   box doesn't storm tokens or saturate the VPN; queue the rest.

## Simple path — one-shot phased scan

```bash
scripts/roo recon <target>
# → recon-results/<target>/summary.txt  (+ all-ports.* and services.*)
```

Phase 1 finds every open port (full `-p-`), phase 2 runs `-sCV` on just those.
Always a SYN scan (root inside the container), `-Pn` (CTF hosts often drop
ping), and safe to re-run.

## Hostname discovery → vhost / subdomain enum

Boxes reveal hostnames you then enumerate further — the classic "IP → `:80`
redirects to `box.htb` → add to hosts → find `admin.box.htb`" loop.

1. **Discover.** A buckaroo on an http/https port pulls hostnames from the
   redirect target and the TLS cert (CN/SAN) into `facts.md` ("Discovered
   hostnames"), and appends them to `recon-results/<target>/hostnames.txt`.
2. **Add to `./hosts`.** For each name, add `IP name` (e.g. `10.10.10.5 box.htb`)
   so every tool container resolves it.
3. **Enumerate more names** — branch on the target:
   - **Internal IP (RFC1918/VPN)** → vhost fuzz the Host header:
     `scripts/roo vhost <ip> <domain>` → `recon-results/<ip>/vhosts.txt`.
   - **External domain** → DNS subdomain brute:
     `scripts/roo dns <domain>` → `recon-results/<domain>/subdomains.txt`.
   Both stream hits live and default to a fast wordlist; pass
   `--wordlist combined_subdomains.txt` (baked, thorough) or
   `ROO_WORDLIST=<host path>` for a custom list.
4. **Loop.** Add newly-found names to `./hosts` and re-buckaroo their web ports
   with the right Host — new vhosts often expose new content and more names.

## Tooling runs in containers

Every CLI runs in a minimal Docker image via `roo` (`scripts/roo` on Unix,
`scripts\roo.cmd` on PowerShell), identical across Linux/macOS/Windows. Needs
Docker running and Python 3; a tool's first use builds its image. Prefix
VPN-only targets with `ROO_NET=container:roorecon-vpn`.

**Need an ad-hoc client (curl, wget, nc, dig)?** No `roo run` image exists for
those — run them at the tunnel IP with `scripts/roo shell <cmd>`. `roo run` is
only for tools with a dedicated image (nmap, gobuster); see CLAUDE.md "Which box
has which tool."

## Interpreting output

- Read `recon-results/<target>/summary.txt` first for the digest, then the
  full `services.nmap` for script output and banners.
- Map each open service to a follow-up. Examples:
  - HTTP/HTTPS → recursive content discovery (`scripts/roo dirbust <url>`, see
    the **dirbust** skill) + vhost enum; check `robots.txt`, source, headers,
    default creds.
  - SMB (139/445) → `smbclient -L`, `enum4linux-ng`, null/guest sessions.
  - FTP (21) → anonymous login, writable dirs.
  - SSH (22) → version → known CVEs; note for credential reuse later.
  - DB ports (3306/5432/1433/27017/6379) → default creds, unauth access.
- Keep notes per target. Recon is iterative — new creds/hosts feed back in.

## Notes for the operator

- Enumeration, not exploitation — produces a map and a plan; the operator
  approves the attacking steps.
- Full `-p-` is slow; say it's running and roughly how long rather than blocking
  silently. A tool's first run also builds its image.
- Container-only, no host fallback. If Docker is down or an image fails to build,
  surface the error — don't run a host binary.
