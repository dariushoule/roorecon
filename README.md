<p align="center">
  <img src="gemini_roorecon.png" alt="RooRecon" width="320">
</p>

# RooRecon

CTF and authorized-pentesting skills for **Claude Code** and **Codex** — agent
*skills* (methodology) plus *automation* (the `roo` CLI). Start an agent in this
repo and ask for recon on a box; it drives the tooling and reads the output.

## Containerized tooling

Every CLI runs in its own minimal Docker image, so scans behave the same on
Linux, macOS, and Windows. One entry point: the cross-platform **`roo` CLI**
(`scripts/roo.py`, stdlib Python) — `scripts/roo` on Unix, `scripts\roo.cmd` on
PowerShell/cmd. It builds each image on demand (tagged by Dockerfile hash) and
mounts the cwd at `/work`.

```bash
scripts/roo run nmap -sCV -p- 10.10.10.5   # runs nmap in roorecon/nmap
```

A changed Dockerfile rebuilds automatically on the next run (the tag is its
hash), so a `git pull` is picked up with no extra step.

## Quick start

Drop your engagement `.ovpn` in `./vpn/` (if the target needs one), then:

```sh
claude "Connect to machines_us-dedivip-1.ovpn and run recon on 10.0.24.44"
```

## Commands

The agent drives the recon pipeline for you — sweep → per-port enum →
content/vhost discovery → **CVE & public-exploit research** (`roo vulns`, sharpened
by `roo fingerprint`) → report. Post-foothold, the VPN sidecar doubles as your box
on the engagement network:

| Command | Use |
|---------|-----|
| `scripts/roo vulns <target>` | CVE + public-PoC lookup for recon fingerprints (keyless; never tunneled) |
| `scripts/roo fingerprint <url>` | web tech/version detection (whatweb) — sharper than nmap |
| `scripts/roo browser [url]` | host browser, VPN-proxied + agent-drivable over CDP (Playwright MCP) |
| `scripts/roo proxy up` | SOCKS5 egress — host browser/Burp/curl reach the target through the tunnel |
| `scripts/roo shell` | operator shell at the tunnel IP — reverse shells, hosting, and the AD kit (`nxc`, `bloodyAD`, `certipy`, `evil-winrm`, impacket, `bhcollect`) |
| `scripts/roo bloodhound view <zip>` | local BloodHound CE — ingest a collection and view the attack graph in the browser |
| `scripts/roo fwd <port>` | bridge a tunnel port to a host listener |
| `scripts/roo ip` | print the tunnel IP (your LHOST) |

See **[ARCHITECTURE.md](ARCHITECTURE.md)** for the design (the sidecar is a
*location*; everything else is a *tool* that runs in its namespace).

## Active Directory

When recon finds a Domain Controller (Kerberos + LDAP + SMB), the agent switches
to the **ad** skill — a credentialed AD runbook driving `nxc`, `bloodyAD`,
`certipy`, and impacket from `roo shell`: domain ID → shares/users/roast → ADCS,
delegation, ACL and **BadSuccessor** (Server 2025 dMSA) triage → DCSync. It's
built to work on *hardened* DCs: tools that **seal** LDAP (so signing-enforced /
LDAPS-resetting DCs don't block you), `clocksync <dc>` to beat Kerberos clock
skew without touching the host clock, and `bhcollect <dc> <user> <pass>` —
one command that collects a BloodHound graph via rusthound-ce's Kerberos path
where the usual Python collectors can't. View it with
`scripts/roo bloodhound view <zip>` (the **bloodhound** skill).

## Requirements

- **Docker** (Engine, Desktop, or OrbStack) — all tooling runs in containers.
- **Python 3** — runs the `roo` CLI (stdlib only).
- *Optional, for `roo browser`* — a Chromium-family browser (Chrome/Chromium/
  Edge/Brave) on the host, plus **Node** (`npx`) for the agent's Playwright MCP.
- *Recommended, for sharper advice* — the
  **[Context7](https://github.com/upstash/context7)** and
  **[Exa](https://github.com/exa-labs/exa-mcp-server)** MCP servers. Context7
  pulls current tool/service docs and Exa does live web search, which materially
  improves the agent's enumeration and fingerprinting guidance (version quirks,
  default creds, known-good flags, technique write-ups). See
  [docs/MCP.md](docs/MCP.md).

## VPN targets

Drop a `.ovpn` in `./vpn/` (git-ignored) and recon the box — `roo` runs the VPN
as a sidecar container and shares its network namespace with tool containers, so
it works the same across platforms (where a container otherwise can't reach a
host `tun`). You don't touch Docker networking. Manage the tunnel with
`scripts/roo vpn up|down|status` (the agent brings it up for you, but you can
drive it directly).

**Run only one tunnel per `.ovpn`.** HTB/THM allow a single connection per
config. A host VPN client on the same `.ovpn` fights the sidecar for the slot and
makes scans flaky (ports flip `filtered`/open). If scans look unreliable, suspect
this first — disconnect the host client and let the sidecar own the tunnel.

## Host name overrides

Containers can't see the host's `/etc/hosts`, so RooRecon keeps its own. Tell the
agent ("`box.htb` is `10.10.10.5`") or add lines to a git-ignored `./hosts`:

```
10.10.10.5  box.htb  admin.box.htb
```

`roo` mounts it into every tool container, direct or over VPN.

## Layout

```
.claude/skills/<name>/SKILL.md   # skill playbooks (auto-loaded by Claude Code)
scripts/roo.py                   # the cross-platform roo CLI
docker/<tool>/Dockerfile         # one minimal image per CLI
ARCHITECTURE.md                  # design + decisions
CLAUDE.md / AGENTS.md            # Claude Code / Codex entry points
vpn/ · hosts · recon-results/    # configs, host overrides, output (git-ignored)
```

## Authorized use only

For **CTF boxes, lab ranges, and signed-scope systems** only. Don't scan systems
you aren't explicitly authorized to assess.

## Model access (verification required)

These skills drive dual-use tooling that frontier labs gate behind verification —
models may refuse offensive tasks unless your account is verified for security
work:

- **Anthropic — Cyber Verification Program:**
  [Apply](https://claude.com/form/cyber-use-case) ·
  [Overview](https://support.claude.com/en/articles/14604842-real-time-cyber-safeguards-on-claude) ·
  [Policy](https://www.anthropic.com/aup)
- **OpenAI — Trusted Access for Cyber:**
  [Overview](https://openai.com/index/trusted-access-for-cyber/) ·
  [Verify](https://chatgpt.com/cyber)

## Credits

- **Wordlists** — [SecLists](https://github.com/danielmiessler/SecLists) (Daniel
  Miessler, Jason Haddix & contributors).
- **Tooling** — [nmap](https://nmap.org),
  [gobuster](https://github.com/OJ/gobuster),
  [WhatWeb](https://github.com/urbanadventurer/WhatWeb),
  [OpenVPN](https://openvpn.net), each in its own minimal container.
- **Active Directory** — [NetExec](https://github.com/Pennyw0rth/NetExec),
  [Impacket](https://github.com/fortra/impacket) (Fortra),
  [bloodyAD](https://github.com/CravateRouge/bloodyAD),
  [Certipy](https://github.com/ly4k/Certipy),
  [evil-winrm](https://github.com/Hackplayers/evil-winrm) /
  [evil-winrm-py](https://github.com/adityatelange/evil-winrm-py), and
  [RustHound-CE](https://github.com/g0h4n/RustHound-CE) feeding
  [BloodHound CE](https://github.com/SpecterOps/BloodHound) (SpecterOps).
- **Browser control** — [Playwright MCP](https://github.com/microsoft/playwright-mcp)
  (Microsoft) drives the host browser over CDP for `roo browser`.
- **Vulnerability & exploit data** (keyless) — [NVD](https://nvd.nist.gov) (NIST),
  [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
  [EPSS](https://www.first.org/epss) (FIRST),
  [Exploit-DB](https://www.exploit-db.com) (OffSec),
  [PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub), and
  [Metasploit Framework](https://github.com/rapid7/metasploit-framework) module
  metadata (Rapid7 & contributors).
