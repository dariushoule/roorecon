<p align="center">
  <img src="gemini_roorecon.png" alt="RooRecon" width="320">
</p>

# RooRecon

A CTF and authorized-pentesting skills repo for **Claude Code** and **Codex**.
It combines agent *skills* (methodology + judgment the agent applies) with
traditional *automation* (scripts that do the repeatable scanning work).

Start Claude Code or Codex inside this repo and the skills become available —
ask for recon on a box and the agent drives the right tooling and interprets
the output for you.

## Containerized tooling

Every CLI runs inside its own minimal Docker image, so a scan behaves
identically on Linux, macOS, and Windows — no host installs, no "works on my
machine." The single entry point is the cross-platform **`roo` CLI**
(`scripts/roo.py`, stdlib Python): run `scripts/roo` on Unix or `scripts\roo.cmd`
from PowerShell/cmd. It builds each tool's image on demand and runs it with your
current directory mounted at `/work`.

```bash
scripts/roo run nmap -sCV -p- 10.10.10.5   # runs nmap in roorecon/nmap
```

Images are tagged with a hash of their Dockerfile, so editing a Dockerfile
auto-rebuilds and unchanged tools start instantly.

## Quick start

```bash
# Just ask the agent to "recon 10.10.10.5", or drive the CLI directly:
scripts/roo sweep 10.10.10.5     # streaming parallel discovery (fast path)
scripts/roo recon 10.10.10.5     # simple one-shot phased scan
# → results in ./recon-results/10.10.10.5/
```

## What's here

| Skill | What it does | Drives |
|-------|--------------|--------|
| `recon` | Maps a target's attack surface. Fast path: streaming parallel TCP+UDP sweep that fires a per-port "buckaroo" deep-dive the moment each port opens. Simple path: a one-shot phased scan. | `roo sweep` + `roo buckaroo`, or `roo recon` |

More skills (web exploitation, pwn/reversing, crypto/forensics) are planned —
this repo intentionally starts small.

## Layout

```
.claude/skills/<name>/SKILL.md   # skill playbooks — auto-loaded by Claude Code
scripts/roo.py                   # the cross-platform roo CLI (tooling + automation)
scripts/roo, scripts/roo.cmd     # Unix and Windows shims to it
docker/<tool>/Dockerfile         # one minimal image per CLI (nmap, openvpn, …)
AGENTS.md                        # Codex entry point → same skills
CLAUDE.md                        # Claude Code conventions
vpn/                             # your .ovpn configs (git-ignored)
hosts                            # per-engagement /etc/hosts overrides (git-ignored)
recon-results/                   # scan output (git-ignored)
```

## Authorized use only

Everything here is for **CTF boxes, lab ranges, and systems in a signed
engagement scope**. Do not scan or test systems you are not explicitly
authorized to assess.

## Model access (provider verification required)

These skills drive dual-use security tooling, which frontier labs gate behind
verification programs — Claude and OpenAI models will refuse or limit
offensive/dual-use tasks unless your account is verified for legitimate security
work. To use RooRecon with foundation-lab models, enroll in the relevant program:

- **Anthropic — Cyber Verification Program (CVP):** free, application-based;
  lifts default blocks on dual-use work for verified defenders.
  [Apply](https://claude.com/form/cyber-use-case) ·
  [Overview](https://support.claude.com/en/articles/14604842-real-time-cyber-safeguards-on-claude) ·
  [Usage Policy](https://www.anthropic.com/aup)
- **OpenAI — Trusted Access for Cyber (TAC):** identity + organizational
  verification with tiered access for defenders.
  [Overview](https://openai.com/index/trusted-access-for-cyber/) ·
  [Verify](https://chatgpt.com/cyber)

Access remains subject to each provider's usage policy and the authorized-scope
rules above.

## Requirements

- **Docker** — all tooling runs in containers (Docker Engine, Docker Desktop,
  or OrbStack).
- **Python 3** — runs the `roo` CLI (stdlib only, no `pip install`).

That's it. The `roo` CLI runs natively from **PowerShell**, cmd, bash, zsh, or
Git Bash — same behavior everywhere. No host installs of `nmap` etc.; the images
carry them.

### VPN targets (HTB/THM/OpenVPN)

**Just drop your engagement `.ovpn` into `./vpn/`** (git-ignored) and ask the
agent to recon the box — it brings the tunnel up and routes every tool through
it for you. You don't touch Docker networking.

Under the hood it runs the VPN as a sidecar container and has tool containers
share its network namespace, so this works the same on Linux, macOS, and Windows
(where a container otherwise can't reach a VPN `tun` on the host).

### Host name overrides

The host's `/etc/hosts` is invisible to containers, so RooRecon keeps its own.
When a box needs a name, just tell the agent (e.g. "`box.htb` is `10.10.10.5`")
and it records the mapping — or add it yourself to a git-ignored `./hosts` file
(same format as `/etc/hosts`):

```
10.10.10.5  box.htb  admin.box.htb
```

Either way `roo` mounts it into every tool container, so vhost resolution works
whether you scan direct or over the VPN.
