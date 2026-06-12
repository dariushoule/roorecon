# RooRecon

A CTF and authorized-pentesting skills repo for **Claude Code** and **Codex**.
It combines agent *skills* (methodology + judgment the agent applies) with
traditional *automation* (scripts that do the repeatable scanning work).

Start Claude Code or Codex inside this repo and the skills become available —
ask for recon on a box and the agent drives the right tooling and interprets
the output for you.

## Containerized tooling

Every CLI runs inside its own minimal Docker image, so a scan behaves
identically on Linux, macOS, or Windows (WSL2) — no host installs, no
"works on my machine." `scripts/roo` is the single entry point: it builds the
tool's image on demand and runs it with your current directory mounted at
`/work`.

```bash
scripts/roo nmap -sCV -p- 10.10.10.5     # runs nmap in roorecon/nmap
```

Images are tagged with a hash of their Dockerfile, so editing a Dockerfile
auto-rebuilds and unchanged tools start instantly.

## Quick start

```bash
# Drive the recon skill directly, or just ask the agent to "recon 10.10.10.5"
scripts/recon/recon-host.sh 10.10.10.5
# → results in ./recon-results/10.10.10.5/  (summary.txt has the digest)
```

## What's here

| Skill | What it does | Drives |
|-------|--------------|--------|
| `recon` | Maps a target's attack surface: full TCP sweep, service/version fingerprinting, and a prioritized "attack this first" list. | `scripts/recon/recon-host.sh` |

More skills (web exploitation, pwn/reversing, crypto/forensics) are planned —
this repo intentionally starts small.

## Layout

```
.claude/skills/<name>/SKILL.md   # skill playbooks — auto-loaded by Claude Code
scripts/roo                      # containerized-tooling dispatcher
scripts/vpn                      # OpenVPN sidecar lifecycle (up/down/status)
scripts/lib/image.sh             # shared build-on-demand image helper
scripts/<name>/                  # automation each skill drives (calls roo)
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

## Requirements

- **Docker** — all tooling runs in containers (Docker Engine, Docker Desktop,
  or OrbStack). On Windows, run from **WSL2** with Docker integration.
- A POSIX shell (`bash`). On Windows that's WSL2 or Git Bash.

No host installs of `nmap` etc. — the images carry them.

### VPN targets (HTB/THM/OpenVPN)

A container can't reach a VPN tunnel on the host on every platform (Docker
Desktop on Windows/macOS won't route to a host `tun`). The portable fix: run the
VPN as a sidecar container and have tools share its network namespace.

```bash
# Drop your engagement .ovpn in ./vpn/ (git-ignored), then:
scripts/vpn up                 # starts the roorecon-vpn sidecar, prints the tunnel IP
ROO_NET=container:roorecon-vpn scripts/recon/recon-host.sh 10.10.10.5
scripts/vpn status             # check the tunnel
scripts/vpn down               # tear it down
```

### Host name overrides

The host's `/etc/hosts` is invisible to containers. Put per-engagement mappings
in a git-ignored `./hosts` file (same format as `/etc/hosts`):

```
10.10.10.5  box.htb  admin.box.htb
```

`roo` merges them with the standard localhost lines and mounts the result into
every tool container — so vhost resolution works whether you scan direct or over
the VPN.
