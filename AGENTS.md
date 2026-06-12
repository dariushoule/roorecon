# RooRecon — Codex entry point

CTF and authorized-pentest skills repo. This file points Codex at the same
skills Claude Code uses, so there's one source of truth.

## Skills (read the SKILL.md before acting)

Each skill is a markdown playbook. When a task matches, read the file in full,
then follow its workflow and drive its helper scripts.

- **recon** → `.claude/skills/recon/SKILL.md`
  Network/service/web enumeration. Fast path: `scripts/roo sweep` streams open
  ports while per-port `scripts/roo buckaroo` deep-dives each; simple path:
  `scripts/roo recon`. Produces a prioritized attack list.
  Use for: "recon", "enumerate", "scan", "what's open on this box", "where do
  I start on this target".

## Containerized tooling (convention)

All CLIs run in containers, never from the host, so behavior is identical across
Linux/macOS/Windows. The single entry point is the cross-platform `roo` CLI
(`scripts/roo.py`) — `scripts/roo` on Unix, `scripts\roo.cmd` from
PowerShell/cmd. Subcommands:

```bash
scripts/roo run <tool> [args...]          # e.g. scripts/roo run nmap -sCV -p- <t>
scripts/roo sweep <target>                # streaming parallel TCP+UDP discovery
scripts/roo buckaroo <target> <proto> <port>   # per-port enum -> facts.md
scripts/roo recon <target>                # simple one-shot phased scan
scripts/roo vpn <up|down|status> [cfg]    # OpenVPN sidecar
```

It builds `docker/<tool>/Dockerfile` on demand and mounts the cwd at `/work`.
VPN-only target? Join the sidecar's netns:
`ROO_NET=container:roorecon-vpn scripts/roo run nmap ...`.

## Networking & VPN (agent guidance — important)

- **Recognize internal/VPN-only targets.** Any RFC1918 address (`10.0.0.0/8`,
  `172.16.0.0/12`, `192.168.0.0/16`), CGNAT (`100.64.0.0/10`), or a VPN-based
  platform (HackTheBox, TryHackMe) is reachable only through a tunnel.
- **Hostnames need explicit resolution — don't assume external.** When the target
  is a name, resolve it first and choose the network path from what it resolves
  to. Lab/CTF names (`*.htb`, `*.thm`, `*.box`, `.local`, internal corp domains)
  usually don't resolve via public DNS — they need a `./hosts` entry (which needs
  the box's IP) or DNS over the VPN. If you can't resolve a name and don't have
  its IP, **ask the user** rather than scanning blind.
- **Require a tunnel before scanning such a target.** Check
  `scripts/roo vpn status`; if down, `scripts/roo vpn up`, then route tools
  through it: `ROO_NET=container:roorecon-vpn scripts/roo sweep <target>`.
- **If no OpenVPN config is present, ask for one.** `scripts/roo vpn up` looks
  for a `.ovpn` in `./vpn/`. If there is none, STOP and ask the user to drop
  their `.ovpn` into `./vpn/` (git-ignored) — never scan a VPN-only target
  without it.
- **Note internal IPs.** Record every private/internal IP you encounter — the
  target and any internal hosts in scan output — as pivot candidates.
- **Host overrides go in `./hosts`, not the host's `/etc/hosts`** (which
  containers can't see). Add lines like `10.10.10.5 box.htb` to `./hosts`; `roo`
  mounts them into every tool container, direct or over VPN.

## Ground rules

- **Authorized targets only** — CTF boxes, lab ranges, or hosts in a signed
  engagement scope. Confirm scope before active scanning.
- **Enumerate before exploiting.** Produce a map and a plan; let the operator
  approve the actual attacking steps.
- **Tools run in containers, full stop** — no host fallback. Missing Docker or a
  failed image build is a hard error, not a silent retry on the host.

## Layout

- `.claude/skills/<name>/SKILL.md` — skill playbooks (source of truth).
- `scripts/roo.py` — the cross-platform `roo` CLI (all tooling + automation).
- `scripts/roo`, `scripts/roo.cmd` — Unix and Windows shims to it.
- `docker/<tool>/Dockerfile` — one minimal image per CLI.
- `recon-results/` — scan output (git-ignored).
