# RooRecon

CTF and authorized-pentest skills repo for Claude Code and Codex. A mix of
agent skills (methodology + judgment) and traditional automation (scripts that
do the repeatable work).

## How skills work here

Skills live in `.claude/skills/<name>/SKILL.md` and are auto-discovered by
Claude Code — each activates when its `description` matches the task. The
SKILL.md is the single source of truth; the helper scripts it drives live in
`scripts/<name>/`. Codex reads the same skills via `AGENTS.md`.

## Containerized tooling (convention)

All CLIs run in containers, never from the host, so behavior is identical
across Linux/macOS/Windows(WSL2). Never call `nmap` (or any tool) directly —
go through the dispatcher:

```bash
scripts/roo <tool> [args...]      # e.g. scripts/roo nmap -sCV -p- <target>
```

`scripts/roo` builds `docker/<tool>/Dockerfile` on demand (tagged by Dockerfile
hash) and runs it with the cwd mounted at `/work`. For VPN-only targets, join a
VPN sidecar's network: `ROO_NET=container:roorecon-vpn scripts/roo nmap ...`.

## Networking & VPN (agent guidance — important)

- **Recognize internal/VPN-only targets.** Any RFC1918 address (`10.0.0.0/8`,
  `172.16.0.0/12`, `192.168.0.0/16`), CGNAT (`100.64.0.0/10`), or a VPN-based
  platform (HackTheBox, TryHackMe) is reachable only through a tunnel.
- **Hostnames need explicit resolution — don't assume external.** When the
  target is a name rather than an IP, resolve it first and decide the network
  path from what it resolves to; if it's an internal range, apply the VPN flow.
  Lab/CTF names (`*.htb`, `*.thm`, `*.box`, `.local`, internal corp domains)
  usually do **not** resolve via public DNS — they need an entry in `./hosts`
  (or DNS pushed by the VPN), and that entry needs the box's IP. If you can't
  resolve a name and don't have its IP, **ask the user for the IP/mapping**
  rather than scanning blind. Note resolution context differs by mode: a tool
  container resolves via its own DNS + the mounted `./hosts`, and over the VPN it
  uses the tunnel's DNS — not the host's resolver.
- **Require a tunnel before scanning such a target.** Check `scripts/vpn status`.
  If it's down, start it with `scripts/vpn up`, then route tools through it:
  `ROO_NET=container:roorecon-vpn scripts/recon/recon-host.sh <target>`.
- **If no OpenVPN config is present, ask for one.** `scripts/vpn up` looks for a
  `.ovpn` in `./vpn/`. If there is none, STOP and ask the user to drop their
  `.ovpn` into `./vpn/` (it's git-ignored) — never attempt to scan a VPN-only
  target without it.
- **Note internal IPs.** Record every private/internal IP you encounter — the
  target itself and any internal hosts surfaced in scan output — as pivot
  candidates in your engagement notes.
- **Host overrides go in `./hosts`, not the host's `/etc/hosts`.** The host's
  `/etc/hosts` is invisible to containers. When a box needs a name (e.g.
  `10.10.10.5 box.htb`), add the line to `./hosts`; `roo` mounts it into every
  tool container automatically (works direct or over VPN).

## Available skills

- **recon** (`.claude/skills/recon/SKILL.md`) — network/service/web enumeration.
  Drives `scripts/recon/recon-host.sh` to map a target's attack surface and
  produce a prioritized "attack this first" list.

## Ground rules

- **Authorized targets only.** Everything here is for CTF boxes, lab ranges, or
  systems in a signed engagement scope. Confirm scope before active scanning.
- **Enumerate before exploiting.** Skills produce a map and a plan; the operator
  approves the actual attacking steps.
- **Tools run in containers, full stop.** No native-binary fallback — if Docker
  is missing or the tool image fails, that's a hard error, not a silent retry on
  the host.

## Adding a skill

1. `mkdir -p .claude/skills/<name>` and write `SKILL.md` with `name` +
   `description` frontmatter (the description is what triggers activation).
2. Put any automation in `scripts/<name>/`; have it drive tools via
   `scripts/roo`, keep it re-runnable.
3. New CLI? Add `docker/<tool>/Dockerfile` (minimal, `FROM debian:stable-slim`)
   and, if it needs raw sockets, a caps entry in the `roo` registry.
4. List it under "Available skills" above and in `AGENTS.md`.
