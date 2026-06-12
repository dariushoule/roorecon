# RooRecon

CTF and authorized-pentest skills repo for Claude Code and Codex. A mix of
agent skills (methodology + judgment) and traditional automation (scripts that
do the repeatable work).

## How skills work here

Skills live in `.claude/skills/<name>/SKILL.md` and are auto-discovered by
Claude Code — each activates when its `description` matches the task. The
SKILL.md is the single source of truth; the automation it drives lives in the
`roo` CLI (`scripts/roo.py`). Codex reads the same skills via `AGENTS.md`.

## Containerized tooling (convention)

All CLIs run in containers, never from the host, so behavior is identical across
Linux/macOS/Windows. The single entry point is the cross-platform `roo` CLI
(`scripts/roo.py`, stdlib Python) — invoke `scripts/roo` on Unix or
`scripts\roo.cmd` from PowerShell/cmd. Subcommands:

```bash
scripts/roo run <tool> [args...]          # e.g. scripts/roo run nmap -sCV -p- <t>
scripts/roo sweep <target>                # streaming parallel TCP+UDP discovery
scripts/roo buckaroo <target> <proto> <port>   # per-port enum + hostname discovery
scripts/roo vhost <ip> <domain>           # vhost (Host-header) enum, internal IP
scripts/roo dns <domain>                  # DNS subdomain enum, external domain
scripts/roo recon <target>                # simple one-shot phased scan
scripts/roo vpn <up|down|status> [cfg]    # OpenVPN sidecar
```

Name-enum wordlists are baked into the gobuster image (SecLists); default is a
fast list, override with `--wordlist <name|host-path>` or `$ROO_WORDLIST`.

`roo` builds `docker/<tool>/Dockerfile` on demand (tagged by Dockerfile hash)
and runs it with the cwd mounted at `/work`. For VPN-only targets, join the VPN
sidecar's network: `ROO_NET=container:roorecon-vpn scripts/roo run nmap ...`.

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
- **Require a tunnel before scanning such a target.** Check
  `scripts/roo vpn status`. If it's down, start it with `scripts/roo vpn up`,
  then route tools through it:
  `ROO_NET=container:roorecon-vpn scripts/roo sweep <target>`.
- **If no OpenVPN config is present, ask for one.** `scripts/roo vpn up` looks
  for a `.ovpn` in `./vpn/`. If there is none, STOP and ask the user to drop
  their `.ovpn` into `./vpn/` (it's git-ignored) — never attempt to scan a
  VPN-only target without it.
- **Run exactly one tunnel per `.ovpn` — don't fight the sidecar.** Platforms
  like HTB/THM allow only a single connection per config. If the user also has a
  host VPN client (system OpenVPN, the HTB app, Tunnelblick, etc.) connected with
  the **same** `.ovpn`, it and the sidecar contend for that one slot — the server
  flaps between them and scans go flaky (ports show `filtered`/closed
  intermittently, results don't reproduce). If you see that symptom, suspect
  contention first, not the box. The fix: pick one tunnel. For this containerized
  flow, prefer the sidecar — have the user disconnect the host client, then
  `scripts/roo vpn up`. (The host client's tunnel usually doesn't route into the
  Docker VM anyway, which is why the sidecar exists.)
- **Note internal IPs.** Record every private/internal IP you encounter — the
  target itself and any internal hosts surfaced in scan output — as pivot
  candidates in your engagement notes.
- **Host overrides go in `./hosts`, not the host's `/etc/hosts`.** The host's
  `/etc/hosts` is invisible to containers. When a box needs a name (e.g.
  `10.10.10.5 box.htb`), add the line to `./hosts`; `roo` mounts it into every
  tool container automatically (works direct or over VPN).
- **Follow hostnames the box reveals.** A buckaroo on a web port reports
  redirect/cert hostnames (in `facts.md` and `hostnames.txt`). Add each to
  `./hosts`, then enumerate more: `roo vhost <ip> <domain>` for an internal IP,
  `roo dns <domain>` for an external one. Feed new names back into `./hosts` and
  re-buckaroo — recon is a loop, not a line.

## Available skills

- **recon** (`.claude/skills/recon/SKILL.md`) — network/service/web enumeration.
  Fast path: `scripts/roo sweep` streams open ports while per-port
  `scripts/roo buckaroo` deep-dives each one; simple path: `scripts/roo recon`.
  Produces a prioritized "attack this first" list.

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
2. Drive tools through `scripts/roo run <tool>`. Reusable multi-step automation
   goes in `scripts/roo.py` as a new subcommand (keep it cross-platform: stdlib
   only, no shell-isms).
3. New CLI? Add `docker/<tool>/Dockerfile` (minimal, `FROM debian:stable-slim`)
   and, if it needs raw sockets, add the tool to `_caps()` in `scripts/roo.py`.
4. List it under "Available skills" above and in `AGENTS.md`.
