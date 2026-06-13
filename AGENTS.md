# RooRecon — Codex entry point

CTF and authorized-pentest skills repo. This file points Codex at the same
skills Claude Code uses, so there's one source of truth.

## Skills (read the SKILL.md before acting)

Each skill is a markdown playbook. When a task matches, read the file in full,
then follow its workflow and drive its helper scripts.

- **recon** → `.claude/skills/recon/SKILL.md`
  Network/service/web enumeration. Fast path: `scripts/roo sweep` streams open
  ports while per-port `scripts/roo buckaroo` deep-dives each; simple path:
  `scripts/roo recon`. Findings stream to the CLI as found; `scripts/roo report`
  assembles the final document. Produces a prioritized attack list.
  Use for: "recon", "enumerate", "scan", "what's open on this box", "where do
  I start on this target".
- **dirbust** → `.claude/skills/dirbust/SKILL.md`
  Recursive web content discovery: `scripts/roo dirbust <url>` drives gobuster
  breadth-first over discovered directories (SecLists baked in), streaming hits.
  Use for: "dirbust", "directory brute", "content discovery", "find hidden
  paths/files", "fuzz endpoints".
- **vuln-research** → `.claude/skills/vuln-research/SKILL.md`
  CVE + public-PoC lookup for recon fingerprints: `scripts/roo vulns <target>`
  maps product/version → CVEs (NVD/KEV/EPSS) and exploits (GitHub/Exploit-DB/
  Metasploit), ranked; `scripts/roo fingerprint <url>` (whatweb) sharpens web
  versions first. CVE lookups hit the public internet, **never the VPN** — don't
  prefix `roo vulns` with `ROO_NET`. Use for: "CVE", "known vulnerabilities",
  "exploits for X", "is X vulnerable", "public PoC", "searchsploit".

## Containerized tooling (convention)

All CLIs run in containers, never from the host, so behavior is identical across
Linux/macOS/Windows. The single entry point is the cross-platform `roo` CLI
(`scripts/roo.py`) — `scripts/roo` on Unix, `scripts\roo.cmd` from
PowerShell/cmd. Subcommands:

```bash
scripts/roo run <tool> [args...]          # e.g. scripts/roo run nmap -sCV -p- <t>
scripts/roo sweep <target>                # streaming parallel TCP+UDP discovery
scripts/roo buckaroo <target> <proto> <port>   # per-port enum + hostname discovery
scripts/roo vhost <ip> <domain>           # vhost (Host-header) enum, internal IP
scripts/roo dns <domain>                  # DNS subdomain enum, external domain
scripts/roo dirbust <url>                 # recursive directory/file brute (SecLists)
scripts/roo fingerprint <url>             # web tech/version detection (whatweb)
scripts/roo vulns <target>                # CVE + public-PoC lookup (keyless; not tunneled)
scripts/roo recon <target>                # simple one-shot phased scan
scripts/roo report <target>               # assemble per-port facts+notes into report.md
scripts/roo vpn <up|down|status> [cfg]    # OpenVPN sidecar (the "location")
scripts/roo proxy <up|down|status>        # SOCKS5 egress for host tools (browser/Burp)
scripts/roo shell [cmd...]                # operator shell at the tunnel IP (reverse shells, hosting)
scripts/roo ip                            # print the tunnel IP (your LHOST)
scripts/roo fwd <port> [--stop]           # bridge a tunnel port to a host listener
```

It builds `docker/<tool>/Dockerfile` on demand and mounts the cwd at `/work`;
images are tagged by a hash of the tool's build context (Dockerfile + any COPY'd
files), so an edit to either rebuilds on the next run. VPN-only target? Join the sidecar's netns:
`ROO_NET=container:roorecon-vpn scripts/roo run nmap ...`.

**Architecture:** the VPN sidecar is a *location* (owns the tunnel namespace);
everything else is a *tool* that runs in it. `proxy`/`shell`/`fwd` are run-modes
of one `net-toolbox` image, not the scanners. Read **`ARCHITECTURE.md`** before
adding a tool, skill, or network capability.

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
- **Follow hostnames the box reveals.** Buckaroos report redirect/cert hostnames
  (in `facts.md` + `hostnames.txt`). Add each to `./hosts`, then `roo vhost <ip>
  <domain>` (internal) or `roo dns <domain>` (external) to find more; loop the
  new names back through `./hosts` and re-buckaroo.

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
