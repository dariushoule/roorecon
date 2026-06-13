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
scripts/roo dirbust <url>                 # recursive directory/file brute (SecLists)
scripts/roo fingerprint <url>             # web tech/version detection (whatweb), sharper than nmap
scripts/roo vulns <target>                # CVE + public-PoC lookup for fingerprints (keyless)
scripts/roo recon <target>                # simple one-shot phased scan
scripts/roo report <target>               # assemble per-port facts+notes into report.md
scripts/roo vpn <up|down|status> [cfg]    # OpenVPN sidecar (the "location")
scripts/roo proxy <up|down|status>        # SOCKS5 egress for host tools (browser/Burp/curl)
scripts/roo shell [cmd...]                # operator shell at the tunnel IP (reverse shells, hosting)
scripts/roo ip                            # print the tunnel IP (your LHOST)
scripts/roo fwd <port> [--stop]           # bridge a tunnel port to a host listener
```

SecLists wordlists are baked into the gobuster image (DNS/subdomain for
`vhost`/`dns`, Web-Content for `dirbust`); each verb defaults to a fast list,
override with `--wordlist <name|host-path>` or `$ROO_WORDLIST`.

`roo` builds `docker/<tool>/Dockerfile` on demand (tagged by a hash of the tool's
whole build context — Dockerfile + any COPY'd files) and runs it with the cwd
mounted at `/work` — editing the Dockerfile or a copied asset changes the hash, so
the next run rebuilds automatically. For VPN-only targets, join the VPN
sidecar's network: `ROO_NET=container:roorecon-vpn scripts/roo run nmap ...`.

**Docker Hub rate limit on a first build** (`429 / toomanyrequests / pull rate
limit`) → the fix is **`docker login`** (authenticated pulls get a much higher
limit), then re-run. Don't retag/alias base images or edit Dockerfiles to dodge
it — `roo` prints this hint on a rate-limited build.

**Which box has which tool (don't guess).** `roo run <tool>` works *only* for
tools with a `docker/<tool>/Dockerfile` (`nmap`, `gobuster`) — `roo run curl …`
fails, there's no such image. Ad-hoc clients (curl, wget, nc, socat, dig,
impacket) live in `net-toolbox`; reach them at the tunnel IP with
**`scripts/roo shell <cmd>`** (e.g. `scripts/roo shell curl -s http://target/`).
Rule of thumb: a scanner with its own image → `roo run`; anything else you'd run
on a jump box → `roo shell`. For web content discovery use
**`scripts/roo dirbust <url>`**, not raw `gobuster dir` — it manages recursion
and wordlists. For CVE/exploit research use **`scripts/roo vulns <target>`** (and
**`scripts/roo fingerprint <url>`** to sharpen web versions first) — see the
vuln-research skill.

**Windows/Git-Bash gotcha:** an arg that looks like a Unix path (`/wordlists/x`,
`/usr/share/...`) gets MSYS-mangled into `C:/Program Files/Git/...` before it
reaches the container. Prefix the command with `MSYS_NO_PATHCONV=1` when passing
absolute container paths.

**Architecture (read `ARCHITECTURE.md` before adding tools/skills).** The VPN
sidecar is a *location* — it owns the tunnel namespace and nothing else (no tools
in it). Everything else is a *tool* that runs in that namespace: scanners
(`nmap`, `gobuster`) and the `net-toolbox` operator image, whose three run-modes
are `proxy` (outbound SOCKS egress), `shell` (inbound listeners/hosting at the
tunnel IP), and `fwd` (bridge a tunnel port to a host listener). Reverse shells
and stage hosting must bind the tunnel IP, so they live in `shell`, not behind a
proxy. Don't apt-install tools into the sidecar; add them to `net-toolbox`.

## Networking & VPN (agent guidance — important)

- **Recognize internal/VPN-only targets.** Any RFC1918 (`10/8`, `172.16/12`,
  `192.168/16`), CGNAT (`100.64/10`), or VPN platform (HackTheBox, TryHackMe) is
  reachable only through a tunnel.
- **Resolve hostnames before assuming external.** Resolve a name first and pick
  the path from what it resolves to. Lab/CTF names (`*.htb`, `*.thm`, `*.box`,
  `.local`, internal corp domains) usually don't resolve via public DNS — they
  need a `./hosts` entry (which needs the box's IP) or DNS pushed by the VPN. Can't
  resolve and don't have the IP? **Ask the user** — don't scan blind. (Resolution
  differs by mode: a tool container uses its own DNS + mounted `./hosts`; over the
  VPN it uses the tunnel's DNS — never the host resolver.)
- **Require a tunnel first.** Check `scripts/roo vpn status`; if down,
  `scripts/roo vpn up`, then prefix tools with
  `ROO_NET=container:roorecon-vpn`.
- **`.ovpn` configs live in `./vpn/`.** Asked to "connect to `foo.ovpn`"? Run
  `scripts/roo vpn up foo.ovpn` — a bare name resolves against `./vpn/`, so don't
  hunt for the full path. One config there → plain `roo vpn up` auto-picks it.
- **No `.ovpn` present → STOP and ask.** `roo vpn up` needs a `.ovpn` in `./vpn/`
  (git-ignored). Never scan a VPN-only target without one.
- **One tunnel per `.ovpn`.** HTB/THM allow a single connection per config; a host
  VPN client on the *same* `.ovpn` contends with the sidecar and makes scans flaky
  (ports flip `filtered`/closed, nothing reproduces). On that symptom, suspect
  contention before the box — disconnect the host client and prefer the sidecar.
  (A host client's tunnel usually can't route into the Docker VM anyway — the
  reason the sidecar exists.)
- **Note internal IPs.** Record every private IP you see — the target and any
  internal hosts in scan output — as pivot candidates.
- **Host overrides go in `./hosts`, not the host's `/etc/hosts`** (invisible to
  containers). Add lines like `10.10.10.5 box.htb`; `roo` mounts them into every
  tool container (direct or over VPN).
- **Follow hostnames the box reveals.** Buckaroos report redirect/cert hostnames
  (`facts.md`, `hostnames.txt`). Add each to `./hosts`, then enumerate more:
  `roo vhost <ip> <domain>` (internal) or `roo dns <domain>` (external) for names,
  `roo dirbust <url>` for paths. Feed new names back into `./hosts` and
  re-buckaroo — recon is a loop, not a line.

## Available skills

- **recon** (`.claude/skills/recon/SKILL.md`) — network/service/web enumeration.
  Fast path: `scripts/roo sweep` streams open ports while per-port
  `scripts/roo buckaroo` deep-dives each one; simple path: `scripts/roo recon`.
  Findings stream to the CLI as found; `scripts/roo report` assembles the final
  document. Produces a prioritized "attack this first" list.
- **dirbust** (`.claude/skills/dirbust/SKILL.md`) — recursive web content
  discovery. `scripts/roo dirbust <url>` drives gobuster breadth-first over
  discovered directories (SecLists baked in), streaming each hit live.
- **vuln-research** (`.claude/skills/vuln-research/SKILL.md`) — CVE + public-PoC
  lookup for recon fingerprints. `scripts/roo vulns <target>` maps each
  product/version to CVEs (NVD/KEV/EPSS) and exploits (GitHub/Exploit-DB/
  Metasploit), ranked by exploitability; `scripts/roo fingerprint <url>` (whatweb)
  sharpens web versions first. Runs post-fingerprint in recon and standalone.
  **CVE lookups egress on the public internet, never the VPN — don't prefix
  `roo vulns` with `ROO_NET`** (only `fingerprint` is target-facing).

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
