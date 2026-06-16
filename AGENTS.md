# RooRecon — Codex entry point

CTF and authorized-pentest skills repo. This file points Codex at the same
skills Claude Code uses, so there's one source of truth.

## Skills (read the SKILL.md before acting)

Each skill is a markdown playbook. When a task matches, read the file in full,
then follow its workflow and drive its helper scripts.

A SKILL.md is a **router + cross-cutting judgment**; deep, cherry-picked technique
mechanics live in `<skill>/runbooks/<technique>.md` and are read **only when that
path is live** (progressive disclosure — keeps the always-loaded skill lean). When
a SKILL.md's dispatch menu points you at a runbook (e.g. the **ad** skill →
`runbooks/badsuccessor.md` once `nxc -M badsuccessor` flags a Server 2025 OU), read
that file then. When *authoring*: keep the workflow/footguns/auth tables inline,
extract only genuinely deep + niche technique detail, and always name a runbook
with a one-line trigger so it isn't orphaned. See CLAUDE.md "Keep SKILL.md lean".

- **recon** → `.claude/skills/recon/SKILL.md`
  Network/service/web enumeration. Fast path: `./roo sweep` streams open
  ports while per-port `./roo buckaroo` deep-dives each; simple path:
  `./roo recon`. Findings stream to the CLI as found; `./roo report`
  assembles the final document. Produces a prioritized attack list.
  Use for: "recon", "enumerate", "scan", "what's open on this box", "where do
  I start on this target".
- **ad** → `.claude/skills/ad/SKILL.md`
  Active Directory enumeration + attack-path runbook. Recon hands off here on a
  DC profile (Kerberos+LDAP+SMB), or start here when you hold domain creds. Drives
  `net-toolbox` AD tooling (`nxc`, `bloodyAD`, `certipy`, `evil-winrm`, impacket) via
  `./roo shell`: domain ID → unauth footholds → credentialed sweep
  (shares/users/roast/BloodHound/ADCS) → triage to DA (delegation, ESCs,
  BadSuccessor on Server 2025, DCSync). Carries the auth footgun cheat-sheet
  (MD4, clock skew→faketime, LDAP signing→nxc). Use for: "active directory",
  "domain controller", "I have domain creds", "kerberoast", "bloodhound",
  "certipy/ADCS", "BadSuccessor", "DCSync", "evil-winrm", "what can I do on this DC".
- **bloodhound** → `.claude/skills/bloodhound/SKILL.md`
  Stand up BloodHound CE locally and load AD collection data to view the attack
  graph. `./roo bloodhound view <zip>` brings up the host-local CE stack
  (postgres+neo4j+web, *not* in the tunnel), ingests a collection over the REST
  API, and opens it in the browser. Analysis not attack; collection is the **ad**
  skill's job. Use for: "open bloodhound", "visualize the domain", "graph the AD",
  "show me paths to DA", "ingest this collection".
- **dirbust** → `.claude/skills/dirbust/SKILL.md`
  Recursive web content discovery: `./roo dirbust <url>` drives gobuster
  breadth-first over discovered directories (SecLists baked in), streaming hits.
  Use for: "dirbust", "directory brute", "content discovery", "find hidden
  paths/files", "fuzz endpoints".
- **sqlmap** → `.claude/skills/sqlmap/SKILL.md`
  Automated SQL injection detection + exploitation: `./roo sqlmap [args...]`
  is a target-facing passthrough to sqlmap (prefix `ROO_NET=container:roorecon-vpn`
  for VPN boxes) — confirms an injection point, enumerates the DB, dumps
  tables/creds. Defaults `--batch` (no hanging prompts) and `--output-dir
  recon-results/sqlmap` (injection point cached, loot persisted). Dumped hashes
  hand off to **hashcat**, plaintext creds to reuse/**ad**. Use for: "sqlmap",
  "SQL injection", "SQLi", "dump the users table", "is this param injectable".
- **vuln-research** → `.claude/skills/vuln-research/SKILL.md`
  CVE + public-PoC lookup for recon fingerprints: `./roo vulns <target>`
  maps product/version → CVEs (NVD/KEV/EPSS) and exploits (GitHub/Exploit-DB/
  Metasploit), ranked; `./roo fingerprint <url>` (whatweb) sharpens web
  versions first. CVE lookups hit the public internet, **never the VPN** — don't
  prefix `roo vulns` with `ROO_NET`. Use for: "CVE", "known vulnerabilities",
  "exploits for X", "is X vulnerable", "public PoC", "searchsploit".
- **browse** → `.claude/skills/browse/SKILL.md`
  Companion web browsing: `./roo browser [url]` launches a host browser
  routed through the VPN (SOCKS) with a CDP port; the agent attaches via the
  Playwright MCP (`.mcp.json`, needs Node) and drives the same browser the
  operator uses — authenticated enumeration, network/console capture, repro flows.
  CDP is local (127.0.0.1:9222); only page traffic is tunneled. Use for: "open a
  browser", "drive the browser", "poke around the web app", "log in and explore".
  **Before using this skill, read `docs/MCP.md`.** If browser/Playwright MCP
  tools are not visible in the current harness, you cannot drive the browser yet;
  tell the operator to enable the MCP and continue with CLI-based enumeration.
- **hashcat** → `.claude/skills/hashcat/SKILL.md`
  Offline hash cracking on the host GPU. `./roo hashcat` runs the real
  hashcat (auto-installs on first use — a host-tool exception, never
  target-facing); `./roo wordlist` fetches SecLists password lists (default
  rockyou). Identify the hash → mode (`-m`) via hashcat's example-hashes wiki, then
  wordlist→rules→mask. The **ad** skill hands roasts here. Use for: "help me crack
  this hash", "crack this NTLM/NetNTLMv2/kerberoast hash", "what hashcat mode".
- **memforensics** → `.claude/skills/memforensics/SKILL.md`
  Offline memory-image forensics. `./roo vol <image> creds` runs volatility3's
  credential trifecta (SAM hashdump + LSA secrets + cached domain creds) over a
  local RAM dump / VM memory snapshot (`.vmem`/`.dmp`/`hiberfil`); `… <plugin>`
  passes through any volatility3 plugin, `… strings` does a cleartext/flag sweep.
  Offline + host-side like hashcat (never target/VPN). The **ad** skill hands a
  looted memory image here; recovered hashes loop back to its spray/PTH flow. Use
  for: ".vmem", "memory dump", "lsass dump", "memory forensics", "creds from RAM".
- **wintools** → `.claude/skills/wintools/SKILL.md`
  Fetch prebuilt Windows offensive tooling (GhostPack/Rubeus, SharpHound, Certify,
  the *Potato suite, …) from the Forge registry into a **shared, off-host `/tools`
  Docker volume**: `./roo tools list|builds|get|installed|rm`. Binaries land
  in the Docker VM (not a host path EDR scans) and show at `/tools` in every `roo
  shell` to stage onto a target; downloads egress the public internet, never the
  VPN. `get` prefers the **fresh main/branch build** over stale release tags
  (Rubeus-style; override `--release`/`--ref`). Use for: "grab a windows tool",
  "download Rubeus/SharpHound", "I need <SharpX>".
- **catch** → `.claude/skills/catch/SKILL.md`
  Persistent, shared reverse-shell catcher: `./roo catch up [port]` runs
  pwncat-cs in a tmux session inside a detached, tunnel-bound net-toolbox container
  and prints the LHOST/port + paste-ready revshell one-liners. Both parties drive
  the same caught shell, drop-in/drop-out — operator `roo catch attach` (TTY),
  agent `roo catch send <cmd>` / `roo catch capture`. pwncat gives platform
  detection + `upload`/`download` (downloads → `.roo/catch/`). Named
  `roorecon-catch-<port>`, swept by teardown. Use for: "catch a shell", "set up a
  listener", "pwncat", "upload/download to the target", "stage a tool".
- **teardown** → `.claude/skills/teardown/SKILL.md`
  Clean end-of-engagement shutdown: close the browser, `roo proxy down`, then
  `roo vpn down` (last), remove Playwright scratch (`.playwright-mcp/`), verify no
  `roorecon-*` containers remain — preserving loot (`recon-results/`) and the saved
  browser profile. Don't auto-commit; solo commits only when asked. Use for: "clean
  up", "shut down", "tear down", "wrap up", "stop everything", "we're done".
- **retro** → `.claude/skills/retro/SKILL.md`
  The learning loop. Reads an engagement's operator↔agent interactions back and
  proposes durable improvements to the skills/runbooks/`roo` CLI — refine skills,
  extract runbooks, prune box-specific dead weight, suggest new skills/tools, fix
  where the agent tripped. **Proposal-first** (operator approves the changeset, applied
  on a branch), disciplined about *generic over box-specific* and not over-fitting to
  one run (cross-engagement memory in `docs/retro-log.md`). Run before **teardown**,
  while transcript + artifacts are warm. Use for: "retro", "debrief", "what did we
  learn", "improve the skills", "capture lessons".

## Containerized tooling (convention)

All CLIs run in containers, never from the host, so behavior is identical across
Linux/macOS/Windows. The single entry point is the cross-platform `roo` CLI
(`scripts/roo.py`) — `./roo` from the repo root on Unix/macOS, `.\roo` from
PowerShell/cmd (or just `roo` with the repo root on `PATH`). Subcommands:

```bash
./roo run <tool> [args...]          # e.g. ./roo run nmap -sCV -p- <t>
./roo sweep <target>                # streaming parallel TCP+UDP discovery
./roo buckaroo <target> <proto> <port>   # per-port enum + hostname discovery
./roo vhost <ip> <domain>           # vhost (Host-header) enum, internal IP
./roo dns <domain>                  # DNS subdomain enum, external domain
./roo dirbust <url>                 # recursive directory/file brute (SecLists)
./roo sqlmap [args...]              # automated SQL injection detection + exploitation (target-facing)
./roo fingerprint <url>             # web tech/version detection (whatweb)
./roo vulns <target>                # CVE + public-PoC lookup (keyless; not tunneled)
./roo recon <target>                # simple one-shot phased scan
./roo report <target>               # assemble per-port facts+notes into report.md
./roo vol <image> <plugin|creds|strings>  # offline memory forensics (volatility3) on a RAM dump
./roo vpn <up|down|status> [cfg]    # OpenVPN sidecar (the "location")
./roo proxy <up|down|status>        # SOCKS5 egress for host tools (browser/Burp)
./roo browser [url]                 # host browser, VPN-proxied + agent-drivable over CDP
./roo bloodhound <up|ingest|view|open|down> [zip]   # local BloodHound CE: ingest + view the graph
./roo shell [cmd...]                # operator shell at the tunnel IP (reverse shells, hosting)
./roo catch <up|attach|status|send|capture|down> [port|cmd]  # persistent shared reverse-shell catcher (pwncat)
./roo responder [args...]           # LLMNR/NBT-NS/mDNS poisoning + capture (tunnel iface)
./roo ip                            # print the tunnel IP (your LHOST)
./roo fwd <port> [--stop]           # bridge a tunnel port to a host listener
./roo hashcat [args...]             # GPU password cracking on the HOST (auto-installs)
./roo wordlist [name]               # fetch a SecLists password list (default rockyou)
./roo tools <list|builds|get|installed|rm> [name]  # prebuilt Windows tools → off-host /tools (prefers main builds)
```

It builds `docker/<tool>/Dockerfile` on demand and mounts the cwd at `/work`;
images are tagged by a hash of the tool's build context (Dockerfile + any COPY'd
files), so an edit to either rebuilds on the next run. VPN-only target? Join the sidecar's netns:
`ROO_NET=container:roorecon-vpn ./roo run nmap ...`.

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
  `./roo vpn status`; if down, `./roo vpn up`, then route tools
  through it: `ROO_NET=container:roorecon-vpn ./roo sweep <target>`.
- **If no OpenVPN config is present, ask for one.** `./roo vpn up` looks
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
  failed image build is a hard error, not a silent retry on the host. *Two
  deliberate host-tool exceptions (not fallbacks), per ARCHITECTURE.md:* `browser`
  (the operator's real browser) and `hashcat` (GPU cracking — host-side, never
  target-facing).

## Layout

- `.claude/skills/<name>/SKILL.md` — skill playbooks (source of truth).
- `.claude/skills/<name>/runbooks/<technique>.md` — deep per-technique deep-dives,
  read on demand when a skill routes to them (progressive disclosure).
- `roo`, `roo.cmd` — repo-root entrypoints (thin shims to `scripts/roo.py`).
- `scripts/roo.py` — the cross-platform `roo` CLI (all tooling + automation).
- `docker/<tool>/Dockerfile` — one minimal image per CLI.
- `docs/MCP.md` — MCP setup notes for browser control across harnesses.
- `recon-results/` — scan output (git-ignored).
