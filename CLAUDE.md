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
(`scripts/roo.py`, stdlib Python) — invoke `./roo` from the repo root on
Unix/macOS or `.\roo` from PowerShell/cmd (or just `roo` with the repo root on
`PATH`). Subcommands:

```bash
./roo run <tool> [args...]          # e.g. ./roo run nmap -sCV -p- <t>
./roo pyrun [--py V] [--pip "pkgs"] <script> [args...]  # exploit runner: pinned python:V-slim, tunnel-aware, deps cached
./roo sweep <target>                # streaming parallel TCP+UDP discovery
./roo buckaroo <target> <proto> <port>   # per-port enum + hostname discovery
./roo vhost <ip> <domain>           # vhost (Host-header) enum, internal IP
./roo dns <domain>                  # DNS subdomain enum, external domain
./roo dirbust <url>                 # recursive directory/file brute (SecLists)
./roo sqlmap [args...]              # automated SQL injection detection + exploitation (target-facing)
./roo aws <service> <op> ...        # AWS CLI vs AWS or an AWS-compatible mock endpoint (tunnel-aware)
./roo fingerprint <url>             # web tech/version detection (whatweb), sharper than nmap
./roo vulns <target>                # CVE + public-PoC lookup for fingerprints (keyless)
./roo recon <target>                # simple one-shot phased scan
./roo report <target>               # assemble per-port facts+notes into report.md
./roo vol <image> <plugin|creds|strings>  # offline memory forensics (volatility3) on a RAM dump
./roo vpn <up|down|status> [cfg]    # OpenVPN sidecar (the "location")
./roo proxy <up|down|status>        # SOCKS5 egress for host tools (browser/Burp/curl)
./roo browser [url]                 # host browser, VPN-proxied + agent-drivable over CDP
./roo bloodhound <up|ingest|view|open|down> [zip]   # local BloodHound CE: ingest a collection, view the graph
./roo shell [cmd...]                # operator shell at the tunnel IP (reverse shells, hosting)
./roo catch <up|attach|status|send|capture|down> [port|cmd]  # persistent shared reverse-shell catcher (pwncat)
./roo responder [args...]           # LLMNR/NBT-NS/mDNS poisoning + capture (tunnel iface)
./roo ip                            # print the tunnel IP (your LHOST)
./roo fwd <port> [--stop]           # bridge a tunnel port to a host listener
./roo hashcat [args...]             # GPU password cracking on the HOST (auto-installs)
./roo wordlist <search|get|name>    # browse/fetch any SecLists list on demand (passwords default)
```

SecLists wordlists are baked into the gobuster/ffuf images (DNS/subdomain for
`vhost`/`dns`, Web-Content for `dirbust`/`ffuf`); each verb defaults to a fast
list, override with `--wordlist <name|host-path|seclists:<repo-path>>` or
`$ROO_WORDLIST`. Anything not baked is pulled on demand — `roo wordlist search
<kw>` to find a list, `roo wordlist get <repo-path>` to cache it (see the
**wordlists** skill). The whole repo is available without rebaking an image.

**Engagement scratch is organized *by target, not by runtime.*** Per-box exploit
scripts and custom inputs (payloads, wordlists, CSVs) go in
`recon-results/<target>/exploit/` — co-located with that box's facts/notes/report/
loot, git-ignored, self-contained. *How* a script runs (net-toolbox via
`roo shell`, or a pinned container via `./roo pyrun`) is metadata for its
header/shebang, not a reason to split the tree. Keep `.roo/` for machine-managed
runtime only (catch downloads, browser profile, MCP scratch) — **teardown** wipes
it, so don't author exploits there. A reusable *technique* (not the box-specific
instance) graduates to a tracked runbook under the relevant skill
(`<skill>/runbooks/<technique>.md`).

`roo` builds `docker/<tool>/Dockerfile` on demand (tagged by a hash of the tool's
whole build context — Dockerfile + any COPY'd files) and runs it with the cwd
mounted at `/work` — editing the Dockerfile or a copied asset changes the hash, so
the next run rebuilds automatically. For VPN-only targets, join the VPN
sidecar's network: `ROO_NET=container:roorecon-vpn ./roo run nmap ...`.

**Docker Hub rate limit on a first build** (`429 / toomanyrequests / pull rate
limit`) → the fix is **`docker login`** (authenticated pulls get a much higher
limit), then re-run. Don't retag/alias base images or edit Dockerfiles to dodge
it — `roo` prints this hint on a rate-limited build.

**Which box has which tool (don't guess).** `roo run <tool>` works *only* for
tools with a `docker/<tool>/Dockerfile` (`nmap`, `gobuster`, `ffuf`) — `roo run
curl …` fails, there's no such image. (`ffuf` complements `gobuster`: it fuzzes a
`FUZZ` keyword *inside* a request body/header/param — e.g. an SSRF `url=` — and
filters on the response, which `gobuster dir` can't.) Ad-hoc clients (curl, wget, nc, socat, dig,
smbclient, ldapsearch, impacket) and the AD attack tooling (`nxc`/NetExec,
`bloodyAD`, `certipy`, `evil-winrm` + `evil-winrm-py`, BloodHound collectors —
incl. `rusthound-ce` wrapped by the one-command `bhcollect` for hardened DCs —
plus the `clocksync`/`krbconf`/`faketime`/`rlwrap` helpers) live in
`net-toolbox` (which also carries **Responder** — run it on the tunnel iface with
**`./roo responder`** to poison LLMNR/NBT-NS/mDNS and capture NetNTLM —
plus `unzip` and the usual archive tools); reach them at the tunnel IP with
**`./roo shell <cmd>`**
(e.g. `./roo shell nxc smb <target> -u U -p P --shares`). For a Domain
Controller, follow the **ad** skill — it sequences these into a runbook and
carries the auth footgun fixes (MD4, clock skew, LDAP signing).
Rule of thumb: a scanner with its own image → `roo run`; anything else you'd run
on a jump box → `roo shell`. For web content discovery use
**`./roo dirbust <url>`**, not raw `gobuster dir` — it manages recursion
and wordlists. For CVE/exploit research use **`./roo vulns <target>`** (and
**`./roo fingerprint <url>`** to sharpen web versions first) — see the
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
- **Require a tunnel first.** Check `./roo vpn status`; if down,
  `./roo vpn up`, then prefix tools with
  `ROO_NET=container:roorecon-vpn`.
- **`.ovpn` configs live in `./vpn/`.** Asked to "connect to `foo.ovpn`"? Run
  `./roo vpn up foo.ovpn` — a bare name resolves against `./vpn/`, so don't
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
  Fast path: `./roo sweep` streams open ports while per-port
  `./roo buckaroo` deep-dives each one; simple path: `./roo recon`.
  Findings stream to the CLI as found; `./roo report` assembles the final
  document. Produces a prioritized "attack this first" list.
- **ad** (`.claude/skills/ad/SKILL.md`) — Active Directory enumeration +
  attack-path runbook. Recon hands off here on a DC profile (Kerberos+LDAP+SMB),
  or start here when you hold domain creds. Drives the `net-toolbox` AD tooling
  (`nxc`, `certipy`, `evil-winrm`, impacket) via `./roo shell`: domain ID →
  unauth footholds → credentialed sweep (shares/users/roast/BloodHound/ADCS) →
  triage to Domain Admin (delegation, ADCS ESCs, BadSuccessor on Server 2025,
  DCSync). Carries the auth footgun cheat-sheet (MD4, clock skew → `faketime`,
  LDAP signing → `nxc`).
- **dirbust** (`.claude/skills/dirbust/SKILL.md`) — recursive web content
  discovery. `./roo dirbust <url>` drives gobuster breadth-first over
  discovered directories (SecLists baked in), streaming each hit live.
- **sqlmap** (`.claude/skills/sqlmap/SKILL.md`) — automated SQL injection
  detection + exploitation. `./roo sqlmap [args...]` is a target-facing
  passthrough to sqlmap (prefix `ROO_NET=container:roorecon-vpn` for VPN boxes)
  that confirms an injection point, enumerates the DB, and dumps tables/creds —
  defaulting `--batch` (no hanging prompts) and `--output-dir recon-results/sqlmap`
  (session cached, loot persisted). Recon/dirbust/vuln-research hand an injectable
  param here; dumped hashes hand off to **hashcat**, plaintext creds to reuse/**ad**.
- **vuln-research** (`.claude/skills/vuln-research/SKILL.md`) — CVE + public-PoC
  lookup for recon fingerprints. `./roo vulns <target>` maps each
  product/version to CVEs (NVD/KEV/EPSS) and exploits (GitHub/Exploit-DB/
  Metasploit), ranked by exploitability; `./roo fingerprint <url>` (whatweb)
  sharpens web versions first. Runs post-fingerprint in recon and standalone.
  **CVE lookups egress on the public internet, never the VPN — don't prefix
  `roo vulns` with `ROO_NET`** (only `fingerprint` is target-facing).
- **cloud** (`.claude/skills/cloud/SKILL.md`) — cloud-emulator / AWS-mock attack
  path. Recon hands off here on an AWS-shaped endpoint (STS/S3/SQS/IAM, a
  `/latest/meta-data/` IMDS, a LocalStack/moto/`:4566` backend), or start here with
  an access key in hand. Drives **`./roo aws`** (containerized AWS CLI passthrough,
  tunnel-aware) through the genre's arc: SSRF→IMDS creds → map the IAM-enforcing
  gateway vs IAM-free backend → **permission-oracle** enumeration (not name-guessing)
  → abuse a service (queue→worker, CodeBuild privileged-container→host, ECS/EKS/Lambda
  exec, emulator→`docker.sock`). Carries the gateway-vs-backend split, the AKID-only-auth
  test, and the "verify the sink actually runs (native-image dead features)" footgun;
  deep service-abuse mechanics in its `service-abuse` runbook. Hashes/creds hand off to
  **hashcat**/**ad**; identify+read the emulator's source via **vuln-research**.
- **browse** (`.claude/skills/browse/SKILL.md`) — companion web browsing.
  `./roo browser [url]` launches a host Chrome routed through the VPN SOCKS
  proxy with a CDP debug port; the agent attaches via the **Playwright MCP**
  (`.mcp.json` `playwright` server — needs Node/`npx`) and drives the *same*
  browser the operator uses. Great for authenticated enumeration after the
  operator logs in. The browser is the one host (non-container) tool; its CDP
  channel is local (`127.0.0.1:9222`), only its page traffic is tunneled.
- **bloodhound** (`.claude/skills/bloodhound/SKILL.md`) — stand up BloodHound CE
  locally and load AD collection data to see the attack graph. `./roo
  bloodhound view <zip>` brings up the (host-local, non-tunneled) CE stack, ingests
  a SharpHound/rusthound/nxc collection over the REST API, and opens it in the
  browser. Analysis, not attack — collection is the **ad** skill's job; the
  compose stack is a documented architecture exception (see ARCHITECTURE.md).
- **hashcat** (`.claude/skills/hashcat/SKILL.md`) — offline hash cracking on the
  host GPU. `./roo hashcat` runs the real hashcat (auto-installs on first
  use; a host-tool exception, never target-facing) and `./roo wordlist`
  fetches SecLists password lists (default rockyou). The skill identifies the hash
  type → mode (`-m`) against hashcat's example-hashes wiki, then runs a
  wordlist→rules→mask ladder. The **ad** skill hands roasts (Kerberoast/AS-REP/
  NetNTLMv2) here. Triggers on "help me crack this hash".
- **wordlists** (`.claude/skills/wordlists/SKILL.md`) — pick + fetch the right
  SecLists list on demand. `./roo wordlist search <kw>` browses the whole repo by
  filename, `./roo wordlist get <repo-path>` caches one to `.roo/wordlists/`, and
  tools consume it via `--wordlist seclists:<path>` (gobuster `dirbust`/`vhost`/
  `dns`) or `/work/.roo/wordlists/<name>` (`roo run ffuf -w`). The baked
  gobuster/ffuf lists stay the fast path; everything else is pull-on-demand
  without rebaking an image. Carries the task→list-family table and "start small,
  widen on a miss" judgment. Triggers on "which wordlist", "find a wordlist",
  "seclists", "api/parameter/fuzz wordlist", "pull down a bigger list".
- **memforensics** (`.claude/skills/memforensics/SKILL.md`) — offline memory-image
  forensics. `./roo vol <image> creds` runs volatility3's credential trifecta
  (SAM hashdump + LSA secrets + cached domain creds) over a local RAM dump / VM
  memory snapshot (`.vmem`/`.dmp`/`hiberfil`); `… <plugin>` passes through any
  volatility3 plugin and `… strings` does a cleartext/flag sweep. Offline + host-
  side like hashcat (never the target/VPN). The **ad** skill hands a looted memory
  image here; recovered hashes loop back to its spray/PTH flow. Triggers on
  ".vmem", "memory dump", "lsass dump", "memory forensics", "extract creds from RAM".
- **wintools** (`.claude/skills/wintools/SKILL.md`) — fetch prebuilt Windows
  offensive tooling (GhostPack/Rubeus, SharpHound, Certify, the *Potato suite, …)
  from the Forge registry into a **shared, off-host `/tools` Docker volume**:
  `./roo tools list|builds|get|installed|rm`. Binaries land in the Docker VM
  (not a host path your EDR scans) and are visible at `/tools` in every `roo shell`
  to stage onto a target. `get` defaults to the **fresh main/branch build** over
  stale release tags (Rubeus-style — override with `--release`/`--ref`). Downloads
  egress the public internet, never the VPN. Triggers on "grab a windows tool".
- **catch** (`.claude/skills/catch/SKILL.md`) — persistent, shared reverse-shell
  catcher. `./roo catch up [port]` stands up **pwncat-cs in a tmux session**
  inside a detached, tunnel-bound `net-toolbox` container, prints the LHOST/port +
  paste-ready revshell one-liners, and listens. Both parties drive the *same*
  caught shell, drop-in/drop-out: the operator with `roo catch attach` (TTY), the
  agent with `roo catch send <cmd>` / `roo catch capture`. pwncat brings platform
  detection + `upload`/`download` (downloads default to `.roo/catch/`). Containers
  are named `roorecon-catch-<port>` so they're killable and swept by **teardown**.
- **teardown** (`.claude/skills/teardown/SKILL.md`) — clean end-of-engagement
  shutdown. Closes the browser, drops the proxy then the VPN tunnel (last), tidies
  Playwright MCP scratch (`.playwright-mcp/`) out of the tree, and verifies no
  `roorecon-*` containers remain — while preserving loot (`recon-results/`) and the
  saved browser profile. Triggers on "clean up", "shut down", "tear down", "wrap up".
- **retro** (`.claude/skills/retro/SKILL.md`) — the learning loop. Reads an
  engagement's operator↔agent interactions back and proposes durable improvements to
  the skills/runbooks/`roo` CLI: refine skills, extract runbooks, prune box-specific
  dead weight, suggest new skills/tools, and fix where the agent tripped. Edits the
  source of truth, so it's **proposal-first** (operator approves the changeset, applied
  on a branch) and disciplined about *generic over box-specific* and not over-fitting
  to one run (it keeps a cross-engagement memory in `docs/retro-log.md`). Run it before
  **teardown**, while transcript + artifacts are warm. Triggers on "retro", "debrief",
  "what did we learn", "improve the skills", "capture lessons".

## Ground rules

- **Authorized targets only.** Everything here is for CTF boxes, lab ranges, or
  systems in a signed engagement scope. Confirm scope before active scanning.
- **Stay within usage-policy bounds, and keep authorization explicit.** This repo
  is for *authorized* security testing — keep that context attached so the work is
  correctly recognized as legitimate. Name the engagement (CTF box, lab range,
  signed scope) and describe actions by their assessment goal ("read root.txt to
  prove the privesc", "recover the user hash to demonstrate the SQLi") rather than
  in real-world-harm terms ("exfiltrate the data", "deploy ransomware", "evade
  their EDR"). Some categories are out of bounds regardless of authorization and
  this repo does not do them: denial-of-service / resource exhaustion, destructive
  or self-propagating payloads (wipers, worms), mass or indiscriminate targeting,
  supply-chain compromise, and detection-evasion whose purpose is to defeat a real
  defender. If a task seems to need one of those, stop and reframe toward the
  assessment objective or ask the operator. The aim is to be genuinely in-bounds —
  not to strip context to push a request through.
- **Enumerate before exploiting.** Skills produce a map and a plan; the operator
  approves the actual attacking steps.
- **Tools run in containers, full stop.** No native-binary fallback — if Docker
  is missing or the tool image fails, that's a hard error, not a silent retry on
  the host. *Two deliberate exceptions, each a host tool by design (not a
  fallback) and justified in ARCHITECTURE.md:* **`browser`** (must be the
  operator's real browser) and **`hashcat`** (cracking wants the host GPU; a CPU
  container would be strictly slower). Both run on the host, never target-facing.

## Adding a skill

1. `mkdir -p .claude/skills/<name>` and write `SKILL.md` with `name` +
   `description` frontmatter (the description is what triggers activation).
2. Drive tools through `./roo run <tool>`. Reusable multi-step automation
   goes in `scripts/roo.py` as a new subcommand (keep it cross-platform: stdlib
   only, no shell-isms).
3. New CLI? Add `docker/<tool>/Dockerfile` (minimal, `FROM debian:stable-slim`)
   and, if it needs raw sockets, add the tool to `_caps()` in `scripts/roo.py`.
4. List it under "Available skills" above and in `AGENTS.md`.

### Keep SKILL.md lean — push deep technique detail to runbooks

A SKILL.md is loaded **in full every time the skill activates**, so inlining every
technique blows up context on engagements that use none of it. Use progressive
disclosure: the SKILL.md is a **router + cross-cutting judgment**; deep, cherry-picked
technique mechanics live in `<skill>/runbooks/<technique>.md` and are `Read` **only
when that path is live**. Always-loaded cost stays ~flat; the on-disk library grows.

- **Keep inline** the judgment that applies on *most* engagements: the workflow
  skeleton, scope guardrail, footgun/auth cheat-sheets, tool-selection tables, and
  the dispatch menu that routes to runbooks. These are relevant whatever the box.
- **Extract to a runbook** durable technique mechanics that are deep *and*
  cherry-picked — used on a fraction of boxes, irrelevant otherwise (the `ad`
  skill's `runbooks/badsuccessor.md` is the reference example).
- **Route, don't orphan.** A runbook only gets read if the SKILL.md names it with a
  one-line "when to reach for this" trigger (same discipline as a skill
  `description`). Keep a runbooks index + the dispatch pointer in sync.
- **Shard by what the operator cherry-picks, not by atomic fact.** One
  `adcs-esc.md` covering ESC1–16, not sixteen files — over-sharding just trades
  context bloat for many reads to assemble one path. Don't extract a small,
  mostly-cross-cutting skill at all; the bar is a genuinely deep, niche block.
- **Subfile vs. its own skill.** Keep technique detail as a runbook *subfile* until
  it's independently triggerable — i.e. the agent should route to it *without*
  already being in the parent skill's flow. That bar is what earned `hashcat` and
  `memforensics` top-level skills (recon/ad hand off to them cold); most technique
  mechanics need the parent skill's context and stay subfiles.
