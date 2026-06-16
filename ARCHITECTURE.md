# RooRecon architecture

How the tooling is structured and why. This is the "why" companion to
`CLAUDE.md`/`AGENTS.md` (the "how to drive it"). If you're adding a tool, a
skill, or a new network capability, read this first — it explains the one
principle everything else follows.

## The core principle: a location, and tools that run in it

Every CLI runs in a container. For VPN/CTF work the question that organizes
everything is *which network namespace does a tool run in*, because a routed
OpenVPN tunnel (its `tun0` interface and routes) lives in **exactly one network
namespace**. Only processes in that namespace can reach the engagement network.

So we split two orthogonal concerns:

- **The location** — a single long-lived container (`roorecon-vpn`, the OpenVPN
  *sidecar*) that owns the tunnel and the namespace. Its only job is to *be the
  place*. Tool containers join it with `--network container:roorecon-vpn` and
  inherit the tunnel.
- **The tools** — short(er)-lived containers that do the actual work (scan,
  proxy, listen, forward) *in* that namespace. Tools are interchangeable; the
  namespace is the constant.

**The rule that keeps this clean: the location image carries no tools.** The
sidecar is `openvpn` + `iproute2` and nothing else. It may carry namespace-level
*config* that only the namespace owner can establish (see below) — but never an
apt-installed tool. The moment you `apt install socat` into the sidecar "just to
make one command work," it stops being a location and becomes a junk drawer.
Put the tool in a tool image instead and run it in the namespace.

## Why not one monolithic image

Tempting — one image with OpenVPN and every tool — but it fuses three things
that must vary independently:

- **Privilege.** The sidecar needs `NET_ADMIN` + `/dev/net/tun`. Scanners need
  `NET_RAW`. The operator toolbox needs neither. A monolith forces maximum
  privilege on everything — wrong for a security tool specifically.
- **Lifetime.** The tunnel is long-lived; tearing it down drops every caught
  shell. You must be able to update or run a scanner *without* restarting the
  tunnel. Separate images make tools come and go while the location persists.
- **Rebuild blast radius.** Images are tagged by a hash of their Dockerfile, so
  any edit rebuilds that image (and only that image) on next use — editing a
  wordlist rebuilds `gobuster`, not the tunnel and not the toolbox.
- **Conceptual clarity for skills.** A skill says "run tool X in the engagement
  namespace." The author never reasons about Docker networking — the namespace
  is a given, tools plug into it.

## The images

| Image | Role | Notes |
|-------|------|-------|
| `openvpn` | **location** — owns the tunnel + namespace | minimal: `openvpn` + `iproute2`. No tools. |
| `net-toolbox` | **operator tools** | `ncat`/`socat`/`microsocks`, impacket, the AD kit (`nxc`, `bloodyAD`, `certipy`, `evil-winrm`(+`-py`), BloodHound collectors), Responder, `smbclient`/`ldapsearch`/`dig`, `unzip`, `faketime`/`rlwrap`. One image, four run-modes (`shell`/`proxy`/`fwd`/`responder`). |
| `nmap` | **recon scanner** | `NET_RAW` for SYN/UDP/OS scans. Kept apart from operator tools: different privilege, different phase. |
| `gobuster` | **recon scanner** | vhost/DNS name enum + recursive content discovery (`dirbust`); SecLists baked in. |
| `bloodhound` (compose) | **local analysis platform** | 3-service CE stack (postgres + neo4j + web). *Not* a per-tool image, *not* in the tunnel — see the exception below. |

`net-toolbox` is deliberately *one* image used three ways rather than three
near-identical images — microsocks-as-egress, socat-as-forwarder, and the
interactive shell are all "operator tools," differing only in how they're run:

- `roo shell` — interactive (reverse-shell catchers, payload hosting, impacket,
  pivots), with `/work` mounted so loot lands on the host.
- `roo proxy` — detached `microsocks` (SOCKS5 egress for host tools).
- `roo fwd`   — detached `socat` (bridge a tunnel port to a host listener).
- `roo responder` — `Responder` on the tunnel iface (`tun0`): LLMNR/NBT-NS/mDNS
  poisoning + NetNTLM capture, persisting to `recon-results/responder/`. Like
  `shell`, an inbound listener bound to the engagement LAN — not a SOCKS egress.

**Persistent state across `--rm` runs** mounts in two ways, chosen by *whether it
should surface to the host*: `.roo/home` is a **host bind** for `$HOME`/tool caches
(visible on disk, git-ignored); the **`roorecon-tools` named volume** at `/tools`
(`roo tools`) is deliberately *not* a host bind — prebuilt Windows offensive
binaries live in the Docker VM, shared across every shell but never on a host path
your EDR scans (no false-positive quarantine). `roo tools` fetches from the public
internet (Forge), never the target/VPN — like CVE lookups.

### Three deliberate exceptions to "one minimal Dockerfile per tool, in the namespace"

Each exists because a capability is fundamentally **not a target-facing tool** and so
doesn't fit the per-image, in-the-tunnel model. Name them so they don't become a
licence to sprawl:

1. **The host browser** (`roo browser`) — a GUI you interact with can't live in a
   netns. It runs on the host, pointed at the VPN SOCKS proxy so only its *page
   traffic* is tunneled; the agent drives it over a local CDP port (Playwright MCP).
2. **BloodHound CE** (`roo bloodhound`) — a **local analysis platform**, not a
   tool that acts on the target. It's a 3-service stack (postgres + neo4j + the
   BloodHound API/web), so it's run via `docker compose`
   (`docker/bloodhound/docker-compose.yml`), not a hash-tagged per-tool image. It
   ingests *static collection files* and renders the graph for the operator, so it
   **never joins the tunnel namespace** — it binds `127.0.0.1` on the docker host
   and you view it in the browser. The target-facing half (collecting the data from
   the DC) stays a normal namespace tool in `net-toolbox` (`nxc`, the BloodHound
   collectors); only the *visualization* is this exception.
3. **hashcat** (`roo hashcat`) — **offline** cracking of hashes already on disk,
   not an action on the target. It wants the **host GPU**, which a container can't
   reliably reach (GPU passthrough is absent/painful, so a containerized hashcat is
   CPU-only and strictly slower) — so `roo hashcat` shells out to the real host
   binary, bootstrapping it on first use (apt / brew / the Windows portable build,
   cached under `.roo/hashcat`). It never sees the target or the tunnel; `roo
   wordlist` likewise just fetches SecLists fuel to `.roo/wordlists`. The
   target-facing half (capturing/roasting the hash) stays a namespace tool in
   `net-toolbox`; only the *cracking* is this exception.

The rule the exceptions still honour: **target-facing work runs as a tool in the
tunnel namespace.** A GUI, a local graph DB, and an offline GPU cracker aren't that,
so they're allowed out — anything that scans, auths to, or exploits the target is not.

## The sidecar is your box on the engagement network

Because the sidecar owns the tunnel IP, it *is* the tester's host on the
network. Capabilities sort cleanly by **connection direction**:

- **Outbound (you → target):** scanning, web apps, exploit delivery. Handled by
  scanner containers in the namespace, or by `roo proxy` for host-side tools
  (browser/Burp/curl) that speak SOCKS.
- **Inbound (target → you):** reverse shells, payload/stage hosting, file/DNS
  exfil, hash capture, pivot servers. These must **bind the tunnel IP**, so they
  run in the namespace via `roo shell`. A forward proxy cannot help here — SOCKS
  is outbound-only.
- **Inbound, but you insist on a host listener** (host-run C2/msfconsole):
  `roo fwd <port>` bridges `tunnel-ip:port` back to `host:port`. The escape
  hatch, not the default — catching in the namespace (`roo shell`) avoids
  double-bridged TTY headaches.
- **`roo ip`** prints the tunnel IP — your `LHOST` for every payload.

### What a forward proxy can't carry

`roo proxy` (SOCKS) and any `tun2socks`-style bridge terminate at the TCP/UDP
layer. Raw packets don't cross them: `nmap -sS`/`-sU`, ICMP, and OS
fingerprinting must originate *inside* the namespace. So **raw scans run as
scanner containers** (`ROO_NET=container:roorecon-vpn roo run nmap ...`);
app-level/TCP-connect work can go through the proxy.

## Docker constraints that shaped this (and the gotchas they create)

- **You can't publish ports from a netns-sharing container.** `docker run
  --network container:X -p ...` is rejected. So the host-facing SOCKS port is
  published by the **sidecar** at creation. Published ports are fixed at create
  time, so the sidecar always publishes it (cycle the tunnel to change the
  port). This is the one bit of namespace *config* — not a tool — that the
  location legitimately carries.
- **`--add-host` is rejected under `--network container:`.** So a tool container
  can't map `host.docker.internal` itself. The sidecar carries that mapping
  (`--add-host host.docker.internal:host-gateway`, also config), and `roo fwd`
  resolves the host's literal IP through the sidecar, then hands it to `socat`.
- **An open SOCKS proxy is a pivot risk.** `microsocks` is bound to the
  sidecar's **bridge IP, not `tun0`** — reachable from the host via the
  published port, but *not* from a box on the VPN that could otherwise use us as
  an open relay. The SOCKS port is also published on `127.0.0.1` only.
- **`roo fwd` binds `tun0` only**, so a forward accepts solely from the VPN side,
  and uses `TCP4` to the host (the `host.docker.internal` name can resolve
  IPv6-only on Docker Desktop).

## Cross-platform rules (Linux/macOS/Windows must behave identically)

Every tool is Linux-in-a-container, but the host shell may be Windows. Two
classes of bug come from forgetting that:

- **Paths handed to a tool must be POSIX.** `str(Path)` on Windows yields
  backslashes, which a Linux tool treats as literal filename characters — output
  scatters into mangled flat files. Use `_cpath()` (`as_posix()`) for any path
  passed as a container argument. Host-side mount *sources* stay native (Docker
  accepts them).
- **Our own output is forced to UTF-8.** Windows consoles default to cp1252, so
  printing the status glyphs (`—`/`→`/`…`) would raise `UnicodeEncodeError` and
  kill the thread doing it. `roo.py` reconfigures `stdout`/`stderr` to UTF-8 at
  startup.

## Operational: run exactly one tunnel per `.ovpn`

HTB/THM allow a single connection per config. A host VPN client and the sidecar
sharing the same `.ovpn` contend for that slot and make scans flaky (ports flip
`filtered`/open, nothing reproduces). If scans look unreliable, suspect
contention before the box. Prefer the sidecar; disconnect the host client. (A
host client's tunnel usually can't route into the Docker VM anyway — which is
the whole reason the sidecar exists.) See the README "Gotchas".

## Adding a capability

1. **A new scanner/tool?** Add `docker/<tool>/Dockerfile` (minimal,
   `FROM debian:stable-slim`). If it needs raw sockets, add it to `_caps()`.
   Drive it via `./roo run <tool>` or a thin subcommand.
2. **A new operator capability** (listener type, proxy, forwarder)? It's almost
   certainly another *run-mode of `net-toolbox`* in the namespace — not a new
   image. Add the tool to `net-toolbox`, add a thin verb that runs it with
   `--network container:roorecon-vpn`.
3. **Reusable multi-step automation?** A new `roo` subcommand in `scripts/roo.py`
   (stdlib only, cross-platform — no shell-isms, POSIX container paths).
4. **A new skill?** `.claude/skills/<name>/SKILL.md` with `name` + `description`
   frontmatter; list it in `CLAUDE.md` and `AGENTS.md`. Skills are methodology
   that *composes verbs*; verbs run *tool images* *in the namespace*.
