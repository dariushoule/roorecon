<p align="center">
  <img src="gemini_roorecon.png" alt="RooRecon" width="320">
</p>

# RooRecon

**A pentest & CTF copilot for [Claude Code](https://claude.com/claude-code) and
[Codex](https://openai.com/codex/).** Point an agent at a box (*"run recon on
10.10.10.5"*) and it runs a whole pipeline: discovers the attack surface,
fingerprints services, researches known exploits, and hands you a ranked
attack plan. 

Under the hood the agent reads each tool's output and decides the next move,
guided by **skills** and **runbooks**. A skill encodes high-level methodology
and runbooks carry step-by-step behaviors. 

## Requirements

- **Docker** for the containerized tooling.
- **Python 3** to run the `roo` CLI (stdlib only, nothing to `pip install`).
- *Optional, for `roo browser`*: a Chromium-family browser on the host, plus
  **Node** (`npx`) for the agent's Playwright MCP.
- *Recommended*: the **[Context7](https://github.com/upstash/context7)**. 

## Quick start

Drop your engagement `.ovpn` in `./vpn/` (if the target needs one), then start an
agent in this repo and just ask:

```sh
claude "Connect to lab.ovpn and run recon on 10.10.10.5"
```

The agent brings the tunnel up, sweeps the box, deep-dives each open port, and
streams findings as they land. 

## How it works

Ask for recon and the agent runs a pipeline, going deeper as results arrive:

```
sweep ports → enum each port → content/vhost discovery → CVE & exploit research → report
```

Each stage is a **skill** the agent activates by matching the task. Findings
stream to you live, and `./roo report <target>` assembles the final document.

| Skill | What it does |
|-------|--------------|
| **recon** | Map the attack surface (ports, services, web apps) and triage what to hit first. |
| **vuln-research** | Turn fingerprints into ranked CVEs + public PoCs (NVD/KEV/EPSS, GitHub, Exploit-DB, Metasploit). |
| **dirbust** | Recursive web content discovery (gobuster + SecLists). |
| **sqlmap** | Confirm and exploit SQL injection, then dump the creds that become the next foothold. |
| **ad** | Active Directory enumeration and attack-path runbook to Domain Admin (see below). |
| **bloodhound** | Stand up BloodHound CE locally and view the AD attack graph. |
| **hashcat** | Offline hash cracking on the host GPU: identify the mode, run the wordlist→rules→mask ladder. |
| **memforensics** | Pull creds and artifacts out of a RAM dump or lsass image with Volatility 3. |
| **browse** | Drive a real VPN-routed browser alongside the operator (Playwright MCP) for authenticated enumeration. |
| **catch** | Persistent, shared reverse-shell catcher (pwncat) both you and the agent can drive. |
| **wintools** | Stage prebuilt Windows offensive tooling (Rubeus, SharpHound, Certify, …) off-host. |
| **teardown** | Clean end-of-engagement shutdown: drop the browser, proxy, and tunnel while keeping the loot. |

Post-foothold, the VPN sidecar doubles as **your box on the engagement network**:

| Command | Use |
|---------|-----|
| `./roo shell` | operator shell at the tunnel IP for reverse shells, hosting, and the AD kit (`nxc`, `bloodyAD`, `certipy`, `evil-winrm`, impacket, `bhcollect`) |
| `./roo proxy up` | SOCKS5 egress so host browser/Burp/curl reach the target through the tunnel |
| `./roo browser [url]` | host browser, VPN-proxied and agent-drivable over CDP (Playwright MCP) |
| `./roo fwd <port>` | bridge a tunnel port to a host listener |
| `./roo ip` | print the tunnel IP (your LHOST) |

See **[ARCHITECTURE.md](ARCHITECTURE.md)** for the design (the VPN sidecar is a
*location*, and everything else is a *tool* that runs in its namespace), and
**[CLAUDE.md](CLAUDE.md)** / **[AGENTS.md](AGENTS.md)** for the full agent
guidance and command reference.

## VPN targets & host overrides

Drop a `.ovpn` in `./vpn/` (git-ignored) and recon the box. `roo` runs the VPN as
a sidecar container and shares its network namespace with tool containers, so it
works the same across platforms (where a container otherwise can't reach a host
`tun`). You don't touch Docker networking. Manage the tunnel directly with
`./roo vpn up|down|status` if you like, though the agent handles it for you.

> **Run only one tunnel per `.ovpn`.** HTB/THM allow a single connection per
> config. A host VPN client on the same `.ovpn` fights the sidecar for the slot
> and makes scans flaky (ports flip `filtered`/open). If scans look unreliable,
> suspect this first, disconnect the host client, and let the sidecar own it.

Containers can't see the host's `/etc/hosts`, so RooRecon keeps its own. Tell the
agent (*"`box.htb` is `10.10.10.5`"*) or add lines to a git-ignored `./hosts`
(`10.10.10.5  box.htb  admin.box.htb`). `roo` mounts it into every tool container,
direct or over VPN.

## Layout

```
roo · roo.cmd                    # entrypoints: run ./roo from the repo root
scripts/roo.py                   # the cross-platform roo CLI (all tooling + automation)
.claude/skills/<name>/SKILL.md   # skill playbooks (auto-loaded by Claude Code)
docker/<tool>/Dockerfile         # one minimal image per CLI
ARCHITECTURE.md                  # design + decisions
CLAUDE.md / AGENTS.md            # Claude Code / Codex entry points
vpn/ · hosts · recon-results/    # configs, host overrides, output (git-ignored)
```

## Model access (verification required)

These skills drive dual-use tooling that frontier labs gate behind verification.
Models may refuse offensive tasks unless your account is verified for security
work:

- **Anthropic, Cyber Verification Program:**
  [Apply](https://claude.com/form/cyber-use-case) ·
  [Overview](https://support.claude.com/en/articles/14604842-real-time-cyber-safeguards-on-claude) ·
  [Policy](https://www.anthropic.com/aup)
- **OpenAI, Trusted Access for Cyber:**
  [Overview](https://openai.com/index/trusted-access-for-cyber/) ·
  [Verify](https://chatgpt.com/cyber)

## Credits

RooRecon orchestrates a lot of excellent open-source tooling. Full attributions
are in **[CREDITS.md](CREDITS.md)**.
