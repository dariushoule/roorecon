---
name: vuln-research
description: CVE and public-exploit (PoC) research for authorized pentesting and CTF. Use after recon fingerprints a service/version to find known vulnerabilities and working exploits — GitHub PoCs, Exploit-DB, Metasploit modules — ranked by exploitability. Also sharpens web fingerprints (versions) before lookup. Triggers on "CVE", "known vulnerabilities", "vuln research", "vuln lookup", "exploits for <service>", "is X vulnerable", "public PoC", "searchsploit", "find exploits", "what can I exploit".
---

# Vulnerability & exploit research

Turn recon fingerprints (service → product → version) into a ranked, evidence-backed
list of relevant CVEs and **public exploit PoCs**, then triage what's actually
exploitable on this box. Driven by `./roo vulns` (keyless data sources) and
`./roo fingerprint` (whatweb), plus your own page-pulls and web search.

This runs as the **post-fingerprint phase of recon** and **standalone**.

## Scope guardrail

Authorized targets only — CTF boxes, lab ranges, or signed-scope hosts. This skill
*finds* known vulns and public PoCs; it does not launch exploits. Running an exploit
against the target is an operator-approved step, not part of this skill.

## ⚠️ VPN / networking

CVE lookups hit the **public internet** (NVD, CISA KEV, EPSS, GitHub, Exploit-DB) —
**never the target**. `roo vulns` runs on the default docker network even when
`ROO_NET=container:roorecon-vpn` is set, so it works with the tunnel up or down and
never leaks research traffic through the engagement VPN. Do **not** prefix `roo vulns`
with `ROO_NET`. Only `roo fingerprint` (which talks to the target) honors `ROO_NET`.

## Workflow

### 1. Sharpen the fingerprint first (don't trust nmap alone)

A wrong version → wrong CVEs. nmap's `-sV` is a starting point; confirm and tighten it,
especially for web apps, before looking anything up.

- **Web services are auto-fingerprinted.** `roo buckaroo` already runs whatweb on every
  http/https port (against the IP) and drops `fingerprint.json` in the port dir, which
  `roo vulns` mines for app/library versions (WordPress, PHP, Tomcat, …) — so a versioned
  app nmap only labels "http" still gets a CVE lookup, automatically.
- **Re-fingerprint a discovered hostname/vhost** → `./roo fingerprint
  http://<hostname>/` (prefix `ROO_NET=container:roorecon-vpn` for a VPN-only target).
  The buckaroo hits the IP, so a vhost-only app (the IP just 301s to `box.htb`) needs an
  explicit run against the hostname — once it's in `./hosts` — to see the real app. Also
  use it for a deeper/aggressive re-scan.
- **Then mine pages by hand** for version strings whatweb misses (use
  `./roo shell curl ...` so it runs at the tunnel IP):
  - response headers: `Server`, `X-Powered-By`, `X-Generator`, `X-AspNet-Version`
  - cookies as framework tells: `PHPSESSID`, `JSESSIONID`, `laravel_session`,
    `csrftoken` (Django), `ci_session` (CodeIgniter)
  - HTML: `<meta name="generator">`, asset URLs with `?ver=1.2.3`, JS/CSS bundle names
  - well-known files: `/CHANGELOG`, `/CHANGELOG.md`, `/README`, `/VERSION`,
    `/composer.lock`, `/package.json`, `/wp-includes/version.php`, `/.git/`
  - login pages / footers: "Powered by X v1.2.3", admin panel banners
  - favicon hash → tech (when nothing else gives it away)
- Feed the **sharper** product+version back into the lookup (`roo vulns --product …
  --version …`, below). Recon is a loop — a better version means better CVEs.

### 2. Look up CVEs + PoCs

**From a completed recon dir** (reads every port's fingerprint, incl. the `nmap.xml`
CPEs the buckaroo now captures):

```bash
./roo vulns <target>            # e.g. ./roo vulns 10.10.10.5
```

**Ad-hoc** for a single product/version (no recon dir needed):

```bash
./roo vulns box --product nginx --version 1.18.0
./roo vulns box --cpe cpe:/a:openbsd:openssh:8.9p1
```

Useful flags: `--port tcp-80` (one port), `--min-bucket HIGH` (only chase PoCs for
high-severity), `--no-github/--no-msf/--no-searchsploit` (trim sources / rate-limit
pressure), `--refresh` (bypass the 24h cache).

It writes `recon-results/<target>/vulns.md` (+ `vulns.json`, + per-port `vulns.md`)
and streams KEV/HIGH hits live. `./roo report <target>` folds the results into
the report's "Known vulnerabilities & exploits" section.

### 3. Triage — read the buckets, don't trust them blindly

`roo vulns` ranks each CVE into a bucket and records *why* (CVSS, EPSS, KEV, PoC):

- **CRITICAL-KEV** — in CISA's Known-Exploited catalog. Top priority; real-world abuse.
- **HIGH** — severe (CVSS ≥ 7 or EPSS ≥ 0.5) **and** a public PoC exists. Strong lead.
- **MEDIUM** — severe, high EPSS, *or* has a PoC. Worth a look.
- **LOW** — everything else (shown only with `--min-bucket LOW`).

Then apply judgment the tool can't:

- **Distro backports.** Services packaged by a distro (`nginx 1.18.0 (Ubuntu)`,
  `OpenSSH 8.9p1 Ubuntu 3ubuntu0.15`) are flagged `uncertain (distro backport …)`.
  The upstream version may match a CVE while the distro silently patched it — confirm
  against the Ubuntu USN / Debian security tracker before treating it as live.
- **Read the PoC before trusting it.** A GitHub "PoC" may be a stub, a scanner, or
  malware. For Exploit-DB, fetch the actual exploit from the printed `exploit-db.com`
  URL and read it. Match the PoC's assumptions (exact version, config, auth) to the box.
- **Map to what recon saw.** A CVE needing a feature/endpoint you haven't observed is
  lower-priority than one matching an exposed surface.

### 4. Research freely — the structured lookup is the floor, not the ceiling

`roo vulns` covers the indexable sources. **You are explicitly empowered to run any
freeform lookup you judge useful** to confirm exploitability and find a working path —
don't stop at the tool's output. Reach for **Exa** (if the Exa MCP is available this
session — prefer it for technical recall) and **`WebFetch` / `WebSearch`** liberally,
and follow threads wherever they lead. Some of the many things worth chasing:

- **Confirm or kill a CVE in *this* context** — read the advisory, the NVD references,
  the commit/patch diff, the GitHub issue. Does it need an auth level, config flag,
  module, or endpoint this box actually has?
- **Resolve the distro-backport question directly** — `WebFetch` the Ubuntu USN /
  Debian DSA / RHSA page for the package and version to see if the fix was backported
  (turns an `uncertain` into a yes/no).
- **Find/vet PoCs the index missed** — exploit writeups, blog posts, conference demos,
  newer GitHub repos; read the code before trusting it.
- **Custom / uncommon apps NVD won't have** (e.g. a bespoke in-house web app) —
  search the product name + "vulnerability/exploit/CVE", GitHub for its source,
  default-credential lists, and known-CVE plugins/themes/libraries it ships. The vuln
  is often in *its* code or a dependency, not a CVE database — pair this with source
  review and the **dirbust** skill.
- **CTF/lab context** — for a known box, search for the technology stack and intended
  vuln class (don't fetch spoiler walkthroughs unless the operator asks).
- **Newer-than-cutoff intel** — your training has a cutoff; web search is how you learn
  about recently-disclosed CVEs, fresh PoCs, and current exploitation status.

Fold whatever you find back into the triage and the report's
"Known vulnerabilities & exploits" section, with the source link as evidence. When a
freeform finding changes the picture (a confirmed-exploitable bug, a backport that
clears a CVE), say so explicitly in your summary to the operator.

## What gets written

- `recon-results/<target>/vulns.md` + `vulns.json` — ranked aggregate.
- `recon-results/<target>/ports/<proto>-<port>/vulns.md` + `vulns.json` — per service.
- `.vulncache/` — 24h on-disk cache (NVD/KEV/EPSS/PoC) so re-runs stay under NVD's
  keyless rate limit; `--refresh` to force fresh.

## Tooling runs in containers

`roo vulns` (image `roorecon/vuln`) and `roo fingerprint` (image `roorecon/whatweb`)
build on first use like every other tool. Data sources are keyless — no API keys to
configure. If a source is rate-limited or down, the worker warns and continues with
the rest; re-run later (or `--refresh`) to fill gaps.
