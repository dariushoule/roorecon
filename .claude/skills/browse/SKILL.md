---
name: browse
description: Drive a real web browser as a companion to the operator during authorized pentesting/CTF — a host Chrome routed through the VPN that both the human and the agent can control over CDP (Playwright MCP). Use to explore a web app interactively, reproduce/poke at flows, enumerate authenticated areas after the operator logs in, capture network/console, and turn what's seen into recon/exploit leads. Triggers on "open a browser", "browse to", "drive the browser", "poke around the web app", "click through the app", "log in and explore", "look at this page in a browser", "use the browser".
---

# Companion browsing (human + agent share one browser)

A native host browser, routed through the VPN, that you and the operator drive
*together*. The operator browses normally; you tap in over CDP (the Playwright
MCP) to look around, reproduce a flow, or enumerate when asked. Launched by
`scripts/roo browser`; you attach to the **same** browser instance.

## Scope guardrail

Authorized targets only — CTF boxes, lab ranges, signed-scope hosts. A browser
*acts on* the app (submits forms, triggers requests), which is more than passive
recon. Stick to navigation, reading, and enumeration unless the operator asks for
a specific state-changing action. The operator owns destructive/irreversible steps
(deleting data, sending mail, paying, etc.) — confirm before any of those.

## Setup (operator does this once)

1. **Tunnel up:** `scripts/roo vpn up` (the box must be reachable).
2. **Launch:** `scripts/roo browser http://<target>/` — starts the host browser
   with a persistent, git-ignored profile (`.roo/browser-profile`), routed through
   the VPN SOCKS proxy (auto-started; remote DNS, so `box.htb` resolves via
   `./hosts`), with a CDP port (default `9222`) open for you.
3. **Enable the MCP:** the project `.mcp.json` defines a `playwright` server that
   attaches to `http://127.0.0.1:9222`. Approve/enable it in Claude Code (needs
   Node/`npx` on the host). Once enabled you get `browser_*` tools.

If the `browser_*` tools aren't present, the MCP isn't enabled yet — tell the
operator to enable the `playwright` server and (if needed) restart Claude Code.

## How you drive (Playwright MCP)

You attach to the operator's live browser over CDP — same cookies, same logged-in
session. Typical tools:

- `browser_snapshot` — the accessibility tree (your primary "what's on the page";
  prefer it over screenshots for reasoning — it's text and has stable refs).
- `browser_navigate`, `browser_click`, `browser_type`, `browser_select_option`,
  `browser_press_key` — interaction.
- `browser_evaluate` — run JS in the page (read DOM, pull `<meta>`/version strings,
  inspect JS globals, dump `localStorage`).
- `browser_take_screenshot` — when layout/visual matters or to show the operator.
- `browser_console_messages`, `browser_network_requests` — capture console errors
  and the request log (great for finding API endpoints, tokens, hidden params).
- `browser_tab_new`, `browser_tab_list`, `browser_tab_select` — manage tabs.

## Shared-session etiquette (don't hijack the operator's tab)

The operator is a person actively using this browser. Be a considerate co-driver:

- **Open your own tab** (`browser_tab_new`) to poke around. Don't navigate the tab
  the operator is on unless they tell you to "drive" or "take this tab".
- **Say what you're about to do** before a multi-step action, and **report what you
  found**, with the evidence (URL, snapshot excerpt, request).
- **Hand control back** — leave the browser in a sane state; don't close the
  operator's tabs.
- **Never enter credentials or solve CAPTCHAs for the operator.** Let *them* log in
  / clear MFA; then you enumerate the authenticated app (you share their session).

## What this is great for

- **Authenticated enumeration:** operator logs in, you map the dashboard, every
  authenticated route, forms, roles, and hidden admin/API endpoints — exactly the
  foothold path for apps like SmartHire.
- **Endpoint/parameter discovery:** read `browser_network_requests` to harvest API
  routes, request shapes, tokens, and parameters the HTML doesn't reveal.
- **Reproducing a flow** the operator describes, then inspecting the requests it
  makes (e.g. an upload, a search, a state change → candidate IDOR/SSRF/injection).
- **Fingerprint confirmation:** `browser_evaluate` for `<meta name=generator>`, JS
  framework globals, asset `?ver=` — feed sharper versions into `roo vulns`.

## Feed findings back into the toolkit

Browsing is reconnaissance with a real client — loop the results into the rest:

- New paths/endpoints → `scripts/roo dirbust <url>` (the **dirbust** skill) to brute
  around them; note them for manual testing.
- New hostnames (redirects, links, JS config) → add to `./hosts`, then
  `scripts/roo vhost <ip> <domain>` and re-buckaroo.
- Confirmed product/version → `scripts/roo vulns` (the **vuln-research** skill).
- Interesting requests/params → record them in the engagement notes / report.

## Networking notes

- Browser traffic egresses through the **VPN tunnel** via the SOCKS proxy (remote
  DNS). The **CDP** channel (`127.0.0.1:9222`) is **local** — your control plane,
  not tunneled, not exposed to the target.
- `scripts/roo browser --no-proxy` browses direct (off-VPN) — only for non-tunnel
  targets; it's flagged loudly because it bypasses the engagement path.
- The profile persists between runs (logins/cookies stick), so the operator doesn't
  re-auth every session. It's under `.roo/` (git-ignored).
