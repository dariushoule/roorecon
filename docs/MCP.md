# MCP setup

RooRecon *integrates* MCP for companion browser control — scanning and reporting
run through `./roo` and need no MCP. Two further MCP servers are
**recommended (optional)** because they sharpen the agent's advice rather than
add a tool: see "Recommended knowledge MCPs" below.

## Recommended knowledge MCPs (optional)

Enumeration and fingerprinting are far more effective when the agent can pull
current facts instead of relying on training memory. Two add-ons help a lot:

- **[Context7](https://github.com/upstash/context7)** — fetches up-to-date docs
  for tools/services/frameworks (default creds, version-specific behavior,
  known-good flags). Keyless.
- **[Exa](https://github.com/exa-labs/exa-mcp-server)** — live web search for
  advisories, version quirks, and technique write-ups. Ships in this repo's
  `.mcp.json` alongside Playwright.

Neither is required; without them the agent falls back to its own knowledge.
Context7 is configured in your harness/Codex config (not auto-loaded from this
repo), the same way as the Playwright server below; Exa is wired into `.mcp.json`
directly.

## What the MCP does

`./roo browser [url]` launches a host browser with a persistent profile,
VPN SOCKS routing, and a local CDP endpoint at `http://127.0.0.1:9222`.

The Playwright MCP attaches to that CDP endpoint so an agent can inspect and
drive the same browser session as the operator.

## Important harness rule

The repo can provide MCP configuration, but the harness must load it. If browser
or Playwright tools are not visible to the agent, the agent cannot drive the
browser yet. In that case, tell the operator MCP is not enabled and use CLI-based
enumeration until the harness exposes browser tools.

Do not claim to have browser control just because `.mcp.json` exists.

## Project MCP file

This repo includes `.mcp.json` with `playwright` and `exa` servers.

## Codex CLI

Codex MCP servers are normally configured in the user's Codex config, not
auto-loaded from this repo's `.mcp.json`. Install the RooRecon browser MCP with:

```sh
codex mcp add roorecon-playwright -- npx -y @playwright/mcp@latest --cdp-endpoint http://127.0.0.1:9222
```

Check it with:

```sh
codex mcp list
```

After adding the server, restart or reload the Codex session so the new MCP tools
are available.

## Runtime checklist

Before asking the agent to browse:

1. Start the target browser:

   ```sh
   ./roo browser http://<target>/
   ```

2. Confirm the harness has loaded the Playwright MCP.
3. Confirm browser or Playwright tools are visible to the agent.

If those tools are absent, the agent should say so and should not attempt
browser-only actions.
