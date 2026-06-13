# MCP setup

RooRecon uses MCP only for companion browser control. Scanning and reporting run
through `scripts/roo` and do not need MCP.

## What the MCP does

`scripts/roo browser [url]` launches a host browser with a persistent profile,
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

This repo includes `.mcp.json` with a `playwright` server.

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
   scripts/roo browser http://<target>/
   ```

2. Confirm the harness has loaded the Playwright MCP.
3. Confirm browser or Playwright tools are visible to the agent.

If those tools are absent, the agent should say so and should not attempt
browser-only actions.
