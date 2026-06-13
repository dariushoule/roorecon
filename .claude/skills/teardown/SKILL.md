---
name: teardown
description: Cleanly shut down a RooRecon engagement — close the browser, drop the SOCKS proxy and VPN tunnel, tidy runtime scratch out of the working tree, and confirm nothing is left running. Use when the operator says to clean up, shut down, tear down, wrap up, or stop everything at the end of a session. Triggers on "clean up", "shut down", "shut things down", "tear down", "wrap up", "stop everything", "we're done", "end the engagement".
---

# Teardown — clean shutdown of an engagement

Bring everything down in the right order, leave the working tree clean, and keep the
loot. This is the end-of-session counterpart to recon: it stops what's running and
tidies scratch, without throwing away results or the operator's work.

## Principles

- **Preserve the loot.** Never delete `recon-results/` (recon, vuln-research,
  fingerprints) or `.roo/browser-profile` (the operator's saved login) unless the
  operator explicitly asks for a deep clean. They're git-ignored, so they don't dirty
  the tree — leaving them costs nothing and saves a re-auth / re-scan next time.
- **Don't auto-commit code.** Make the tree *clean to report*, but commit source
  changes only when the operator asks. Commits are solo-authored — no co-author /
  generated-by trailer.
- **Idempotent and quiet.** Only stop what's actually running; a teardown must never
  error because something is already down. Skip steps that don't apply (no browser
  open → nothing to close).
- **Graceful order:** close the browser *before* dropping the tunnel, and drop the
  tunnel **last** — so nothing loses its network out from under it mid-operation.

## Sequence

1. **Close the browser** (if a `roo browser` / CDP session is up). Use the Playwright
   MCP `browser_close`. The host Chrome runs on a dedicated profile, so closing its
   last window exits that instance without touching the operator's other browsers.
2. **Tidy runtime scratch from the working tree.**
   - The Playwright MCP writes snapshots/console logs/screenshots to `.playwright-mcp/`
     in the cwd. Make sure it's git-ignored (it is, in `.gitignore`), then remove it:
     `rm -rf .playwright-mcp`.
   - `git status --short` — anything left should be intentional. Generated runtime
     dirs (`.roo/`, `recon-results/`) are git-ignored and stay.
3. **Drop the SOCKS proxy:** `scripts/roo proxy down`.
4. **Drop the VPN tunnel (last):** `scripts/roo vpn down` — now off the engagement
   network.
5. **Verify nothing is left:**
   - `docker ps --filter name=roorecon --format '{{.Names}} ({{.Status}})'` → empty.
   - `git status --short` → clean (or only intentional, operator-approved changes).

## Report back

Tell the operator, plainly, what's down and what was kept:

- Browser closed; SOCKS proxy stopped; VPN tunnel down (off the engagement network);
  no `roorecon-*` containers running.
- Working tree clean.
- **Preserved:** `recon-results/` (loot) and `.roo/browser-profile` (saved login) on
  disk, git-ignored.

If the operator asked to commit pending changes, do so (solo author, concise message)
and report the hash. If there are uncommitted source changes you did *not* commit,
list them so nothing is silently dropped.

## Optional deep clean (only if asked)

- Remove the saved browser session / generated artifacts: `rm -rf .roo/` (forces
  re-auth and regenerates proxychains/hosts next run).
- Remove engagement results: `rm -rf recon-results/<target>/` — **destructive, confirm
  first.** This is the loot; never do it on your own initiative.
