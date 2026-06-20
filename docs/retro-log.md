# Retro log — the learning loop's memory

Cross-engagement signals from the **retro** skill. Generic only (no box specifics —
those stay in `recon-results/`). The retro skill reads this back at the start of each
run to (a) check whether prior fixes held and (b) tell a recurring pattern from a
one-off fluke before promoting it to a skill edit.

Two sections. Move an item from **Deferred** to **Resolved** when a change lands and a
later engagement confirms it held.

## Deferred / watching (N=1 — needs a second sighting before it earns an edit)

| Date | Signal | Where it'd land if it recurs | Seen |
|------|--------|------------------------------|------|
| 2026-06-20 | Pickle/cloudpickle RCE payloads must match the **target's Python minor version** (3.12-built model → "code expected at most 16 arguments, got 18" against a 3.10 target). No natural skill home yet (vuln-research is lookup-only). | runbook under vuln-research, or a deserialization-exploit note, if it recurs | 1 |
| 2026-06-20 | `roo shell` is ephemeral per invocation — a cookie jar / state written in one call is gone the next. Chain multi-step authed `curl` flows in a single `roo shell bash -c '...'`. | CLAUDE.md "roo shell" note or recon ad-hoc-client note | 1 |
| 2026-06-20 | Playwright file-chooser modals (from clicking upload widgets) wedge the tab and block `browser_evaluate`/`snapshot`. Read app JS via `evaluate`/`fetch` instead of clicking uploaders. | browse skill footgun note | 1 |

## Resolved (a retro edit that a later engagement confirmed)

| Date | Change | Confirmed by |
|------|--------|--------------|
| _seed_ | _no entries yet_ | — |

## Applied this retro (awaiting a later engagement to confirm)

| Date | Change | Evidence it fixes |
|------|--------|-------------------|
| 2026-06-20 | **catch**: `roo catch enter` verb (sends Ctrl-D into the target PTY) + `$ROO_CATCH_PORT` for send/capture; SKILL.md documents the local-vs-remote pwncat prompt and multi-catcher footgun. | ~3 `send` commands bounced as `unknown command`; `send 6666 cmd` swallowed the port; stray catcher made send ambiguous. |
| 2026-06-20 | **recon**: theme the vhost/subdomain wordlist on the known tech stack when generic top-N comes back empty. | Default top-5000 → 0 hits; themed MLOps list instantly found `models.<box>`. Operator had to redirect. |
| 2026-06-20 | **roo pyrun**: tunnel-aware, version-pinned `python:<ver>-slim` exploit runner (deps cached, `./hosts` mounted). | Hand-rolled a per-box `.ps1`; `--py` makes the target-Python match (pickled code objects) a first-class knob. |
| 2026-06-20 | **convention** (CLAUDE.md): engagement scratch organized by target → `recon-results/<target>/exploit/`; `.roo/` stays runtime-only; techniques → runbooks. | Exploit files had landed inconsistently (`exploit/` root + wordlist under `recon-results/`). |
