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
| 2026-06-21 | Prior-session notes can mislabel an **inference** as a **fact** ("X is missing/closed") that was never actually tested; the agent then built on it for multiple sessions. Cheaply re-verify load-bearing claims before designing around them (one probe settled a long-standing assumption). | general doctrine note (CLAUDE.md / retro) if it recurs | 1 |
| 2026-06-21 | On targets with **multiple AWS endpoints** (IAM-free backend + enforcing gateway), conflating them wrecks the mental model — name the exact host:port in every note. (Partly captured in the new cloud skill; logged to confirm it generalizes.) | cloud skill footgun (already noted) / recon | 1 |

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
| 2026-06-21 | **cloud** (new skill + `service-abuse` runbook): the AWS-emulator genre (SSRF→IMDS→IAM-free-backend-vs-enforcing-gateway→service-abuse) + permission-oracle enumeration, AKID-only-auth test, image-delivery & native-image-dead-feature footguns. | Whole methodology was hand-rolled with no skill home; recon now hands off on an AWS-shaped endpoint. |
| 2026-06-21 | **roo aws** (new subcommand + `docker/aws`): containerized AWS CLI passthrough, tunnel-aware, `./hosts` mounted, creds via `$ROO_AWS_ENV`/`AWS_*`, endpoint via `$ROO_AWS_ENDPOINT`. | Hand-built mid-engagement to drive permission-oracle enumeration of an AWS-compatible mock. |
| 2026-06-21 | **vuln-research**: "reproduce locally" technique — pull the published image / clone the exact version tag, run it locally, read `docker logs`/source for suppressed errors. | Pulling the OSS target's published image + reading its logs turned a many-turn opaque-500 hunt into a one-line root cause. |
