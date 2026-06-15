---
name: sqlmap
description: Automated SQL injection detection and exploitation with sqlmap, for authorized pentesting and CTF. Use after recon/dirbust finds a parameter or endpoint that looks injectable (or a known SQLi CVE) to confirm the injection, enumerate the database, and dump tables/credentials. Triggers on "sqlmap", "SQL injection", "SQLi", "dump the database", "dump the users table", "is this parameter injectable", "extract creds via SQLi", "blind SQL injection".
---

# SQL injection with sqlmap

Automated SQLi detection and exploitation against an authorized target, driven by
`scripts/roo sqlmap` (sqlmap in a container). sqlmap confirms an injection point,
fingerprints the DBMS, and enumerates/dumps data — schema, tables, and the
credentials that usually become the next foothold.

## Scope guardrail (read first)

Authorized targets only — CTF boxes, lab ranges, or signed-scope hosts. This is
active, intrusive traffic that **writes to and reads from the target database**;
a `--dump` exfiltrates data. Confirm scope before running, and prefer the
narrowest extraction that answers the question (one table, one column) over a
blind full dump.

## When to use

After recon/dirbust/browse surfaces an injectable-looking parameter, or
vuln-research maps a SQLi CVE to the target's version (e.g. a `tid`/`id` GET
param, a search box, a JSON field). Hand off here to confirm it and extract data.
If the injection needs a logged-in session, get the auth cookie first (the
**browse** skill, or a scripted login) and pass it with `--cookie`.

## Run it

`roo sqlmap` is a thin passthrough to sqlmap — every sqlmap flag works. It is
**target-facing**, so prefix `ROO_NET=container:roorecon-vpn` for a VPN-only box,
exactly like the scanners.

Use placeholders below: `<url>` = the full URL including the suspect parameter,
`<param>` = that parameter, `<c>` = your auth cookie (drop `--cookie` for an
unauthenticated target). Run them in order — each reuses the cached injection.

```bash
# 1. Confirm an injection point (focus one parameter)
ROO_NET=container:roorecon-vpn scripts/roo sqlmap -u "<url>" --cookie "<c>" -p <param>

# 2. Enumerate: current DB/user → databases → a table's columns
ROO_NET=container:roorecon-vpn scripts/roo sqlmap -u "<url>" --cookie "<c>" -p <param> --current-db --current-user
ROO_NET=container:roorecon-vpn scripts/roo sqlmap -u "<url>" --cookie "<c>" -p <param> --dbs
ROO_NET=container:roorecon-vpn scripts/roo sqlmap -u "<url>" --cookie "<c>" -p <param> -D <db> --tables
ROO_NET=container:roorecon-vpn scripts/roo sqlmap -u "<url>" --cookie "<c>" -p <param> -D <db> -T <table> --columns

# 3. Dump — scope it tight (one table, the columns you need, one row if you can)
ROO_NET=container:roorecon-vpn scripts/roo sqlmap -u "<url>" --cookie "<c>" -p <param> \
  -D <db> -T users -C username,password --where "username='<target-user>'" --dump
```

**One sqlmap per target at a time.** Concurrent runs share the same `--output-dir`
session database → corruption, blank dumps, and skewed timing on blind injections.
Let one finish (or stop it) before starting another against the same host.

`roo` injects two defaults you can override:
- **`--batch`** — non-interactive (takes sqlmap's default answer to every prompt).
  Always on unless you pass `--batch` yourself; a container has no TTY to answer
  prompts, so without it sqlmap would hang.
- **`--output-dir recon-results/sqlmap`** — session + dumps persist on the host
  (under `/work`), nested by target host. This **caches the confirmed injection
  point**, so follow-up enumeration runs skip re-detection and go straight to
  extraction. Loot lands in `recon-results/sqlmap/<host>/`.

## Driving it well

- **Point at the right parameter.** Give the full URL with the param present and
  `-p <param>` to focus sqlmap (faster, quieter than testing every param). For
  POST/JSON, use `--data '<body>'`; for a saved request, `-r request.txt` — the
  file **must live under the current directory** (only cwd is mounted into the
  container as `/work`; a path elsewhere is invisible, and on Windows/Git-Bash an
  absolute `/...` arg gets MSYS-mangled — prefix `MSYS_NO_PATHCONV=1` if you must
  pass one).
- **Anti-CSRF tokens.** If the app guards the form with a per-request token
  (a hidden `__csrf`/`authenticity_token`, etc.), plain sqlmap requests get
  rejected — point it at the token with `--csrf-token=<field> --csrf-url=<url>` so
  it refreshes one per request.
- **Start narrow, widen on miss.** Default `--level 1 --risk 1` finds most CTF
  injections. If you have strong evidence it's injectable but sqlmap misses, raise
  `--level 3` (tests more places: headers, cookies) and `--risk 2`; for a known
  CVE you can force the class with `--technique=T` (time-based) or `B` (boolean).
- **Already confirmed it's blind time-based?** (e.g. a `SLEEP()` PoC.) Pass
  `--technique=T --dbms=mysql` to skip the other probes and go straight to it.
- **Authentication.** `--cookie`, `--headers="Authorization: Bearer …"`, or
  `--auth-type basic --auth-cred user:pass`. A redirect to a login page in the
  output means the session expired — refresh the cookie.
- **Enumerate before dumping.** `--current-db`/`--dbs` → `-D db --tables` →
  `-D db -T table --columns` → targeted `--dump` of just the columns you need
  (e.g. `-C Username,Password`). A blind full `--dump` over a slow time-based
  injection can take a very long time.
- **CTF-friendly:** `--threads 10` speeds blind extraction (bounded by the box);
  `--flush-session` discards cached state to retest from scratch; `-v3` shows the
  actual payloads if you need to understand what it's sending.

## Blind injection is slow — scope it, and watch it right

A blind injection (time-based especially) extracts roughly **one character per
several requests**, and time-based adds a fixed delay (`--time-sec`, default 5s)
to *every* request. A full table dump can run for hours. Don't fire one blindly:

- **Estimate before you commit.** Cost ≈ (chars to extract) × (requests/char) ×
  `--time-sec`. Dumping three 60-char bcrypt hashes time-based is an hour-plus;
  one targeted hash is minutes.
- **Scope hard.** `-T <table> -C <col> --where "user='<x>'"` beats `--dump` of a
  whole table. Pull the one row/column that unblocks you, not everything.
- **Tune the channel.** Prefer a faster technique if one exists — sqlmap will use
  UNION/error/boolean over time-based automatically; only force `--technique=T`
  when that's all that works. Lower `--time-sec 2` and raise `--threads` to speed
  blind extraction (at some reliability cost on a noisy link).
- **Consider a non-SQLi shortcut.** If you already hold an app session, an
  authenticated API/admin page may hand you the same data in one request — far
  faster than blind extraction. Reach for SQLi when there's no such path (e.g. the
  field you want, like a password hash, isn't exposed in the UI/API).
- **Watch the live log, never `| tail`.** sqlmap streams progress to
  `recon-results/sqlmap/<host>/log` as it runs — read that for live status.
  Piping the command through `| tail` buffers until the process exits, so a
  long run looks frozen when it's fine.
- **Mind the session clock.** A long run can outlive your auth cookie/token; when
  it expires every request redirects to login → all bits read false → a silent
  blank dump. For long extractions, scope short or refresh auth first.
- **Stopping a run.** sqlmap runs as a named container `roorecon-sqlmap-<pid>`.
  Stopping the host task alone leaves it running (detached) — kill it with
  `docker rm -f roorecon-sqlmap-*` (the **teardown** skill sweeps these too).

## Handing off the loot

- **Hashes** (e.g. ZoneMinder/WordPress/Joomla password columns) → the **hashcat**
  skill: identify the type → mode → wordlist→rules→mask.
- **Plaintext creds** → try them against other services on the box (SSH 22, the
  app's admin panel, SMB) — credential reuse is the common pivot. On a DC, hand
  to the **ad** skill.
- Note every dumped username/host as a pivot candidate, same as recon.

## Notes for the operator

- Exploitation, not just enumeration — this confirms and extracts. Keep the
  operator in the loop on what you're dumping and why; prefer targeted extraction.
- Tools run only in containers (no host fallback). First run builds the sqlmap
  image (clones sqlmap). Surface build/Docker errors; never fall back to a host
  binary.
- Target-facing: always prefix `ROO_NET=container:roorecon-vpn` for an
  internal/VPN-only target, and add discovered vhosts to `./hosts` so sqlmap
  resolves them (it's mounted into the container). A connection refused/timeout is
  **not** a clean "not injectable" result — suspect a missing `ROO_NET`, a down
  tunnel, or an unresolved host first.
