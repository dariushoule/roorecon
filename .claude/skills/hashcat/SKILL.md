---
name: hashcat
description: Offline password-hash cracking with hashcat on the host GPU, for authorized pentesting and CTF. Use to identify an unknown hash's type, pick the right hashcat mode, fetch a wordlist, and run a sensible wordlist→rules→mask attack ladder. Triggers on "help me crack this hash", "crack this hash", "crack this NTLM/NetNTLMv2/kerberoast/AS-REP hash", "what hashcat mode is this", "identify this hash", "hashcat", "crack the roast".
---

Base directory for this skill: `.claude/skills/hashcat`

# hashcat — offline hash cracking (host GPU)

Methodology for turning a captured hash into a plaintext. Cracking is **offline
and host-side** — it never touches the target or the VPN — so unlike every other
tool in this repo, `roo hashcat` runs the real hashcat binary on the host (it
wants the GPU; a CPU container would be strictly slower). It bootstraps itself on
first use (apt / brew / the official Windows portable build). See ARCHITECTURE.md:
hashcat and the browser are the two deliberate host-tool exceptions.

## Scope guardrail (read first)

Authorized targets only — CTF boxes, lab ranges, signed-scope hosts. Crack only
hashes obtained in scope. Cracking itself is non-destructive and offline; the
*decision* to crack a captured credential is an operator-approved step (the ad
skill hands roasts here once they're on disk).

## Tools

```bash
roo hashcat [args...]        # the host hashcat, GPU and all — args pass straight through
roo wordlist [name]          # fetch a SecLists password list → prints its local path (default rockyou)
roo wordlist --list          # known aliases (rockyou, darkweb2017-top10000, xato-1m, top-1m)
```

- First `roo hashcat` run downloads + caches hashcat under `.roo/hashcat/`
  (git-ignored). `$ROO_HASHCAT` overrides the binary.
- `roo wordlist` caches under `.roo/wordlists/` and unpacks `.tar.gz` lists; pass
  an alias or any SecLists *Passwords*-relative path
  (e.g. `Leaked-Databases/rockyou.txt.tar.gz`). It prints **only** the path on
  stdout, so capture it:
  ```bash
  WL=$(scripts/roo wordlist rockyou)             # PowerShell: $WL = scripts\roo.cmd wordlist rockyou
  scripts/roo hashcat -m 1000 ntlm.txt "$WL"
  ```
- **Bundled rules** live in the hashcat dir and resolve as `rules/<name>.rule`
  (hashcat runs from its own folder). v7 ships `best66.rule` (the old `best64`),
  `rockyou-30000.rule`, `dive.rule`, `d3ad0ne.rule`, `leetspeak.rule`, …

## Workflow

### 0. Before you crack: spray, and sanity-check the path

- **Spray every credential you already hold at the target account first.** Reuse is
  free and instant; cracking is neither. The instant you hold any password, spray it
  (and re-spray every new one). Never spend GPU time on a hash whose plaintext a free
  spray would hand you. (See the **ad** skill's "spray before you crack".)
- **On CTF/HTB, treat rockyou(+`best66`) as the verdict on whether this is the path.**
  Intended creds almost always fall to rockyou plus a standard rule. If a roast
  survives that, **suspect you're on the wrong path** (a fallback, not the planted
  route) rather than escalating to giant wordlists/masks for hours. Step back and
  re-examine the attack graph before burning the GPU harder.

### 1. Identify the hash → pick the mode (`-m`)

The mode is everything; the wrong `-m` cracks nothing. There is no `hashid`/
`name-that-hash` in the kit, so identify by **format + provenance**, then confirm
the exact format against the authoritative list:

**Hashcat example-hash reference: https://hashcat.net/wiki/doku.php?id=example_hashes**
(every mode with a sample — match your hash's shape to a sample to lock the `-m`).

Most hashes you'll meet here carry a `$tag$` that names them; map the tag, then
verify against the wiki:

| Looks like | Mode `-m` | Notes |
|---|---|---|
| `$krb5tgs$23$…` (Kerberoast, RC4) | 13100 | the `23` is the etype |
| `$krb5tgs$17$…` / `$krb5tgs$18$…` (Kerberoast, AES128/256) | 19600 / 19700 | hardened DCs roast as **18** → 19700 |
| `$krb5asrep$23$…` (AS-REP, RC4) | 18200 | from `GetNPUsers` |
| `$krb5asrep$18$…` (AS-REP, AES256) | 19900 | |
| `$krb5pa$…` (AS-REQ pre-auth) | 7500 | |
| `user::DOMAIN:…:…:…` (NetNTLMv2) | 5600 | Responder/relay capture |
| `user::DOMAIN:…` (NetNTLMv1) | 5500 | |
| 32 hex, from `secretsdump`/SAM (`rid:LM:NT:::`) | 1000 | the **NT** half — NTLM |
| `$DCC2$10240#user#…` (domain cached) | 2100 | mscash2 |
| `$2a$/$2b$…` bcrypt · `$6$…` sha512crypt · `$1$…` md5crypt | 3200 · 1800 · 500 | `/etc/shadow`, web apps |
| 32 hex / 40 hex / 64 hex, no context | 0 / 100 / 1400 | raw MD5/SHA1/SHA256 — **see disambiguation** |

**Disambiguation (ambiguous shapes).** A bare 32-hex string is MD5 (0), NTLM
(1000), LM (3000), or MD4 (900) — identical length, different meaning. Resolve by
*where it came from*: out of AD (secretsdump/SAM) → **NTLM 1000**; out of a web
app/db → likely **MD5 0**. When you genuinely can't tell, **say so and offer the
2–3 candidate modes** (with the example-hash link) rather than guessing — running
the wrong mode wastes the whole attack. `roo hashcat -m <mode> hash --show` against
each candidate is a cheap way to confirm format parses.

### 2. Get a wordlist

```bash
WL=$(scripts/roo wordlist)            # default: rockyou (133 MB), the right first try
```
Bigger guns when rockyou is dry: `roo wordlist xato-1m`, `roo wordlist top-1m`, or
any SecLists Passwords path. CTF passwords usually fall to **rockyou + a rule**.

### 3. Attack ladder (cheap → expensive — stop as soon as it cracks)

```bash
H=kr.txt; M=19700                                      # your hash file + mode
scripts/roo hashcat -m $M $H "$WL"                     # 1) straight wordlist
scripts/roo hashcat -m $M $H "$WL" -r rules/best66.rule        # 2) + a fast rule
scripts/roo hashcat -m $M $H "$WL" -r rules/rockyou-30000.rule # 3) + a heavier rule
scripts/roo hashcat -m $M $H -a 3 '?u?l?l?l?l?d?d?d?d?!'       # 4) targeted mask (last resort)
scripts/roo hashcat -m $M $H --show                   # read what cracked (from the potfile)
```

- `-a 0` (default) = wordlist; `-r` layers rules on it; `-a 3` = brute/mask.
- Don't jump to full brute force — it's exponential. Prefer rules and *targeted*
  masks built from what you know about the org's password policy (e.g. `Season+
  Year+!` → `?u?l?l?l?l?l?d?d?d?d?s`).

### 4. Read the result

Cracked plaintexts persist in hashcat's **potfile** (in the hashcat dir). Re-print
anytime with `roo hashcat -m <mode> <hashfile> --show`. Then **feed it back**: a
cracked password is a new credential — spray it domain-wide and loop into the ad
skill (see "spray before you crack" there).

## Footguns

- **`user:hash` files** (one cred per line with a username column) → add
  `--username` so hashcat ignores the user field.
- **Mode mismatch silently finds nothing.** If a run exhausts instantly with
  `Exhausted` and 0 recovered, re-check `-m` against the example-hash wiki before
  blaming the wordlist.
- **AES roasts (19700/19600) crack slower than RC4 (13100).** Same wordlist, more
  time — be patient or narrow the candidates; they still fall to rockyou+rules in
  CTF.
- **Speed knobs:** `-O` (optimized kernels, caps password length ~31 — fine for
  human passwords), `-w 3` (workload/heat). `--status --status-timer 10` for
  progress on a long run.
- **Potfile already has it:** if a hash was cracked before, a new run says
  `(remove --potfile-disable…)`/skips it — use `--show` to retrieve, or
  `--potfile-disable` to force a re-crack during testing.
- Wrong-named rule (`best64` on v7) → `No such file or directory`; it's
  **`best66.rule`** now. List them: `ls .roo/hashcat/hashcat-*/rules`.
