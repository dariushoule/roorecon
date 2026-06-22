---
name: wordlists
description: Pick and fetch the right SecLists wordlist on demand for content discovery, fuzzing, subdomain/vhost enum, parameter mining, default-cred spraying, and payload injection (LFI/SSRF/SQLi/XSS), for authorized pentesting and CTF. Use when a fuzz/brute job needs a list the baked tool images don't already carry, or when choosing which list fits the task. Triggers on "which wordlist", "find a wordlist", "seclists", "content discovery list", "api wordlist", "parameter wordlist", "fuzz list", "pull down a wordlist", "bigger wordlist".
---

# Wordlists — browse + fetch SecLists on demand

The gobuster and ffuf images bake a *fast-path* subset of SecLists (a few
Web-Content + DNS lists). Everything else in the ~3000-file SecLists repo is
**pulled on demand** through `roo wordlist`, cached under `.roo/wordlists/`
(git-ignored), and fed to any tool. Don't rebake an image to add a list.

## Workflow

```bash
roo wordlist search <kw>     # find lists by filename: api, lfi, subdomains, params, xss…
roo wordlist get <repo-path> # cache one (prints host path + how to feed it to tools)
```

Then feed it:
- **gobuster (`dirbust`/`vhost`/`dns`):** `--wordlist seclists:<repo-path>` — fetches + mounts automatically.
- **`roo run ffuf -w`:** `/work/.roo/wordlists/<flattened-name>` (cwd mounts at `/work`; `get` prints the exact path).
- **host hashcat:** `roo wordlist <alias>` (rockyou, top-1m, …) stays the password-list fast path.

`search` ranks `Discovery/*` first and is keyword-substring over the cached file
index (delete `.roo/wordlists/.seclists-tree.json` to refresh it).

## Which family for which task

| Task | SecLists family / list |
|------|------------------------|
| Web content discovery (dirs/files) | `Discovery/Web-Content/` — `raft-*-words/-directories/-files`, `directory-list-2.3-*` |
| API route enumeration | `Discovery/Web-Content/api/` — `api-endpoints.txt`, `common-api-endpoints-*` |
| Subdomains (external DNS) | `Discovery/DNS/` — `subdomains-top1million-*`, `combined_subdomains.txt` |
| Vhosts (Host-header, internal) | `Discovery/DNS/` shortlists, or content lists if names are app-specific |
| Parameter mining | `Discovery/Web-Content/burp-parameter-names.txt` |
| Default / service creds | `Passwords/Default-Credentials/`, `Usernames/` |
| Password cracking | `Passwords/` (use the `roo wordlist <alias>` aliases) |
| Injection payloads | `Fuzzing/` — `LFI/`, `SQLi/`, `XSS/`, `SSRF`/`command-injection` lists |

## Judgment

- **Start small, widen on a miss.** `common.txt` → `raft-medium-words` →
  `raft-large`/`directory-list-2.3-big`. A huge list through a slow path (e.g. an
  SSRF-wrapped fuzz) is minutes of noise; only escalate when the small list is dry.
- **Match the list to the *response surface*, not the vibe.** Fuzzing an SSRF
  `url=` param for internal routes → a clean path-token list (`raft-*-words`), not
  `common.txt` (its `Program Files`/`Documents and Settings` entries contain
  spaces that corrupt the request and produce false positives).
- **Lowercase variants** (`*-lowercase.txt`) when the target is case-insensitive —
  half the requests, same coverage.
- **Cache is shared across the engagement** — fetch once, reuse everywhere; the
  list survives until teardown wipes `.roo/`.
