---
name: bloodhound
description: Stand up BloodHound Community Edition locally and load AD collection data so the operator can see the attack graph. Use to ingest an existing SharpHound/rusthound/nxc collection zip (or collect one given domain creds) and open BloodHound in the browser to explore paths to Domain Admin. Triggers on "bloodhound", "open bloodhound", "visualize the domain/AD", "graph the domain", "show me the attack paths", "load this collection", "ingest the zip", "path to DA in a graph".
---

Base directory for this skill: `.claude/skills/bloodhound`

# BloodHound CE — stand up, ingest, view

Automates the config-heavy part of BloodHound: bring up the local CE stack, load a
collection, and open the graph for the operator. The tedium (random admin
password, the multi-step upload API) is handled by `./roo bloodhound`.

This is **analysis, not attack.** BloodHound CE is a *local* platform — it ingests
static collection files and renders them; it never touches the target or the VPN.
Collection (the part that talks to the DC) is the **ad** skill's job; this skill is
ingest + view. The consumer is the **human** (you look at the graph); the agent's
role is to automate setup and, if asked, drive the UI via the **browse** skill.

## The verb

```bash
./roo bloodhound up              # start the stack (first run pulls ~2 GB), seed a known admin
./roo bloodhound ingest <zip>    # load a collection over the REST API
./roo bloodhound open            # open the graph in the host browser
./roo bloodhound view <zip>      # one-shot: up + ingest + open
./roo bloodhound status          # is it up? prints URL + login
./roo bloodhound down [--wipe]   # stop (──wipe also drops the neo4j/postgres data)
```

UI at `http://127.0.0.1:8080`, login `admin` / `BloodHoundRoo!2026` (override with
`$BHE_ADMIN_USER` / `$BHE_ADMIN_PASS`). Data persists across `down`/`up` until
`--wipe`. It's a host-local stack on the docker host, **not** in the VPN namespace.

## Workflow

1. **Get a collection.** Two sources:
   - **Collect now** — `./roo shell bhcollect <dc-ip> <user> <pass>` drops a
     CE zip in the cwd. It drives rusthound-ce's Kerberos/GSSAPI path, which
     **seals LDAP over 389**, so it works even on signing-enforced / LDAPS-resetting
     DCs that defeat the python collectors (`bloodhound-ce-python`,
     `nxc --bloodhound`). bhcollect auto-discovers the domain/DC and handles the
     krb5/clock setup. (Soft DCs: `bloodhound-ce-python` works too.)
   - **Bring a zip** — a SharpHound/rusthound/AzureHound or `nxc --bloodhound` zip
     already on disk (e.g. SharpHound from a Windows foothold). Just ingest it.
2. **View it.** `./roo bloodhound view <zip>` — brings the stack up, ingests,
   and opens the browser. Or run the steps separately.
3. **Explore (operator-driven).** Mark tier-zero/owned principals, run the
   prebuilt "Shortest paths to Domain Admins" queries, and follow the graph. If you
   want the agent to pull a specific path or screenshot it, that's the **browse**
   skill driving the same browser over CDP (Playwright MCP) — ask for it.

## Notes

- **First `up` is slow** (~2 GB of postgres + neo4j + bloodhound images) and neo4j
  wants a couple GB of RAM — it's opt-in, only stand it up when you want the graph.
- **Ingest is async** — BloodHound processes + analyses server-side after upload;
  give it a few seconds before the paths populate.
- BloodHound CE consumes **CE-format** collections (SharpHound CE / rusthound-ce /
  `bloodhound-ce-python` / `nxc --bloodhound`). Legacy BH-4 JSON won't ingest.
- Tear down with `./roo bloodhound down` when done; `teardown` leaves it
  alone (it holds loot you may still want) unless you pass through to it.
