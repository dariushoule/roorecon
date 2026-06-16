# dMSA / BadSuccessor mechanics (durable — the technique, not a box)

Deep-dive runbook for the **ad** skill. Read this only when the BadSuccessor path
is live: a Server 2025 DC (build 26100) where `nxc -M badsuccessor` flags a
writable OU (`CreateChild`) plus a reachable KDS root key. The cross-cutting
judgment this relies on — the **loopback rule** (ad skill, phase 5 *Foothold &
shells*), the **Rubeus-staleness** and **short-ticket-lifetime** footguns (ad
skill, footgun cheat-sheet) — stays in the skill; this file is just the
operational detail that bites.

The KDC lets a dMSA "supersede" an account and inherit its privileges. Exploiting
it cleanly has several non-obvious gates; verify each before blaming the box:

1. **Patched vs unpatched decides the target.** *Unpatched* (pre-Aug-2025): a
   one-way link works — supersede a DA directly (only the dMSA-side attributes
   matter, no rights on the victim). *Patched* (BetterSuccessor): the KDC validates
   the link **bidirectionally**, so you must also write the victim side → you can
   only supersede an account you have **`GenericWrite`** over. So: enumerate what you
   can write *first*, and let that pick the target (often a service account that
   reaches the loot, not a DA).
2. **Create + verify the attributes** (`SharpSuccessor` on Windows, or `bloodyAD
   add badSuccessor`). Before touching Kerberos, confirm on the dMSA:
   `msDS-DelegatedMSAState = 2` and `msDS-ManagedAccountPrecededByLink → victim`
   (and on a patched DC, the victim's `msDS-SupersededManagedAccountLink/State`).
   A read as the *creator* (you may need its own ticket — the OU can deny others
   read) settles "did the write land" vs "is the KDC refusing".
3. **Pull the ticket — two steps, Windows, `/opsec`.** With a **current Rubeus
   build** (verify the banner — older builds silently no-op `/dmsa`): `tgtdeleg` →
   `asktgs /dmsa /service:krbtgt/<realm>` (the dMSA TGT) → then a **second**
   `asktgs /dmsa /service:<spn>` for each service you want (cifs/HTTP/…). The
   inherited PAC rides the `/dmsa`-minted *service* ticket — don't let Windows
   auto-derive it. Keep `/opsec` (some builds NullRef without it; the "delegated
   TGT" detour it prints is harmless).
4. **Consume it remotely, not on the target.** See the ad skill's loopback rule
   (phase 5) — on the DC the ticket is ignored. Export the service ticket and use
   it from the toolbox.
5. **Mind the ~15-min lifetime** (ad skill footgun cheat-sheet) for any large
   transfer.

If the ticket issues but every access is denied, the likely cause is loopback
(phase 5) or a stale Rubeus (footgun) — *not* a patched inheritance, until you've
ruled those out from the toolbox.

## Tooling

- **Audit:** `./roo shell nxc ldap <dc> -u U -p P -M badsuccessor` (sealed —
  works on hardened DCs; `badsuccessor.py -action search` uses ldap3 and dies where
  the DC enforces signing).
- **Create the link:** `bloodyAD add badSuccessor` (Linux, seals over 389) or
  `SharpSuccessor` on Windows.
- **Mint the ticket:** a current Rubeus build (see **wintools** for a fresh
  main/branch build — tag-tracking registries serve year-old binaries that no-op
  `/dmsa`).
- **Bridge the Windows-minted ticket into the toolbox** to consume it remotely:
  see the ad skill's phase-5 ticket-bridging snippet (`ticketConverter.py` →
  `KRB5CCNAME` → `nxc -k --use-kcache`).
