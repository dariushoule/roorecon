# Credits

RooRecon is a thin orchestration layer over a lot of excellent open-source work.
The skills encode methodology; these projects do the actual magic. Thank you to
their authors and maintainers.

- **Wordlists** — [SecLists](https://github.com/danielmiessler/SecLists) (Daniel
  Miessler, Jason Haddix & contributors) — DNS/content lists baked into the
  gobuster image, and password lists (incl. rockyou) via `roo wordlist`.
- **Tooling** — [nmap](https://nmap.org),
  [gobuster](https://github.com/OJ/gobuster),
  [WhatWeb](https://github.com/urbanadventurer/WhatWeb),
  [OpenVPN](https://openvpn.net) — each in its own minimal container — with
  [microsocks](https://github.com/rofl0r/microsocks) (rofl0r) powering `roo proxy`
  and [libfaketime](https://github.com/wolfcw/libfaketime) (wolfcw) powering
  `clocksync`.
- **Active Directory** — [NetExec](https://github.com/Pennyw0rth/NetExec),
  [Impacket](https://github.com/fortra/impacket) (Fortra),
  [bloodyAD](https://github.com/CravateRouge/bloodyAD),
  [Certipy](https://github.com/ly4k/Certipy),
  [evil-winrm](https://github.com/Hackplayers/evil-winrm) /
  [evil-winrm-py](https://github.com/adityatelange/evil-winrm-py),
  [Responder](https://github.com/lgandx/Responder) (Laurent Gaffié / lgandx), and
  [RustHound-CE](https://github.com/g0h4n/RustHound-CE) feeding
  [BloodHound CE](https://github.com/SpecterOps/BloodHound) (SpecterOps).
- **Windows tooling** — staged with `roo tools` via
  [Forge](https://forgenet.pages.dev)
  ([ForgeNet21AR/forge](https://github.com/ForgeNet21AR/forge), by
  [Shadow21AR](https://github.com/Shadow21AR) &
  [azomaxx](https://github.com/azomaxx)), which builds and serves the prebuilt
  .NET offensive ecosystem — [GhostPack](https://github.com/GhostPack) (Rubeus,
  Seatbelt, Certify, SharpUp, SharpDPAPI, SafetyKatz, …),
  [SpecterOps](https://github.com/SpecterOps) (SharpHound), and many more (Inveigh,
  Snaffler, the *Potato suite, Whisker, PassTheCert, ysoserial.net, …), each by its
  respective author.
- **Password cracking** — [hashcat](https://hashcat.net) (Jens "atom" Steube & the
  hashcat team), run on the host GPU via `roo hashcat`.
- **Memory forensics** — [Volatility 3](https://github.com/volatilityfoundation/volatility3)
  (The Volatility Foundation), run on a local image via `roo vol`.
- **Browser control** — [Playwright MCP](https://github.com/microsoft/playwright-mcp)
  (Microsoft) drives the host browser over CDP for `roo browser`.
- **Vulnerability & exploit data** (keyless) — [NVD](https://nvd.nist.gov) (NIST),
  [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
  [EPSS](https://www.first.org/epss) (FIRST),
  [Exploit-DB](https://www.exploit-db.com) (OffSec),
  [PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub), and
  [Metasploit Framework](https://github.com/rapid7/metasploit-framework) module
  metadata (Rapid7 & contributors).
