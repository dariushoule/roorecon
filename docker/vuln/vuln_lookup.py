#!/usr/bin/env python3
"""RooRecon vuln-research worker — runs INSIDE the roorecon/vuln container.

Takes service fingerprints (from a recon-results/<target>/ dir, or an ad-hoc
--product/--version) and produces a ranked list of applicable CVEs + public PoCs
using only keyless sources:

  NVD 2.0           CVE applicability (CPE-aware, server-side version matching)
  CISA KEV          known-exploited flag (top signal)
  EPSS (FIRST)      exploitation-probability score
  Exploit-DB CSV    baked index -> EDB-ID/URL per CVE
  GitHub PoC index  nomi-sec/PoC-in-GitHub per-CVE repo list
  Metasploit meta   rapid7/metasploit-framework module<->CVE map

stdlib only; every HTTP call goes through urllib. Network egress is the *default*
docker network (public internet) — never the VPN tunnel (roo runs us with
use_net=False). Output lands under /work (the mounted cwd).
"""
import argparse
import csv
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

EDB_CSV = "/opt/exploitdb/files_exploits.csv"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
POC_INDEX = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}/{cve}.json"
MSF_META = "https://raw.githubusercontent.com/rapid7/metasploit-framework/master/db/modules_metadata_base.json"
UA = "RooRecon/1.0 (authorized surface mapping; +https://github.com/)"

NVD_SPACING = 6.5          # keyless NVD: stay under ~5 req / 30s
NVD_TTL = 24 * 3600
DAILY = 24 * 3600

# product (lowercased) -> ordered (vendor, product) CPE candidates for NVD.
# nmap's own CPE vendor is often stale (e.g. nginx -> igor_sysoev), so we try the
# nmap CPE first and fall back through these; first candidate with hits wins.
CPE_ALIASES = {
    "openssh": [("openbsd", "openssh")],
    "nginx": [("f5", "nginx"), ("nginx", "nginx")],
    "apache": [("apache", "http_server")],
    "apache httpd": [("apache", "http_server")],
    "httpd": [("apache", "http_server")],
    "apache tomcat": [("apache", "tomcat")],
    "tomcat": [("apache", "tomcat")],
    "lighttpd": [("lighttpd", "lighttpd")],
    "vsftpd": [("beasts", "vsftpd")],
    "proftpd": [("proftpd", "proftpd")],
    "pure-ftpd": [("pureftpd", "pure-ftpd")],
    "mysql": [("oracle", "mysql"), ("mysql", "mysql")],
    "mariadb": [("mariadb", "mariadb")],
    "postgresql": [("postgresql", "postgresql")],
    "redis": [("redis", "redis")],
    "mongodb": [("mongodb", "mongodb")],
    "samba": [("samba", "samba")],
    "smbd": [("samba", "samba")],
    "bind": [("isc", "bind")],
    "isc bind": [("isc", "bind")],
    "exim": [("exim", "exim")],
    "postfix": [("postfix", "postfix")],
    "dovecot": [("dovecot", "dovecot")],
    "openssl": [("openssl", "openssl")],
    "php": [("php", "php")],
    "wordpress": [("wordpress", "wordpress")],
    "drupal": [("drupal", "drupal")],
    "joomla": [("joomla", "joomla")],
    "jenkins": [("jenkins", "jenkins")],
    "dropbear": [("dropbear_ssh_project", "dropbear_ssh"), ("matt_johnston", "dropbear_ssh")],
    "dropbear sshd": [("dropbear_ssh_project", "dropbear_ssh")],
}
DISTRO_RE = re.compile(r"(Ubuntu|Debian|Fedora|CentOS|Red ?Hat|RHEL|SUSE|FreeBSD|"
                       r"Raspbian|Alpine|Amazon)[\w.\- ]*", re.I)
VER_RE = re.compile(r"\d+(?:\.\d+)+[a-zA-Z0-9.\-]*")

# --- output (mirror roo's [+]/[*]/[!] look) ---------------------------------
_TTY = sys.stdout.isatty()


def _c(code, t):
    return f"\033[{code}m{t}\033[0m" if _TTY else t


def ok(m):
    print(_c("32", "[+]"), m, flush=True)


def info(m):
    print(_c("36", "[*]"), m, file=sys.stderr, flush=True)


def warn(m):
    print(_c("33", "[!]"), m, file=sys.stderr, flush=True)


# --- HTTP + cache -----------------------------------------------------------
def _get(url, tries=4):
    """GET + JSON-decode with backoff. Returns parsed JSON, or None on failure."""
    last = None
    for i in range(tries):
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=45) as r:
                return json.loads(r.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            last = e
            if e.code in (403, 429, 503):
                wait = min(60, 6 * (2 ** i))
                warn(f"HTTP {e.code} from {urllib.parse.urlsplit(url).netloc}; backoff {wait}s")
                time.sleep(wait)
                continue
            if e.code == 404:
                return None
            warn(f"HTTP {e.code} {url}")
            return None
        except Exception as e:  # noqa: BLE001 — network is best-effort
            last = e
            time.sleep(3 * (i + 1))
    warn(f"giving up on {urllib.parse.urlsplit(url).netloc}: {last}")
    return None


def _slug(s):
    return re.sub(r"[^a-z0-9]+", "_", s.lower()).strip("_")


def _cache_get(cdir, key, ttl):
    f = cdir / (key + ".json")
    if f.is_file() and (time.time() - f.stat().st_mtime) < ttl:
        try:
            return json.loads(f.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return None
    return None


def _cache_put(cdir, key, obj):
    cdir.mkdir(parents=True, exist_ok=True)
    try:
        (cdir / (key + ".json")).write_text(json.dumps(obj), encoding="utf-8")
    except Exception as e:  # noqa: BLE001
        warn(f"cache write failed ({key}): {e}")


class _Pacer:
    """Enforce a minimum spacing between successive (uncached) NVD calls."""

    def __init__(self, spacing):
        self.spacing = spacing
        self.last = 0.0

    def wait(self):
        dt = time.time() - self.last
        if dt < self.spacing:
            time.sleep(self.spacing - dt)
        self.last = time.time()


# --- version handling -------------------------------------------------------
def _ver_key(v):
    out = []
    for p in re.findall(r"\d+|[A-Za-z]+", v or ""):
        out.append((0, int(p)) if p.isdigit() else (1, p.lower()))
    return out


def _vcmp(a, b):
    ka, kb = _ver_key(a), _ver_key(b)
    for i in range(max(len(ka), len(kb))):
        x = ka[i] if i < len(ka) else (0, 0)
        y = kb[i] if i < len(kb) else (0, 0)
        if x < y:
            return -1
        if x > y:
            return 1
    return 0


def parse_cpe(cpe):
    """(vendor, product, version) from a cpe:/a:... (URI) or cpe:2.3:a:... string."""
    if not cpe:
        return "", "", ""
    if cpe.startswith("cpe:/"):
        parts = cpe[5:].split(":")        # a:vendor:product:version...
    elif cpe.startswith("cpe:2.3:"):
        parts = cpe.split(":")[2:]        # a:vendor:product:version...
    else:
        return "", "", ""
    g = (parts + ["", "", "", ""])
    return g[1], g[2], (g[3] if g[3] not in ("*", "-", "") else "")


# --- NVD --------------------------------------------------------------------
def _parse_nvd(cve):
    cid = cve.get("id", "")
    score = severity = vector = None
    metrics = cve.get("metrics", {})
    for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(k)
        if arr:
            d = arr[0].get("cvssData", {})
            score = d.get("baseScore")
            severity = arr[0].get("baseSeverity") or d.get("baseSeverity")
            vector = d.get("vectorString")
            break
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break
    matches = []
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                matches.append(m)
    return {
        "id": cid, "cvss": score, "severity": severity, "vector": vector,
        "desc": " ".join(desc.split())[:400], "matches": matches,
        "published": (cve.get("published") or "")[:10],
    }


def nvd_vms(vendor, product, version, cdir, refresh, pacer):
    vms = f"cpe:2.3:a:{vendor}:{product}"
    if version:
        vms += f":{version}"
    key = "nvd_" + _slug(vms)
    if not refresh:
        cached = _cache_get(cdir, key, NVD_TTL)
        if cached is not None:
            info(f"cache hit: NVD {vendor}:{product}:{version or '*'}")
            return cached
    url = NVD_URL + "?" + urllib.parse.urlencode(
        {"virtualMatchString": vms, "resultsPerPage": "200"})
    pacer.wait()
    info(f"NVD query: {vendor}:{product} {version or '(all versions)'}")
    data = _get(url)
    out = [_parse_nvd(it.get("cve", {})) for it in (data or {}).get("vulnerabilities", [])]
    _cache_put(cdir, key, out)
    return out


def nvd_keyword(product, cdir, refresh, pacer):
    key = "nvdkw_" + _slug(product)
    if not refresh:
        cached = _cache_get(cdir, key, NVD_TTL)
        if cached is not None:
            info(f"cache hit: NVD keyword {product}")
            return cached
    url = NVD_URL + "?" + urllib.parse.urlencode(
        {"keywordSearch": product, "resultsPerPage": "40"})
    pacer.wait()
    info(f"NVD keyword fallback: {product}")
    data = _get(url)
    out = [_parse_nvd(it.get("cve", {})) for it in (data or {}).get("vulnerabilities", [])]
    _cache_put(cdir, key, out)
    return out


def lookup_service(svc, cdir, refresh, pacer):
    """Return (list_of_cve_dicts, query_label) for one service fingerprint."""
    version = svc.get("version") or ""
    candidates = []
    cv, cp, _ = parse_cpe(svc.get("cpe_app", ""))
    if cv and cp:
        candidates.append((cv, cp))
    for key in (svc.get("product", "").lower().strip(), svc.get("service", "").lower().strip()):
        for vp in CPE_ALIASES.get(key, []):
            if vp not in candidates:
                candidates.append(vp)

    cves, used = {}, None
    for (v, p) in candidates:
        res = nvd_vms(v, p, version, cdir, refresh, pacer)
        if res:
            used = f"cpe:2.3:a:{v}:{p}" + (f":{version}" if version else "")
            for c in res:
                cves[c["id"]] = c
            break
    if not cves:
        prod = (svc.get("product") or svc.get("service") or "").strip()
        if prod and prod.lower() != "unknown":
            for c in nvd_keyword(prod, cdir, refresh, pacer):
                c["status"] = "uncertain (keyword match — verify product/version)"
                cves[c["id"]] = c
            used = f"keyword:{prod}"

    distro = svc.get("distro_note")
    for c in cves.values():
        if "status" in c:
            continue
        if distro:
            c["status"] = f"uncertain (distro backport — verify {distro} security tracker)"
        else:
            c["status"] = "applicable (version within NVD range)"
    return list(cves.values()), used


# --- enrichment -------------------------------------------------------------
def load_kev(cdir, refresh):
    if not refresh:
        cached = _cache_get(cdir, "kev", DAILY)
        if cached is not None:
            return set(cached)
    info("fetching CISA KEV catalog…")
    data = _get(KEV_URL)
    ids = [v.get("cveID") for v in (data or {}).get("vulnerabilities", []) if v.get("cveID")]
    _cache_put(cdir, "kev", ids)
    return set(ids)


def load_epss(ids, cdir, refresh):
    ids = sorted(ids)
    if not ids:
        return {}
    key = "epss_" + _slug(",".join(ids))[:48] + f"_{len(ids)}"
    if not refresh:
        cached = _cache_get(cdir, key, DAILY)
        if cached is not None:
            return cached
    scores = {}
    info(f"fetching EPSS for {len(ids)} CVE(s)…")
    for i in range(0, len(ids), 100):
        chunk = ids[i:i + 100]
        data = _get(EPSS_URL + "?" + urllib.parse.urlencode({"cve": ",".join(chunk)}))
        for row in (data or {}).get("data", []):
            try:
                scores[row["cve"]] = float(row["epss"])
            except (KeyError, ValueError, TypeError):
                pass
    _cache_put(cdir, key, scores)
    return scores


def load_edb():
    idx = {}
    p = Path(EDB_CSV)
    if not p.is_file():
        warn("Exploit-DB CSV not baked in; skipping searchsploit lookup")
        return idx
    with p.open("r", encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            codes = row.get("codes", "") or ""
            for code in re.findall(r"CVE-\d{4}-\d+", codes):
                idx.setdefault(code.upper(), []).append({
                    "edb_id": row.get("id", ""),
                    "title": (row.get("description", "") or "").strip(),
                    "url": f"https://www.exploit-db.com/exploits/{row.get('id', '')}",
                })
    info(f"Exploit-DB index: {len(idx)} CVE(s) mapped")
    return idx


def load_msf(cdir, refresh):
    if not refresh:
        cached = _cache_get(cdir, "msf_modules", DAILY)
        if cached is not None:
            return cached
    info("fetching Metasploit module metadata (cached daily)…")
    data = _get(MSF_META)
    idx = {}
    if isinstance(data, dict):
        for mod in data.values():
            path = mod.get("fullname") or mod.get("name")
            for ref in (mod.get("references") or []):
                cve = None
                if isinstance(ref, (list, tuple)) and len(ref) >= 2 and str(ref[0]).upper() == "CVE":
                    cve = "CVE-" + str(ref[1])
                elif isinstance(ref, str):
                    m = re.search(r"CVE-\d{4}-\d+", ref.upper())
                    cve = m.group(0) if m else None
                if cve and path:
                    idx.setdefault(cve.upper(), []).append(path)
    info(f"Metasploit index: {len(idx)} CVE(s) mapped")
    _cache_put(cdir, "msf_modules", idx)
    return idx


def poc_github(cve, cdir, refresh):
    key = "poc_" + cve.upper()
    if not refresh:
        cached = _cache_get(cdir, key, DAILY)
        if cached is not None:
            return cached
    year = cve.split("-")[1] if "-" in cve else ""
    data = _get(POC_INDEX.format(year=year, cve=cve.upper()))
    repos = []
    if isinstance(data, list):
        for r in data:
            repos.append({
                "url": r.get("html_url"),
                "stars": r.get("stargazers_count", 0) or 0,
                "desc": (r.get("description") or "")[:160],
            })
    repos.sort(key=lambda x: -x["stars"])
    _cache_put(cdir, key, repos)
    return repos


# --- ranking ----------------------------------------------------------------
MINRANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def prelim_rank(c):
    if c["kev"]:
        return 0
    s = c.get("cvss") or 0
    e = c.get("epss") or 0
    return 2 if (s >= 7 or e >= 0.10) else 3


def final_bucket(c):
    if c["kev"]:
        return ("CRITICAL-KEV", 0)
    s = c.get("cvss") or 0
    e = c.get("epss") or 0
    poc = c["has_poc"]
    if (s >= 7 or e >= 0.5) and poc:
        return ("HIGH", 1)
    if s >= 7 or e >= 0.10 or poc:
        return ("MEDIUM", 2)
    return ("LOW", 3)


def has_poc(p):
    return bool(p["edb"] or p["github"] or p["msf"])


# --- service discovery ------------------------------------------------------
def split_version_field(name, verfield):
    verfield = verfield or ""
    m = VER_RE.search(verfield)
    version = m.group(0) if m else ""
    product = (verfield[:m.start()].strip() if m else verfield.strip()) or name
    distro = None
    dm = DISTRO_RE.search(verfield[m.end():] if m else verfield)
    if dm:
        distro = dm.group(0).strip(" ()")
    return product, version, distro


def svc_from_xml(xmlpath):
    try:
        root = ET.parse(str(xmlpath)).getroot()
    except Exception as e:  # noqa: BLE001
        warn(f"could not parse {xmlpath}: {e}")
        return None
    for port in root.iter("port"):
        st = port.find("state")
        if st is None or st.get("state") != "open":
            continue
        sv = port.find("service")
        if sv is None:
            continue
        name = sv.get("name", "")
        product = sv.get("product", "") or ""
        version = sv.get("version", "") or ""
        extra = sv.get("extrainfo", "") or ""
        cpes = [c.text for c in port.findall(".//cpe") if c.text]
        app = next((c for c in cpes if c.startswith("cpe:/a") or c.startswith("cpe:2.3:a")), "")
        ver = VER_RE.search(version)
        clean_ver = ver.group(0) if ver else (parse_cpe(app)[2] if app else "")
        distro = None
        dm = DISTRO_RE.search(version + " " + extra)
        if dm:
            distro = dm.group(0).strip(" ()")
        return {
            "proto": port.get("protocol", ""), "port": port.get("portid", ""),
            "service": name, "product": product or name, "version": clean_ver,
            "cpe_app": app, "distro_note": distro,
        }
    return None


SVC_LINE_RE = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)$")


def svc_from_facts(factspath):
    try:
        text = factspath.read_text(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return None
    for line in text.splitlines():
        m = SVC_LINE_RE.match(line.strip())
        if m:
            num, proto, name, ver = m.groups()
            product, version, distro = split_version_field(name, ver)
            return {
                "proto": proto, "port": num, "service": name,
                "product": product, "version": version,
                "cpe_app": "", "distro_note": distro,
            }
    return None


# whatweb plugins that are page metadata / transport, not a versioned product.
WHATWEB_SKIP = {"httpserver", "ip", "country", "title", "script", "html5",
                "cookies", "uncommonheaders", "redirectlocation", "email",
                "frame", "meta", "x-frame-options", "strict-transport-security",
                "via-proxy", "x-powered-by", "probablymeta", "open-graph-protocol"}


def svcs_from_whatweb(jsonpath, port_label):
    """Extra service candidates from a buckaroo's whatweb fingerprint.json.

    Yields one per version-bearing plugin (WordPress, PHP, jQuery, Tomcat, …) so
    web-app/library versions nmap can't see still get a CVE lookup. These attach
    to the aggregate only (port_dir=None) to avoid clobbering the port's nmap
    vulns.{md,json}.
    """
    try:
        data = json.loads(Path(jsonpath).read_text(encoding="utf-8", errors="replace"))
    except Exception:  # noqa: BLE001
        return []
    out = []
    for entry in (data if isinstance(data, list) else [data]):
        plugins = entry.get("plugins", {}) if isinstance(entry, dict) else {}
        for name, meta in plugins.items():
            if name.lower() in WHATWEB_SKIP:
                continue
            vers = (meta or {}).get("version") or []
            if not vers:
                continue
            vm = VER_RE.search(str(vers[0]))
            if not vm:
                continue
            out.append({
                "proto": "tcp", "port": "0", "service": name.lower(),
                "product": name, "version": vm.group(0), "cpe_app": "",
                "distro_note": None, "origin": "whatweb",
                "port_label": f"{port_label} · whatweb:{name}", "port_dir": None,
            })
    return out


def discover_services(target_dir, port_filter):
    services = []
    ports_dir = target_dir / "ports"
    if not ports_dir.is_dir():
        return services
    for pd in sorted(ports_dir.iterdir(), key=lambda p: p.name):
        if not pd.is_dir():
            continue
        if port_filter and pd.name != port_filter:
            continue
        svc = None
        if (pd / "nmap.xml").is_file():
            svc = svc_from_xml(pd / "nmap.xml")
        if not svc and (pd / "facts.md").is_file():
            svc = svc_from_facts(pd / "facts.md")
        if svc:
            svc["port_label"] = pd.name
            svc["port_dir"] = str(pd)
            services.append(svc)
        else:
            info(f"{pd.name}: no parseable service fingerprint, skipping")
        # whatweb-detected apps/libraries on this port (added after the nmap svc
        # so nmap wins the de-dupe below).
        if (pd / "fingerprint.json").is_file():
            services.extend(svcs_from_whatweb(pd / "fingerprint.json", pd.name))

    # De-dupe: drop a whatweb extra whose (product, version) a prior entry already
    # covers (e.g. nmap + whatweb both seeing nginx 1.18.0). Keep every nmap svc.
    seen, deduped = set(), []
    for s in services:
        key = (s.get("product", "").lower(), s.get("version", ""))
        if s.get("origin") == "whatweb" and key in seen:
            continue
        seen.add(key)
        deduped.append(s)
    return deduped


# --- rendering --------------------------------------------------------------
def poc_cell(p):
    bits = []
    if p["github"]:
        bits.append(f"GH:{len(p['github'])}")
    if p["edb"]:
        bits.append(f"EDB:{len(p['edb'])}")
    if p["msf"]:
        bits.append(f"MSF:{len(p['msf'])}")
    return ", ".join(bits) if bits else "—"


def render_service(svc, cves, cve_db, poc_db, min_rank, display_cap=25):
    title = f"{svc.get('proto', '?')}/{svc.get('port', '?')} — {svc.get('product') or svc.get('service')}"
    if svc.get("version"):
        title += f" {svc['version']}"
    lines = [f"## {title}"]
    if not cves:
        lines.append("")
        lines.append("_No applicable CVEs found via NVD for this fingerprint._")
        return "\n".join(lines) + "\n", []

    rows = sorted(
        (cve_db[c] for c in cves),
        key=lambda c: (c["rank"], -(c.get("epss") or 0), -(c.get("cvss") or 0), c["id"]),
    )
    within = [c for c in rows if c["rank"] <= min_rank]
    shown = within[:display_cap]
    below = len(rows) - len(within)
    capped = len(within) - len(shown)
    note = f"_query: `{svc.get('query') or 'n/a'}` · {len(rows)} applicable CVE(s), {len(shown)} shown"
    if below:
        note += f"; {below} below `--min-bucket`"
    if capped:
        note += f"; {capped} over display cap"
    note += "_"
    lines += ["", note, "",
              "| CVE | Bucket | CVSS | EPSS | KEV | PoC | Status |",
              "|-----|--------|------|------|-----|-----|--------|"]
    for c in shown:
        p = poc_db.get(c["id"], {"edb": [], "github": [], "msf": []})
        epss = f"{c['epss']:.2f}" if c.get("epss") is not None else "—"
        cvss = f"{c['cvss']}" if c.get("cvss") is not None else "—"
        lines.append(
            f"| {c['id']} | {c['bucket']} | {cvss} | {epss} | "
            f"{'yes' if c['kev'] else 'no'} | {poc_cell(p)} | {c['status'].split('(')[0].strip()} |")

    # Detail bullets for the actionable ones (KEV / HIGH with PoCs).
    detail = [c for c in shown if c["rank"] <= 1 or has_poc(poc_db.get(c["id"], {"edb": [], "github": [], "msf": []}))]
    if detail:
        lines += ["", "### Exploitation detail"]
        for c in detail:
            p = poc_db.get(c["id"], {"edb": [], "github": [], "msf": []})
            epss_str = ("%.2f" % c["epss"]) if c.get("epss") is not None else "—"
            lines += ["", f"**{c['id']}** — {c['bucket']}  ·  {c['status']}",
                      f"> {c['desc']}" if c["desc"] else "",
                      f"- scoring: CVSS {c.get('cvss', '—')} ({c.get('vector') or 'n/a'}) · "
                      f"EPSS {epss_str} · KEV {'yes' if c['kev'] else 'no'}"]
            for r in p["github"][:5]:
                lines.append(f"- PoC (GitHub ★{r['stars']}): {r['url']}")
            for e in p["edb"][:5]:
                lines.append(f"- Exploit-DB EDB-{e['edb_id']}: {e['url']}  — {e['title']}")
            for mod in p["msf"][:5]:
                lines.append(f"- Metasploit module: `{mod}`")
            lines.append(f"- NVD: https://nvd.nist.gov/vuln/detail/{c['id']}")
    return "\n".join([ln for ln in lines if ln is not None]) + "\n", shown


# --- main -------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(prog="vuln_lookup")
    ap.add_argument("--target", required=True)
    ap.add_argument("--out", default="recon-results")
    ap.add_argument("--product")
    ap.add_argument("--version")
    ap.add_argument("--cpe")
    ap.add_argument("--port")
    ap.add_argument("--min-bucket", dest="min_bucket", default="MEDIUM",
                    choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    ap.add_argument("--no-github", dest="no_github", action="store_true")
    ap.add_argument("--no-msf", dest="no_msf", action="store_true")
    ap.add_argument("--no-searchsploit", dest="no_searchsploit", action="store_true")
    ap.add_argument("--refresh", action="store_true")
    args = ap.parse_args()

    out_base = Path(args.out)
    target_dir = out_base / args.target
    target_dir.mkdir(parents=True, exist_ok=True)
    cdir = target_dir / ".vulncache"
    min_rank = MINRANK[args.min_bucket]
    pacer = _Pacer(NVD_SPACING)

    # 1. services
    if args.product:
        services = [{
            "proto": "tcp", "port": "0", "port_label": None, "port_dir": None,
            "service": args.product.lower(), "product": args.product,
            "version": args.version or "", "cpe_app": args.cpe or "", "distro_note": None,
        }]
        info(f"ad-hoc lookup: {args.product} {args.version or '(all versions)'}")
    else:
        services = discover_services(target_dir, args.port)
        if not services:
            die_empty(target_dir)
            return
        info(f"{len(services)} service fingerprint(s) from {target_dir}")

    # 2. NVD per service
    cve_db = {}            # id -> cve dict (shared)
    for svc in services:
        found, query = lookup_service(svc, cdir, args.refresh, pacer)
        svc["query"] = query
        svc["cves"] = []
        for c in found:
            cve_db.setdefault(c["id"], c)
            svc["cves"].append(c["id"])
        info(f"{svc.get('port_label') or svc['product']}: {len(found)} applicable CVE(s)"
             + (f" via {query}" if query else " (none)"))

    if not cve_db:
        ok("vuln-research complete — no applicable CVEs found.")
        write_outputs(target_dir, services, cve_db, {}, min_rank)
        return

    # 3. enrichment (KEV + EPSS over the unique set)
    kev = load_kev(cdir, args.refresh)
    epss = load_epss(list(cve_db.keys()), cdir, args.refresh)
    for cid, c in cve_db.items():
        c["kev"] = cid in kev
        c["epss"] = epss.get(cid)

    # 4. PoC discovery for prelim-MEDIUM+ (within threshold), then final bucket
    edb_idx = {} if args.no_searchsploit else load_edb()
    msf_idx = {} if args.no_msf else load_msf(cdir, args.refresh)
    poc_db = {}
    for cid, c in cve_db.items():
        pr = prelim_rank(c)
        p = {"edb": [], "github": [], "msf": []}
        if pr <= max(min_rank, 2):
            p["edb"] = edb_idx.get(cid, [])
            p["msf"] = msf_idx.get(cid, [])
            if not args.no_github:
                p["github"] = poc_github(cid, cdir, args.refresh)
        poc_db[cid] = p
        c["has_poc"] = has_poc(p)
        c["bucket"], c["rank"] = final_bucket(c)

    # 5. stream high-signal live
    for svc in services:
        for cid in sorted(set(svc["cves"]), key=lambda x: cve_db[x]["rank"]):
            c = cve_db[cid]
            if c["rank"] <= 1:   # CRITICAL-KEV or HIGH
                label = svc.get("port_label") or f"{svc['product']} {svc.get('version', '')}".strip()
                ok(f"vuln {cid} [{c['bucket']}] {label} — "
                   f"CVSS {c.get('cvss', '—')}, EPSS "
                   f"{('%.2f' % c['epss']) if c.get('epss') is not None else '—'}, "
                   f"PoC {poc_cell(poc_db[cid])}")

    # 6. write outputs
    write_outputs(target_dir, services, cve_db, poc_db, min_rank)


def die_empty(target_dir):
    warn(f"no service fingerprints under {target_dir}/ports/ — run a buckaroo first, "
         f"or pass --product/--version.")
    sys.exit(2)


def write_outputs(target_dir, services, cve_db, poc_db, min_rank):
    agg_md = [f"# Known vulnerabilities & exploits — {target_dir.name}", ""]
    if not cve_db:
        agg_md.append("_No applicable CVEs found for the current fingerprints._")
    counts = {"CRITICAL-KEV": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for c in cve_db.values():
        counts[c["bucket"]] = counts.get(c["bucket"], 0) + 1
    if cve_db:
        agg_md.append(
            f"_Totals: KEV {counts.get('CRITICAL-KEV', 0)} · HIGH {counts.get('HIGH', 0)} · "
            f"MEDIUM {counts.get('MEDIUM', 0)} · LOW {counts.get('LOW', 0)}. "
            f"Showing ≥ `{[k for k, v in MINRANK.items() if v == min_rank][0]}`._")
        agg_md.append("")
        agg_md.append("> Distro-backport note: services packaged by a distro (Ubuntu/Debian/…) "
                      "are often patched without bumping the upstream version. CVEs flagged "
                      "`uncertain (distro backport …)` need confirmation against the distro's "
                      "security tracker before you treat them as live.")

    for svc in services:
        section, shown = render_service(
            svc, svc.get("cves", []), cve_db, poc_db, min_rank)
        agg_md.append("")
        agg_md.append(section)
        # per-port artifacts (recon mode only)
        pdir = svc.get("port_dir")
        if pdir:
            pd = Path(pdir)
            (pd / "vulns.md").write_text(section, encoding="utf-8")
            (pd / "vulns.json").write_text(json.dumps({
                "service": {k: svc.get(k) for k in
                            ("proto", "port", "service", "product", "version",
                             "cpe_app", "distro_note", "query")},
                "cves": [dict(cve_db[c], poc=poc_db.get(c, {})) for c in svc.get("cves", [])],
            }, indent=2), encoding="utf-8")

    (target_dir / "vulns.md").write_text("\n".join(agg_md) + "\n", encoding="utf-8")
    (target_dir / "vulns.json").write_text(json.dumps({
        "target": target_dir.name,
        "totals": counts,
        "services": [{
            "port_label": svc.get("port_label"),
            **{k: svc.get(k) for k in ("proto", "port", "service", "product",
                                       "version", "cpe_app", "distro_note", "query")},
            "cves": [dict(cve_db[c], poc=poc_db.get(c, {})) for c in svc.get("cves", [])],
        } for svc in services],
    }, indent=2), encoding="utf-8")
    ok(f"vuln-research complete — {target_dir / 'vulns.md'} "
       f"(KEV {counts.get('CRITICAL-KEV', 0)}, HIGH {counts.get('HIGH', 0)}, "
       f"MEDIUM {counts.get('MEDIUM', 0)}, LOW {counts.get('LOW', 0)})")


if __name__ == "__main__":
    main()
