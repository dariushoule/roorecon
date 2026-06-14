#!/usr/bin/env python3
"""roo — RooRecon's cross-platform containerized tooling CLI.

One implementation for every shell (PowerShell, bash, zsh, Git Bash). All
security tooling runs in minimal per-tool Docker images built on demand and
tagged with a hash of their Dockerfile, so behavior is identical on Linux,
macOS, and Windows.

Subcommands:
  run <tool> [args...]            run a CLI in its container (e.g. run nmap -sCV ...)
  sweep <target>                  streaming parallel TCP+UDP port discovery
  buckaroo <target> <proto> <port>  per-port enum -> facts.md (+ hostname discovery)
  vhost <ip> <domain>             vhost (Host-header) enum for an internal IP
  dns <domain>                    DNS subdomain enum for an external domain
  dirbust <url>                   recursive directory/file brute (SecLists)
  recon <target>                  simple one-shot phased scan
  report <target>                 assemble per-port facts + notes into report.md
  vpn <up|down|status> [config]   manage the OpenVPN sidecar
  proxy <up|down|status>          SOCKS5 egress for host tools (browser/Burp/curl)
  shell [cmd...]                  interactive operator shell in the tunnel namespace
  responder [args...]             LLMNR/NBT-NS/mDNS poisoning + capture (tunnel iface)
  ip                              print the tunnel IP (your LHOST)
  fwd <port> [--stop]             bridge a tunnel port to a host listener
  hashcat [args...]               host hashcat for GPU cracking (auto-installs)
  wordlist [name]                 fetch a SecLists password list (default rockyou)
  tools <list|builds|get|installed|rm> [name]  prebuilt Windows tools → off-host /tools (prefers main builds)

Wordlists are baked into the gobuster image from SecLists; select with
--wordlist <name|path> or $ROO_WORDLIST. Defaults: vhost/dns ->
subdomains-top1million-5000, dirbust -> common.txt (recursion-friendly).

Environment:
  ROO_NET=<spec>    docker --network for tools (e.g. container:roorecon-vpn)
  ROO_NAME=<name>   name the container (cleanup of background runs)
  ROO_HOSTS=<path>  /etc/hosts overrides file (default ./hosts)

Authorized targets only — CTF boxes, lab ranges, or signed-scope hosts.
"""

import argparse
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# Force UTF-8 on our own streams. Windows consoles default to a legacy code
# page (cp1252), so printing the em-dash/arrow/ellipsis we use in status lines
# raises UnicodeEncodeError and kills the thread doing it — fatal for the sweep
# reader thread that streams port discoveries. errors="replace" is a belt-and-
# suspenders fallback for any glyph the target encoding still can't represent.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass  # not a reconfigurable TextIOWrapper (e.g. already wrapped/closed)

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCKER_DIR = Path(os.environ.get("ROO_DOCKER_DIR", REPO_ROOT / "docker"))
IMAGE_PREFIX = "roorecon"
VPN_CONTAINER = "roorecon-vpn"
PROXY_CONTAINER = "roorecon-proxy"
# Host port the sidecar publishes for the SOCKS proxy (override with ROO_SOCKS_PORT).
# Bound to 127.0.0.1 on the host; the in-namespace port is always 1080.
SOCKS_PORT = int(os.environ.get("ROO_SOCKS_PORT", "1080"))

DISCOVERED_RE = re.compile(r"Discovered open port (\d+)/(tcp|udp)")

# --- output -----------------------------------------------------------------
_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _s(code, text):
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


# flush=True so background/redirected runs (e.g. the sweep) stream their
# announcements in real time instead of block-buffering until exit.
def err(m):
    print(_s("31", "[!]"), m, file=sys.stderr, flush=True)


def info(m):
    print(_s("36", "[*]"), m, file=sys.stderr, flush=True)


def ok(m):
    print(_s("32", "[+]"), m, flush=True)


def die(m, code=1):
    err(m)
    sys.exit(code)


# --- docker / image helpers -------------------------------------------------
def require_docker():
    if shutil.which("docker") is None:
        die("docker not found. RooRecon runs all tooling in containers — install docker.")


def _dockerfile(tool):
    return DOCKER_DIR / tool / "Dockerfile"


def image_ref(tool):
    d = DOCKER_DIR / tool
    if not (d / "Dockerfile").is_file():
        return None
    # Tag by a hash of the whole build context (Dockerfile + any COPY'd files like
    # docker/vuln/vuln_lookup.py), not just the Dockerfile — so editing a copied
    # asset also bumps the tag and forces a rebuild on the next run.
    h = hashlib.sha256()
    for f in sorted(p for p in d.rglob("*") if p.is_file()):
        h.update(f.relative_to(d).as_posix().encode())
        h.update(b"\0")
        h.update(f.read_bytes())
        h.update(b"\0")
    return f"{IMAGE_PREFIX}/{tool}:{h.hexdigest()[:12]}"


def _image_exists(ref):
    return subprocess.run(
        ["docker", "image", "inspect", ref],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ).returncode == 0


def ensure_image(tool):
    """Build the tool's image on demand; return its ref."""
    ref = image_ref(tool)
    if ref is None:
        die(f'no image defined for "{tool}" (expected {_dockerfile(tool)})')
    if not _image_exists(ref):
        info(f"building {ref} (first use or Dockerfile changed)…")
        r = subprocess.run(
            ["docker", "build", "-q", "-t", ref, str(DOCKER_DIR / tool)],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True,
        )
        if r.returncode != 0:
            if r.stderr:
                sys.stderr.write(r.stderr)
            low = (r.stderr or "").lower()
            if any(s in low for s in ("toomanyrequests", "pull rate limit", "429")):
                err("Docker Hub rate-limited the base-image pull (unauthenticated limit).")
                err("Fix: run `docker login` (an authenticated account has a much higher "
                    "limit), then re-run — no Dockerfile changes needed.")
            die(f"failed to build image for {tool}")
    return ref


def try_image(tool):
    """Like ensure_image but non-fatal — returns None instead of dying.

    For *best-effort enrichment* (e.g. whatweb inside a buckaroo): a missing or
    unbuildable image should skip that extra, not abort the primary scan.
    """
    ref = image_ref(tool)
    if ref is None:
        return None
    if _image_exists(ref):
        return ref
    info(f"building {ref} (first use)…")
    r = subprocess.run(["docker", "build", "-q", "-t", ref, str(DOCKER_DIR / tool)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if r.returncode != 0:
        err(f"could not build {tool} image; skipping this step")
        return None
    return ref


# --- docker run flag builders (shared by every subcommand) ------------------
def _bind(source, target, readonly=False):
    """A --mount bind spec — parses cleanly on Windows (C:\\ colons) unlike -v."""
    src = str(Path(source).resolve())
    spec = f"type=bind,source={src},target={target}"
    if readonly:
        spec += ",readonly"
    return ["--mount", spec]


def _caps(tool):
    # Network scanners need raw sockets for SYN scans, OS detection, etc.
    return ["--cap-add=NET_RAW", "--cap-add=NET_ADMIN"] if tool == "nmap" else []


def _net():
    net = os.environ.get("ROO_NET")
    return ["--network", net] if net else []


def _hosts_mount():
    """Merge ./hosts overrides with localhost lines and mount as /etc/hosts.

    A bind mount (not --add-host) is used so it also works under
    --network container:, where --add-host is rejected.
    """
    overrides = Path(os.environ.get("ROO_HOSTS", "hosts"))
    if not (overrides.is_file() and overrides.stat().st_size > 0):
        return []
    gen_dir = Path(".roo")
    gen_dir.mkdir(exist_ok=True)
    gen = gen_dir / "etc-hosts"
    gen.write_text(
        "127.0.0.1\tlocalhost\n"
        "::1\tlocalhost ip6-localhost ip6-loopback\n"
        + overrides.read_text()
    )
    return _bind(gen, "/etc/hosts", readonly=True)


def _work_mount():
    return _bind(Path.cwd(), "/work") + ["-w", "/work"]


def _home_mount():
    """Persist the container's HOME across `roo shell` runs.

    net-toolbox runs as root, and several tools write under $HOME, not /work:
    NetExec keeps workspaces/logs/loot/downloads under ~/.nxc, certipy caches
    there, Kerberos ccaches default to ~ too. Without this, that state lives only
    in the --rm container and vanishes on exit — which forces needless re-runs
    (e.g. spider_plus output written to ~/.nxc disappears). Mount a git-ignored
    host dir at /root so it survives between invocations.
    """
    home = Path(".roo") / "home"
    home.mkdir(parents=True, exist_ok=True)
    return _bind(home, "/root")


# A *named Docker volume* (not a host bind) for prebuilt Windows tooling: shared
# across every `roo shell`, persists between runs, but lives inside the Docker VM
# — never on a host filesystem path, so host EDR doesn't scan it and offensive
# `.exe`s never trip a false positive. `roo tools` populates it; see cmd_tools.
TOOLS_VOLUME = "roorecon-tools"


def _tools_mount():
    return ["-v", f"{TOOLS_VOLUME}:/tools"]


def _rel_out(out):
    """Resolve an --out base to a cwd-relative path.

    Only the current directory is mounted into containers (/work), so tools must
    write under it. An absolute path inside cwd is rebased to relative; anything
    outside cwd is a hard error (its output would silently vanish in-container).
    """
    p = Path(out)
    if p.is_absolute():
        try:
            p = p.resolve().relative_to(Path.cwd())
        except ValueError:
            die(f"--out must be inside the current directory (mounted as /work); "
                f"got '{out}'")
    return p


def _cpath(p):
    """POSIX form of a cwd-relative path, for passing as a container argument.

    The tool container is always Linux. str(Path) on Windows yields backslash
    separators, which a Linux tool treats as literal filename characters — so an
    -oA/-oN target like recon-results\\host\\tcp lands as one mangled flat file in
    /work instead of nesting into the directory. as_posix() keeps the slashes.
    """
    return Path(p).as_posix()


def _docker_run(tool, ref, tool_args, *, name=None, tty=False, stream=False,
                quiet=False, extra_mounts=None, use_net=True):
    """Build (and optionally launch) a `docker run` for a tool image.

    stream=True -> Popen with stdout piped (for the sweep reader); otherwise a
    blocking subprocess.run. quiet=True silences the tool's stdout/stderr (used
    when we only care about the -oA/-oN files it writes). extra_mounts injects
    additional --mount specs (e.g. a custom wordlist).

    use_net=True applies $ROO_NET (e.g. the VPN tunnel namespace). Pass
    use_net=False for tools whose traffic goes to the *public internet*, not the
    target — e.g. CVE lookups — so they egress on the default docker network and
    are never forced through the engagement tunnel.
    """
    cmd = ["docker", "run", "--rm"]
    if tty and sys.stdin.isatty() and sys.stdout.isatty():
        cmd.append("-it")
    if name:
        cmd += ["--name", name]
    cmd += (_caps(tool) + (_net() if use_net else []) + _hosts_mount() + (extra_mounts or [])
            + _work_mount() + [ref] + list(tool_args))
    if stream:
        return subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
    if quiet:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return subprocess.run(cmd)


# --- subcommand: run --------------------------------------------------------
def cmd_run(args):
    require_docker()
    ref = ensure_image(args.tool)
    name = os.environ.get("ROO_NAME")
    r = _docker_run(args.tool, ref, args.args, name=name, tty=True)
    sys.exit(r.returncode)


# --- subcommand: sweep (streaming producer) ---------------------------------
def cmd_sweep(args):
    require_docker()
    ref = ensure_image("nmap")
    target = args.target
    outdir = _rel_out(args.out) / target
    ports_dir = outdir / "ports"
    ports_dir.mkdir(parents=True, exist_ok=True)
    (outdir / "sweep.done").unlink(missing_ok=True)

    lock = threading.Lock()
    pid = os.getpid()
    tcp_name, udp_name = f"roo-sweep-tcp-{pid}", f"roo-sweep-udp-{pid}"

    def claim(proto, port):
        d = ports_dir / f"{proto}-{port}"
        with lock:
            try:
                d.mkdir()
            except FileExistsError:
                return
            (d / "claim").write_text(f"target={target}\nproto={proto}\nport={port}\n")
            with (outdir / "discovered.tsv").open("a") as t:
                t.write(f"{proto}\t{port}\n")
        ok(f"discovered {proto}/{port}  → {d}/")

    def reader(proc, logpath):
        with logpath.open("w") as lf:
            for line in proc.stdout:
                lf.write(line)
                lf.flush()
                m = DISCOVERED_RE.search(line)
                if m:
                    claim(m.group(2), m.group(1))

    # -oA paths are relative (POSIX) so they land under /work (= cwd) in the container.
    tcp_oa = _cpath(outdir / "tcp")
    udp_oa = _cpath(outdir / "udp")
    tcp_proc = _docker_run(
        "nmap", ref,
        ["-v", "-Pn", "-n", "-sS", "-p-", "--min-rate", "1000", "-T4", "-oA", tcp_oa, target],
        name=tcp_name, stream=True)
    udp_proc = _docker_run(
        "nmap", ref,
        ["-v", "-Pn", "-n", "-sU", "--top-ports", "200", "-T4", "-oA", udp_oa, target],
        name=udp_name, stream=True)

    info(f"sweep on {target}: TCP -p- (SYN) + UDP top-200, streaming discoveries…")
    threads = [
        threading.Thread(target=reader, args=(tcp_proc, outdir / "sweep-tcp.log"), daemon=True),
        threading.Thread(target=reader, args=(udp_proc, outdir / "sweep-udp.log"), daemon=True),
    ]
    try:
        for t in threads:
            t.start()
        tcp_proc.wait()
        udp_proc.wait()
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        pass
    finally:
        for p in (tcp_proc, udp_proc):
            if p.poll() is None:
                p.terminate()
        subprocess.run(["docker", "rm", "-f", tcp_name, udp_name],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    (outdir / "sweep.done").touch()
    n = len([p for p in ports_dir.iterdir() if p.is_dir()])
    ok(f"sweep complete — {n} open port(s). Claims in {ports_dir}/, raw logs in {outdir}/.")


# --- subcommand: buckaroo (mechanical per-port enum) ------------------------
# ssl-cert on the http entry harvests cert CN/SAN hostnames (no-op on plain HTTP).
NSE_PLAYBOOK = [
    (re.compile(r"http"), "http-title,http-headers,http-methods,http-robots.txt,ssl-cert"),
    (re.compile(r"^ssh$"), "ssh2-enum-algos,ssh-hostkey"),
    (re.compile(r"^ftp$"), "ftp-anon,ftp-syst"),
    (re.compile(r"smb|microsoft-ds|netbios"), "smb-os-discovery,smb-security-mode,smb-enum-shares"),
    (re.compile(r"^(domain|dns)$"), "dns-nsid,dns-recursion"),
]


def _service_from(nmap_txt, port, proto):
    line_re = re.compile(rf"^{port}/{proto}\s+open\s+(\S+)")
    for line in nmap_txt.splitlines():
        m = line_re.match(line)
        if m:
            return m.group(1)
    return "unknown"


# Hostnames a box reveals about itself: an HTTP redirect target, or the CN/SAN
# of a TLS cert. These are the classic "add to /etc/hosts, then vhost-fuzz" seeds.
_HOSTNAME_SOURCES = [
    re.compile(r"redirect to https?://([A-Za-z0-9.-]+)"),  # http-title
    re.compile(r"commonName=([A-Za-z0-9.*-]+)"),           # ssl-cert CN
    re.compile(r"DNS:([A-Za-z0-9.*-]+)"),                  # ssl-cert SAN
]
_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _extract_hostnames(text, target):
    names = set()
    for rx in _HOSTNAME_SOURCES:
        for m in rx.finditer(text):
            h = m.group(1).lower().strip(".")
            if h and h != target and not _IP_RE.match(h) and "." in h:
                names.add(h)
    return sorted(names)


def _append_hosts_overrides(target, hostnames):
    """Add newly discovered hostnames to ROO_HOSTS/./hosts when target is an IP."""
    if not (_IP_RE.match(target) and hostnames):
        return []

    usable = [h for h in hostnames if not h.startswith("*.")]
    if not usable:
        return []

    hosts_path = Path(os.environ.get("ROO_HOSTS", "hosts"))
    existing = hosts_path.read_text().splitlines() if hosts_path.exists() else []
    mapped = set()
    for line in existing:
        clean = line.split("#", 1)[0].strip()
        if not clean:
            continue
        parts = clean.split()
        mapped.update(parts[1:])

    added = [h for h in usable if h not in mapped]
    if not added:
        return []

    hosts_path.parent.mkdir(parents=True, exist_ok=True)
    with hosts_path.open("a") as f:
        if existing and existing[-1].strip():
            f.write("\n")
        for h in added:
            f.write(f"{target} {h}\n")
    return added


def _buckaroo_whatweb(svc, target, port, d):
    """Run whatweb on a web service; write fingerprint.json, return a summary str.

    Best-effort enrichment for buckaroo — returns "" (and never raises) if the
    service isn't web, the image can't build, or whatweb finds nothing.
    """
    if not re.search(r"http", svc or ""):
        return ""
    wref = try_image("whatweb")
    if not wref:
        return ""
    scheme = "https" if (re.search(r"https|ssl", svc) or port in ("443", "8443")) else "http"
    url = f"{scheme}://{target}:{port}/"
    info(f"web service → whatweb fingerprint ({url})")
    fp_json = _cpath(d / "fingerprint.json")
    try:
        proc = _docker_run("whatweb", wref,
                           ["--color=never", "-a", "3", f"--log-json={fp_json}", url],
                           stream=True)
        lines = [ln.strip() for ln in proc.stdout if ln.strip()]
        proc.wait()
    except Exception as e:  # noqa: BLE001 — enrichment must not fail the buckaroo
        err(f"whatweb fingerprint failed: {e}")
        return ""
    summary = "\n".join(lines)
    if lines:
        ok(f"web fingerprint tcp/{port}: {lines[0][:200]}")
    return summary


def cmd_buckaroo(args):
    require_docker()
    if args.proto not in ("tcp", "udp"):
        die(f"proto must be tcp or udp (got '{args.proto}')", 2)
    ref = ensure_image("nmap")
    target, proto, port = args.target, args.proto, args.port
    out_base = _rel_out(args.out)
    d = out_base / target / "ports" / f"{proto}-{port}"
    d.mkdir(parents=True, exist_ok=True)
    scan = ["-sS", "-sCV"] if proto == "tcp" else ["-sU", "-sV"]

    info(f"buckaroo on {proto}/{port} @ {target} — focused service scan")
    nmap_out = _cpath(d / "nmap.txt")
    # -oX as well: nmap emits per-service app CPEs (cpe:/a:vendor:product:version)
    # only in XML, and `roo vulns` uses them for accurate CVE lookups. Additive —
    # nmap.txt is unchanged, this just adds nmap.xml alongside it.
    nmap_xml = _cpath(d / "nmap.xml")
    _docker_run("nmap", ref,
                ["-Pn", "-n", *scan, f"-p{port}", "-oN", nmap_out, "-oX", nmap_xml, target],
                quiet=True)

    nmap_txt = (d / "nmap.txt").read_text() if (d / "nmap.txt").exists() else ""
    svc = _service_from(nmap_txt, port, proto)

    nse = next((scripts for pat, scripts in NSE_PLAYBOOK if pat.search(svc)), "")
    scripts_txt = ""
    if nse:
        info(f"service '{svc}' → NSE: {nse}")
        # -sV so service-bound NSE scripts fire on a non-default port.
        _docker_run("nmap", ref,
                    ["-Pn", "-n", "-sV", "--script", nse, f"-p{port}",
                     "-oN", _cpath(d / "scripts.txt"), target], quiet=True)
        if (d / "scripts.txt").exists():
            scripts_txt = (d / "scripts.txt").read_text()

    svc_line = next((ln for ln in nmap_txt.splitlines()
                     if re.match(rf"^{port}/{proto}\s", ln)), "(no open service line)")
    ok(f"fingerprint {proto}/{port}: {svc_line.strip()}")  # surface live, before the report
    facts = [f"# {proto}/{port} on {target}", "", f"- service: `{svc}`", "",
             "## Service/version scan", "```", svc_line, "```"]
    if scripts_txt.strip():
        nse_lines = [ln for ln in scripts_txt.splitlines() if ln.startswith("|")]
        facts += ["", "## NSE script output", "```",
                  "\n".join(nse_lines) if nse_lines else "(no script output)", "```"]

    # Learn redirect/cert hostnames before web enrichment. If the scan target is
    # an IP, persist those names into ./hosts so WhatWeb can follow redirects
    # during this same buckaroo instead of recording a resolver failure.
    hostnames = _extract_hostnames(nmap_txt + "\n" + scripts_txt, target)
    added_hosts = _append_hosts_overrides(target, hostnames)
    if added_hosts:
        ok(f"hosts updated: {', '.join(added_hosts)} → {target}")

    # Web service → sharpen past nmap with whatweb (tech/version from headers,
    # cookies, body, meta). Best-effort: a whatweb miss never fails the buckaroo.
    # Writes fingerprint.json (which `roo vulns` mines for app/version CVEs) and
    # folds a summary into facts.md. Honors ROO_NET like the nmap scans above.
    web_summary = _buckaroo_whatweb(svc, target, port, d)
    if web_summary:
        facts += ["", "## Web fingerprint (whatweb)", "```", web_summary, "```"]

    # Surface hostnames the box revealed (redirect target / cert CN+SAN). These
    # feed vhost/dns enum and now also prime ./hosts for web enrichment above.
    if hostnames:
        facts += ["", "## Discovered hostnames",
                  *(f"- `{h}`  (map to {target} in ./hosts)" for h in hostnames)]
        hp = out_base / target / "hostnames.txt"
        seen = set(hp.read_text().split()) if hp.exists() else set()
        with hp.open("a") as f:
            for h in hostnames:
                if h not in seen:
                    f.write(h + "\n")
        ok(f"hostnames discovered: {', '.join(hostnames)}")

    (d / "facts.md").write_text("\n".join(facts) + "\n")
    ok(f"buckaroo done — facts in {d / 'facts.md'}")


# --- subcommand: vhost / dns (name enumeration via gobuster) ----------------
DEFAULT_WORDLIST = "/wordlists/subdomains-top1million-5000.txt"
# gobuster 3.8 vhost prints "host Status: 200 [Size: N]"; dns prints "fqdn  ip,ip".
VHOST_HIT_RE = re.compile(r"(\S+)\s+Status:")
DNS_HIT_RE = re.compile(r"^([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+)\b")


def _resolve_wordlist(w, default=DEFAULT_WORDLIST):
    """Return (container_path, extra_mounts) for a wordlist selector.

    Selector may be a baked name (e.g. combined_subdomains.txt) or an absolute
    /wordlists path -> used as-is; or a host file path -> mounted into the image.
    Falls back to $ROO_WORDLIST, then the caller's default.
    """
    w = w or os.environ.get("ROO_WORDLIST") or default
    p = Path(w)
    if p.is_file():  # a host path -> mount it in
        return "/wordlists/_custom", _bind(p, "/wordlists/_custom", readonly=True)
    if "/" not in w:  # a bare baked name
        w = f"/wordlists/{w}"
    return w, []


def _stream_hits(proc, logpath, out_path, hit_re, label):
    """Tee a gobuster stream to logpath, append each parsed hit to out_path."""
    found = []
    with logpath.open("w") as lf, out_path.open("a") as of:
        for line in proc.stdout:
            lf.write(line)
            lf.flush()
            m = hit_re.search(line)
            if m:
                name = m.group(1)
                of.write(name + "\n")
                of.flush()
                found.append(name)
                ok(f"{label}: {name}")
    proc.wait()
    return found


def cmd_vhost(args):
    """vhost (Host-header) enumeration against an internal IP."""
    require_docker()
    ref = ensure_image("gobuster")
    wl, mounts = _resolve_wordlist(args.wordlist)
    outdir = _rel_out(args.out) / args.target
    outdir.mkdir(parents=True, exist_ok=True)
    url = f"{args.scheme}://{args.target}"
    info(f"vhost enum on {url} for *.{args.domain} (wordlist {wl})")
    # gobuster 3.8 vhost auto-calibrates against a baseline and only reports
    # vhosts whose response differs — so default-page false positives drop out.
    gob = ["vhost", "-u", url, "--domain", args.domain, "--append-domain",
           "-w", wl, "--no-progress", "-q"]
    proc = _docker_run("gobuster", ref, gob, stream=True, extra_mounts=mounts)
    found = _stream_hits(proc, outdir / "vhost.log", outdir / "vhosts.txt",
                         VHOST_HIT_RE, "vhost")
    ok(f"vhost enum done — {len(found)} hit(s) in {outdir / 'vhosts.txt'}")


def cmd_dns(args):
    """DNS subdomain enumeration for an external domain."""
    require_docker()
    ref = ensure_image("gobuster")
    wl, mounts = _resolve_wordlist(args.wordlist)
    outdir = _rel_out(args.out) / args.domain
    outdir.mkdir(parents=True, exist_ok=True)
    info(f"dns subdomain enum on {args.domain} (wordlist {wl})")
    gob = ["dns", "--domain", args.domain, "-w", wl, "--no-progress", "-q"]
    proc = _docker_run("gobuster", ref, gob, stream=True, extra_mounts=mounts)
    found = _stream_hits(proc, outdir / "dns.log", outdir / "subdomains.txt",
                         DNS_HIT_RE, "subdomain")
    ok(f"dns enum done — {len(found)} name(s) in {outdir / 'subdomains.txt'}")


# --- subcommand: dirbust (recursive content discovery via gobuster) ---------
# gobuster has no native recursion, so roo drives it: BFS over discovered
# directories, re-running `gobuster dir` per level. common.txt is the default
# because recursion multiplies requests — a big list per level explodes fast;
# pass --wordlist DirBuster-2007_directory-list-2.3-big.txt for a thorough run.
DIR_DEFAULT_WORDLIST = "/wordlists/common.txt"
# gobuster dir prints the wordlist entry (no leading slash), e.g.
# "login                (Status: 200) [Size: 6160]"; a real directory adds a
# trailing-slash redirect "[--> http://h/login/]". Capture entry + status.
DIR_HIT_RE = re.compile(r"^(\S+)\s+\(Status:\s*(\d+)\)")
# Recursing into static-asset trees burns requests for nothing — record the hit
# but don't descend. Extend per-run with --skip (this baseline always applies).
NOISE_DIRS = {"css", "js", "javascript", "images", "img", "icons", "fonts",
              "assets", "static", "media", "styles", "vendor", "dist", "build",
              "node_modules", "bower_components"}


def _host_from_url(url):
    m = re.match(r"https?://([^/:]+)", url)
    return m.group(1) if m else url.replace("/", "_")


def _looks_like_dir(path, status, line):
    """Recurse into a hit only if it looks like a directory.

    Most reliable signal: the server redirected to the same path *with a
    trailing slash* (nginx/apache auto-append for real dirs). Absent a redirect,
    treat an extensionless 2xx/403 as a directory candidate. Plain redirects to
    elsewhere (e.g. an auth gate, /dashboard -> /login) are not dirs.
    """
    redir = re.search(r"\[-->\s*(.+?)\]", line)
    if redir:
        return redir.group(1).strip().endswith("/")
    if status.startswith("2") or status == "403":
        return "." not in path.rstrip("/").rsplit("/", 1)[-1]
    return False


def cmd_dirbust(args):
    """Recursive directory/file brute-forcing via gobuster (SecLists)."""
    require_docker()
    ref = ensure_image("gobuster")
    wl, mounts = _resolve_wordlist(args.wordlist, default=DIR_DEFAULT_WORDLIST)
    host = _host_from_url(args.url)
    outdir = _rel_out(args.out) / host
    outdir.mkdir(parents=True, exist_ok=True)
    findings = outdir / "dirbust.txt"
    logpath = outdir / "dirbust.log"

    # Don't recurse into asset/noise dirs (default set + --skip extras).
    skip = NOISE_DIRS | {s.strip().lower() for s in (args.skip or "").split(",") if s.strip()}
    base = args.url.rstrip("/")
    queue = [(base, 0)]       # (url, depth)
    visited = set()
    hits = []
    info(f"dirbust on {base} — wordlist {wl}, depth {args.depth}, cap {args.max_dirs} dirs")
    with findings.open("w") as ff, logpath.open("w") as lf:
        while queue:
            url, depth = queue.pop(0)
            if url in visited:
                continue
            if len(visited) >= args.max_dirs:
                info(f"reached --max-dirs {args.max_dirs}; {len(queue)+1} queued "
                     f"dir(s) not scanned (raise --max-dirs to go deeper)")
                break
            visited.add(url)
            gob = ["dir", "-u", url, "-w", wl, "-t", str(args.threads),
                   "--no-progress", "-q", "-k"]
            if args.ext:
                gob += ["-x", args.ext]
            lf.write(f"\n=== {url} (depth {depth}) ===\n")
            lf.flush()
            info(f"scanning {url}  (depth {depth})")
            proc = _docker_run("gobuster", ref, gob, stream=True, extra_mounts=mounts)
            for line in proc.stdout:
                lf.write(line)
                lf.flush()
                m = DIR_HIT_RE.match(line.strip())
                if not m:
                    continue
                path, status = m.group(1).lstrip("/"), m.group(2)
                full = f"{url}/{path}"
                ff.write(f"{status}\t{full}\n")
                ff.flush()
                hits.append((status, full))
                ok(f"dirbust: {status}  {full}")     # surface live, don't wait for the end
                seg = path.rstrip("/").rsplit("/", 1)[-1].lower()
                if (depth + 1 <= args.depth and seg not in skip
                        and _looks_like_dir(path, status, line)):
                    nxt = full.rstrip("/")
                    if nxt not in visited and all(nxt != q for q, _ in queue):
                        queue.append((nxt, depth + 1))
            proc.wait()
    ok(f"dirbust done — {len(hits)} path(s) across {len(visited)} dir(s) in {findings}")


# --- subcommand: recon (simple phased scan) ---------------------------------
def cmd_recon(args):
    require_docker()
    ref = ensure_image("nmap")
    target = args.target
    outdir = _rel_out(args.out) / target
    outdir.mkdir(parents=True, exist_ok=True)

    info(f"Phase 1/2 — full TCP port sweep on {target} (this can take a few minutes)")
    _docker_run("nmap", ref,
                ["-Pn", "-n", "-sS", "-p-", "--min-rate", "1000", "-T4",
                 "-oA", _cpath(outdir / "all-ports"), target], quiet=True)

    gnmap = outdir / "all-ports.gnmap"
    ports = sorted({m.group(1) for m in
                    re.finditer(r"(\d+)/open", gnmap.read_text() if gnmap.exists() else "")},
                   key=int)
    if not ports:
        (outdir / "summary.txt").write_text(
            f"Target:     {target}\nOpen ports: none found\n")
        die(f"no open TCP ports found on {target}.", 0)

    ok(f"open ports: {','.join(ports)}")
    info("Phase 2/2 — service/version + default scripts on open ports")
    _docker_run("nmap", ref,
                ["-Pn", "-n", "-sS", "-sCV", "-p", ",".join(ports),
                 "-oA", _cpath(outdir / "services"), target], quiet=True)

    svc_nmap = (outdir / "services.nmap").read_text() if (outdir / "services.nmap").exists() else ""
    svc_lines = [ln for ln in svc_nmap.splitlines() if re.match(r"^\d+/(tcp|udp)\s+open", ln)]
    summary = (f"Target:     {target}\nOpen ports: {','.join(ports)}\n\n"
               "== Services ==\n" + "\n".join(svc_lines) + "\n")
    (outdir / "summary.txt").write_text(summary)
    ok(f"done. results in {outdir}/")
    print("\n" + summary)


# --- subcommand: report (assemble per-port artifacts into one markdown) -----
# A report is the *final* aggregation, not the delivery path for time-sensitive
# findings — sweep/buckaroo/dirbust already stream those live to the CLI. This
# just collates what's on disk so the operator (and agent) have one document.
# The layout lives in an editable template (templates/report.md) — roo only
# fills {{TOKENS}} — because it's a high-traffic manual tweak. Override the
# template path with --template or $ROO_REPORT_TEMPLATE.
_SVC_LINE_RE = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)$")
REPORT_TEMPLATE = Path(os.environ.get("ROO_REPORT_TEMPLATE",
                                      REPO_ROOT / "templates" / "report.md"))


def _port_sort_key(name):
    # "tcp-80" -> ("tcp", 80) so ports sort numerically within a protocol.
    proto, _, port = name.partition("-")
    return (proto, int(port) if port.isdigit() else 0)


def _read(p):
    return p.read_text(encoding="utf-8", errors="replace") if p.is_file() else ""


def cmd_report(args):
    """Assemble per-port facts + notes into a single markdown report."""
    target = args.target
    outdir = _rel_out(args.out) / target
    if not outdir.is_dir():
        die(f"no results at {outdir}/ — run a sweep/buckaroo first")
    template = Path(args.template) if args.template else REPORT_TEMPLATE
    if not template.is_file():
        die(f"report template not found: {template}")
    ports_dir = outdir / "ports"
    port_dirs = sorted([p for p in ports_dir.iterdir() if p.is_dir()],
                       key=lambda p: _port_sort_key(p.name)) if ports_dir.is_dir() else []

    # Open-port fingerprint rows, pulled from each port's facts.md service line.
    rows, details = [], []
    for pd in port_dirs:
        facts = _read(pd / "facts.md")
        notes = _read(pd / "notes.md")
        svc = next((m for m in (_SVC_LINE_RE.match(ln.strip())
                                 for ln in facts.splitlines()) if m), None)
        if svc:
            num, proto, name, ver = svc.groups()
            rows.append(f"| {num} | {proto} | {name} | {ver.strip() or '—'} |")
        else:
            rows.append(f"| {pd.name} | | (no facts yet) | — |")
        block = [f"### {pd.name.replace('-', '/')}", ""]
        block.append(facts.strip() or "_no facts.md — run a buckaroo on this port._")
        if notes.strip():
            block += ["", "#### Operator notes", "", notes.strip()]
        details.append("\n".join(block))

    hostnames = [h for h in _read(outdir / "hostnames.txt").split() if h]
    # The template already supplies the section heading, so drop the aggregate
    # vulns.md's own top-level "# …" title to avoid nesting an H1 under an H2.
    vulns_md = re.sub(r"\A#\s+.*\n+", "", _read(outdir / "vulns.md").strip())
    tokens = {
        "TARGET": target,
        "SWEEP_STATUS": "complete" if (outdir / "sweep.done").is_file()
                        else "in progress / not run",
        "PORT_COUNT": str(len(port_dirs)),
        "FINGERPRINT_ROWS": "\n".join(rows or ["| — | | none found | — |"]),
        "HOSTNAMES": ("\n".join(f"- `{h}`  → add `{target} {h}` to ./hosts" for h in hostnames)
                      if hostnames
                      else "_none discovered. Buckaroo a web port to harvest redirect/cert names._"),
        "PER_PORT_DETAIL": "\n\n".join(details) if details else "_no ports enumerated yet._",
        "VULN_FINDINGS": (vulns_md if vulns_md
                          else f"_no vuln-research yet. Run `roo vulns {target}` to populate._"),
    }
    md = template.read_text(encoding="utf-8")
    # Strip a leading HTML comment block — it's editor-only help (the token list)
    # and shouldn't render into the report. The in-body TODO comment survives.
    md = re.sub(r"\A\s*<!--.*?-->\s*", "", md, count=1, flags=re.DOTALL)
    for k, v in tokens.items():
        md = md.replace("{{" + k + "}}", v)
    report = outdir / "report.md"
    report.write_text(md, encoding="utf-8")
    ok(f"report written — {report}  ({len(port_dirs)} port(s), template {template.name})")


# --- subcommand: fingerprint (web tech/version detection via whatweb) -------
def cmd_fingerprint(args):
    """Web fingerprint via whatweb — sharpen tech + version detection past nmap."""
    require_docker()
    ref = ensure_image("whatweb")
    host = _host_from_url(args.url)
    outdir = _rel_out(args.out) / host
    outdir.mkdir(parents=True, exist_ok=True)
    jsonpath = outdir / "fingerprint.json"
    logpath = outdir / "fingerprint.log"
    aggr = str(args.aggression)
    info(f"fingerprint on {args.url} — whatweb -a {aggr} (honors ROO_NET / tunnel)")
    wargs = ["--color=never", "-a", aggr, f"--log-json={_cpath(jsonpath)}", args.url]
    # Target-facing → use_net default True, so it reaches a VPN-only target.
    proc = _docker_run("whatweb", ref, wargs, stream=True)
    with logpath.open("w") as lf:
        for line in proc.stdout:
            lf.write(line)
            lf.flush()
            s = line.strip()
            if s:
                ok(f"fingerprint: {s}")   # surface the tech/version summary live
    proc.wait()
    ok(f"fingerprint done — {jsonpath} (feed sharper versions into `roo vulns`)")


# --- subcommand: vulns (CVE + public PoC lookup; keyless sources) -----------
def cmd_vulns(args):
    """Look up CVEs + public PoCs for recon fingerprints (keyless sources)."""
    require_docker()
    ref = ensure_image("vuln")
    out_base = _rel_out(args.out)
    label = args.target
    if not args.product and not (out_base / label).is_dir():
        die(f"no recon results at {out_base / label}/ — run a sweep/buckaroo first, "
            f"or pass --product/--version for an ad-hoc lookup")
    argv = ["--target", label, "--out", _cpath(out_base), "--min-bucket", args.min_bucket]
    for flag, val in (("--product", args.product), ("--version", args.version),
                      ("--cpe", args.cpe), ("--port", args.port)):
        if val:
            argv += [flag, val]
    for flag, on in (("--no-github", args.no_github), ("--no-msf", args.no_msf),
                     ("--no-searchsploit", args.no_searchsploit), ("--refresh", args.refresh)):
        if on:
            argv.append(flag)
    # CVE lookups hit the *public internet* (NVD/KEV/EPSS/GitHub), never the
    # target — use_net=False keeps them on the default docker network even when
    # ROO_NET points at the VPN, so engagement and research traffic stay split.
    info(f"vuln-research on {label} — public-internet sources, not tunneled")
    r = _docker_run("vuln", ref, argv, use_net=False)
    if r.returncode != 0:
        die(f"vuln-research worker exited {r.returncode}")


# --- subcommand: vpn --------------------------------------------------------
def _vpn_running():
    r = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", VPN_CONTAINER],
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    return r.stdout.strip() == "true"


def _tun_addr():
    r = subprocess.run(["docker", "exec", VPN_CONTAINER, "ip", "-4", "-o", "addr", "show", "tun0"],
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", r.stdout)
    return m.group(1) if m else ""


def _find_ovpn(explicit, vpn_dir):
    if explicit:
        p = Path(explicit)
        if p.is_file():
            return p
        # Bare name or relative path — look inside the vpn dir before failing,
        # so `roo vpn up machines_us-dedivip-1.ovpn` works from anywhere.
        candidate = Path(vpn_dir) / explicit
        if candidate.is_file():
            return candidate
        die(f"config not found: {explicit} (looked in ./ and {vpn_dir}/)")
    matches = sorted(Path(vpn_dir).glob("*.ovpn")) if Path(vpn_dir).is_dir() else []
    if not matches:
        err("no OpenVPN config provided.")
        die(f"Place your .ovpn in {vpn_dir}/ (or pass a path), then re-run.")
    if len(matches) > 1:
        err(f"multiple .ovpn files in {vpn_dir}/ — pass the one to use:")
        for m in matches:
            print(f"      {m}", file=sys.stderr)
        sys.exit(1)
    return matches[0]


def cmd_vpn(args):
    require_docker()
    if args.action == "status":
        if _vpn_running():
            addr = _tun_addr()
            ok(f"VPN connected — tunnel address {addr}") if addr else \
                info("sidecar running but tun0 has no address yet")
        else:
            info("VPN sidecar is not running (roo vpn up to start it)")
        return
    if args.action == "down":
        r = subprocess.run(["docker", "rm", "-f", VPN_CONTAINER],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ok("VPN sidecar stopped") if r.returncode == 0 else info("no VPN sidecar running")
        return
    # up
    config = _find_ovpn(args.config, "vpn")
    ref = ensure_image("openvpn")
    subprocess.run(["docker", "rm", "-f", VPN_CONTAINER],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    info(f"starting VPN sidecar with {config.name}")
    # The sidecar owns the tunnel namespace, so it carries the two bits of
    # namespace *config* that only the owner can set (never tools — see
    # ARCHITECTURE.md): it publishes the SOCKS port the host reaches (netns-
    # sharing containers can't publish), and it maps host.docker.internal so
    # `roo fwd` can resolve the host's IP through it (--add-host is rejected on
    # the netns-sharing side). Both are fixed at creation — Docker can't add them
    # to a running container — so they're always present, not added lazily.
    subprocess.run(
        ["docker", "run", "-d", "--name", VPN_CONTAINER,
         "--cap-add=NET_ADMIN", "--device", "/dev/net/tun",
         "-p", f"127.0.0.1:{SOCKS_PORT}:1080",
         "--add-host", "host.docker.internal:host-gateway",
         *_bind(config.parent, "/vpn", readonly=True), "-w", "/vpn",
         ref, "--config", config.name],
        stdout=subprocess.DEVNULL, check=True)

    addr = ""
    for _ in range(20):
        if not _vpn_running():
            err("sidecar exited — config or credentials likely wrong. Logs:")
            subprocess.run(["docker", "logs", "--tail", "20", VPN_CONTAINER])
            sys.exit(1)
        addr = _tun_addr()
        if addr:
            break
        time.sleep(1)
    if not addr:
        die(f"tunnel did not come up within 20s. Check: docker logs {VPN_CONTAINER}")
    ok(f"VPN up — tunnel address {addr}  (your LHOST for reverse shells)")
    info(f"scan over it:   ROO_NET=container:{VPN_CONTAINER} roo run <tool> ...")
    info("host probes:    roo proxy up   (browser/Burp/curl via SOCKS)")
    info("catch shells:   roo shell      (listeners/hosting at the tunnel IP)")


# --- subcommands: proxy / shell / ip / fwd (sidecar as your box on the net) --
# The sidecar owns the tunnel IP, so it is effectively the tester's host on the
# engagement network. These verbs give that host two faces and an escape hatch:
#   proxy  — egress: outbound host tools reach the target through the tunnel.
#   shell  — ingress: listeners/hosting bind the tunnel IP (reverse shells).
#   fwd    — bridge a tunnel port back to a listener on the real host.
#   ip     — print the tunnel IP (your LHOST).
def _require_vpn(what):
    if not _vpn_running():
        die(f"{what} needs the VPN sidecar — it owns the tunnel. Start it: roo vpn up")


def _sidecar_iface_ip(iface):
    """IPv4 on a named interface inside the sidecar netns (e.g. eth0, tun0)."""
    r = subprocess.run(["docker", "exec", VPN_CONTAINER, "ip", "-4", "-o", "addr", "show", iface],
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", r.stdout)
    return m.group(1) if m else ""


def _host_gateway_ip():
    """IPv4 of the real host as seen from inside the tunnel namespace.

    `roo fwd` needs this so a socat *tool* container (which can't use --add-host
    under --network container:) can reach a host listener by literal IP. We
    resolve it from the sidecar, which carries host.docker.internal via
    --add-host host-gateway (Desktop also injects it). Fall back to the sidecar's
    default route (the bridge gateway) on platforms without that name.
    """
    r = subprocess.run(["docker", "exec", VPN_CONTAINER,
                        "getent", "ahostsv4", "host.docker.internal"],
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    m = re.search(r"^(\d+\.\d+\.\d+\.\d+)", r.stdout)
    if m:
        return m.group(1)
    r = subprocess.run(["docker", "exec", VPN_CONTAINER, "ip", "route"],
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    m = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", r.stdout)
    return m.group(1) if m else ""


def _sidecar_publishes_socks():
    """True if the running sidecar exposes the in-namespace SOCKS port (1080/tcp).

    Published ports are fixed at container creation, so a sidecar started before
    this was added (or with a different ROO_SOCKS_PORT) won't carry it — the proxy
    would start but be unreachable from the host. Detect that and tell the user to
    cycle the tunnel rather than fail silently.
    """
    r = subprocess.run(["docker", "inspect", "-f",
                        "{{json .NetworkSettings.Ports}}", VPN_CONTAINER],
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    return '"1080/tcp"' in r.stdout and "HostPort" in r.stdout


def cmd_ip(args):
    """Print the tunnel IP (your LHOST), unadorned for scripting."""
    require_docker()
    _require_vpn("roo ip")
    addr = _tun_addr()
    if not addr:
        die("sidecar is up but tun0 has no address yet")
    print(addr)


def _proxy_running():
    r = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", PROXY_CONTAINER],
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    return r.stdout.strip() == "true"


def _proxy_up():
    """Start the SOCKS5 egress proxy in the tunnel namespace. Idempotent-ish:
    re-creates the container. Used by `roo proxy up` and `roo browser`."""
    _require_vpn("roo proxy")
    if not _sidecar_publishes_socks():
        die("the running sidecar doesn't publish the SOCKS port — cycle the tunnel "
            "to pick it up:  roo vpn down && roo vpn up")
    ref = ensure_image("net-toolbox")
    # Bind microsocks to the sidecar's *bridge* IP, not tun0: the host reaches it
    # via the published port (DNAT'd to this IP), while a box on the VPN cannot
    # hit tun0:1080 and abuse us as an open pivot. Fall back to 0.0.0.0 only if we
    # can't read the bridge IP (with a warning), never silently.
    bridge_ip = _sidecar_iface_ip("eth0")
    if not bridge_ip:
        err("could not read the sidecar bridge IP; binding 0.0.0.0 (also exposes "
            "the proxy on the tunnel IP — a VPN peer could use it). Investigate if unexpected.")
        bridge_ip = "0.0.0.0"
    subprocess.run(["docker", "rm", "-f", PROXY_CONTAINER],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Mount ./hosts as /etc/hosts so microsocks' remote DNS resolves lab names
    # (box.htb, etc.) — the browser/curl point Chrome-style remote DNS at this
    # proxy, and without the overrides a VPN-only vhost would never resolve.
    subprocess.run(
        ["docker", "run", "-d", "--name", PROXY_CONTAINER,
         "--network", f"container:{VPN_CONTAINER}", *_hosts_mount(), ref,
         "microsocks", "-i", bridge_ip, "-p", "1080"],
        stdout=subprocess.DEVNULL, check=True)
    # A ready-to-use proxychains config for host/container tools that want it.
    gen_dir = Path(".roo")
    gen_dir.mkdir(exist_ok=True)
    pc = gen_dir / "proxychains.conf"
    pc.write_text("strict_chain\nproxy_dns\n[ProxyList]\n"
                  f"socks5 127.0.0.1 {SOCKS_PORT}\n")
    return pc


def cmd_proxy(args):
    """SOCKS5 egress so host tools reach the target through the tunnel."""
    require_docker()
    if args.action == "status":
        ok(f"SOCKS proxy running — host 127.0.0.1:{SOCKS_PORT}") if _proxy_running() else \
            info("SOCKS proxy is not running (roo proxy up)")
        return
    if args.action == "down":
        r = subprocess.run(["docker", "rm", "-f", PROXY_CONTAINER],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ok("SOCKS proxy stopped") if r.returncode == 0 else info("no SOCKS proxy running")
        return
    pc = _proxy_up()
    ok(f"SOCKS proxy up — host 127.0.0.1:{SOCKS_PORT}")
    info(f"  curl:        curl --socks5h 127.0.0.1:{SOCKS_PORT} http://<target>/")
    info(f"  proxychains: proxychains -f {pc} <tool> <target>")
    info(f"  browser/Burp: SOCKS5 host 127.0.0.1 port {SOCKS_PORT} (remote DNS)")
    info("note: TCP-connect only — raw -sS/-sU scans must run as roo containers")


# --- subcommand: browser (host browser, VPN-proxied, agent-instrumentable) --
# A Chromium-family browser on the *host* (so you get a native GUI to drive),
# pointed at the SOCKS proxy (so it egresses through the tunnel with remote DNS)
# and started with a CDP debugging port so the agent can attach via the Playwright
# MCP (.mcp.json) and drive the same browser when you ask. Companion workflow:
# you browse; the agent taps in. The browser is the one host exception to
# "everything in a container" — a GUI you interact with can't live in a netns.
_BROWSER_CANDIDATES = {
    "win32": [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
        "chrome", "msedge",
    ],
    "darwin": [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Chromium.app/Contents/MacOS/Chromium",
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
    ],
    "linux": ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser",
              "brave-browser", "microsoft-edge", "microsoft-edge-stable"],
}


def _find_browser(explicit):
    if explicit:
        cands = [explicit]
    elif os.environ.get("ROO_BROWSER"):
        cands = [os.environ["ROO_BROWSER"]]
    else:
        key = ("win32" if sys.platform.startswith("win")
               else "darwin" if sys.platform == "darwin" else "linux")
        cands = _BROWSER_CANDIDATES[key]
    for c in cands:
        hit = shutil.which(c) or (c if Path(c).is_file() else None)
        if hit:
            return hit
    return None


def _shlex_join(parts):
    out = []
    for p in parts:
        out.append(f'"{p}"' if (" " in p or "\\" in p) else p)
    return " ".join(out)


def _spawn_detached(cmd):
    """Launch a GUI process detached from roo so it outlives this CLI call."""
    if sys.platform.startswith("win"):
        DETACHED = 0x00000008  # DETACHED_PROCESS — don't tie the browser to roo
        subprocess.Popen(cmd, creationflags=DETACHED, close_fds=True)
    else:
        subprocess.Popen(cmd, start_new_session=True,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def cmd_browser(args):
    """Launch a host browser, VPN-proxied and CDP-instrumentable by the agent."""
    require_docker()
    browser = _find_browser(args.browser)
    if not browser:
        die("no Chromium-family browser found. Install Chrome/Chromium/Edge/Brave, "
            "pass --browser <path>, or set $ROO_BROWSER.")
    proxy_flags = []
    if not args.no_proxy:
        _require_vpn("roo browser (proxied)")
        if not args.dry_run and not _proxy_running():
            info("SOCKS proxy not up — starting it")
            _proxy_up()
        proxy_flags = [f"--proxy-server=socks5://127.0.0.1:{SOCKS_PORT}"]
    profile = (Path(".roo") / "browser-profile").resolve()
    profile.mkdir(parents=True, exist_ok=True)
    cdp = str(args.cdp_port)
    cmd = [browser,
           f"--user-data-dir={profile}",
           f"--remote-debugging-port={cdp}",
           "--remote-allow-origins=*",          # let the CDP/MCP client attach (Chrome >111)
           "--no-first-run", "--no-default-browser-check",
           *proxy_flags]
    if args.url:
        cmd.append(args.url)

    info(f"browser: {browser}")
    info(f"profile: {profile}  (persistent, git-ignored)")
    if proxy_flags:
        info(f"proxy:   socks5://127.0.0.1:{SOCKS_PORT}  (through the VPN tunnel, remote DNS)")
    else:
        err("--no-proxy: browsing DIRECT, not through the VPN tunnel")
    info(f"CDP:     http://127.0.0.1:{cdp}  ← agent attaches here (Playwright MCP)")
    if args.dry_run:
        ok("dry run — would launch:")
        print(_shlex_join(cmd))
        return
    try:
        _spawn_detached(cmd)
    except OSError as e:
        die(f"failed to launch browser: {e}")
    ok(f"browser launched — CDP on http://127.0.0.1:{cdp}")
    info("agent control: enable the `playwright` server in .mcp.json (it attaches over "
         "CDP), then ask the agent to drive. See the browse skill.")


# --- host tool: hashcat (GPU cracking) --------------------------------------
# Cracking is the one task that genuinely wants the host GPU, so — like the
# browser — hashcat runs on the *host*, a deliberate exception to the container
# rule (containers here are CPU-only and GPU passthrough on Windows is painful,
# so a host binary is strictly faster). `roo hashcat …` proxies straight to the
# system hashcat, bootstrapping it on first use: apt on Linux, brew on macOS, the
# official portable .7z on Windows (cached under .roo/hashcat). Hashes and roasts
# already live under recon-results on the host, so relative paths pass through.
HASHCAT_VERSION = "7.1.2"
HASHCAT_WIN_URL = f"https://hashcat.net/files/hashcat-{HASHCAT_VERSION}.7z"


def _hashcat_cache():
    return Path(".roo") / "hashcat"


def _find_hashcat():
    env = os.environ.get("ROO_HASHCAT")        # explicit override, like $ROO_BROWSER
    if env:
        return shutil.which(env) or (str(Path(env).resolve()) if Path(env).is_file() else None)
    hit = shutil.which("hashcat")
    if hit:
        return hit
    builds = sorted(_hashcat_cache().glob("hashcat-*/hashcat.exe"))  # portable win build
    return str(builds[-1]) if builds else None


def _download(url, dest):
    # Emit only on a percent *change* (the reporthook fires per 8 KB block, which
    # is thousands of calls); use \r live-update on a TTY, sparse lines otherwise.
    tty = sys.stderr.isatty()
    last = {"pct": -1}
    def hook(blocks, bs, total):
        if total <= 0:
            return
        pct = min(100, blocks * bs * 100 // total)
        if pct == last["pct"]:
            return
        last["pct"] = pct
        if tty:
            sys.stderr.write(f"\r    downloading… {pct:3d}%")
            sys.stderr.flush()
        elif pct % 10 == 0:
            sys.stderr.write(f"    downloading… {pct}%\n")
    urllib.request.urlretrieve(url, str(dest), hook)
    if tty:
        sys.stderr.write("\r" + " " * 24 + "\r")
        sys.stderr.flush()


def _extract_7z(archive, dest):
    for tool in ("7z", "7za", "7zr"):          # a real 7-Zip if one's installed
        if shutil.which(tool) and subprocess.run(
                [tool, "x", "-y", f"-o{dest}", str(archive)],
                stdout=subprocess.DEVNULL).returncode == 0:
            return True
    # Windows 10/11 ship bsdtar as `tar`; libarchive reads the 7zip format.
    if shutil.which("tar") and subprocess.run(
            ["tar", "-xf", str(archive), "-C", str(dest)]).returncode == 0:
        return True
    return False


def _install_hashcat():
    if sys.platform.startswith("win"):
        dest = _hashcat_cache()
        dest.mkdir(parents=True, exist_ok=True)
        archive = dest / f"hashcat-{HASHCAT_VERSION}.7z"
        if not archive.is_file():
            info(f"fetching hashcat {HASHCAT_VERSION} ({HASHCAT_WIN_URL})")
            try:
                _download(HASHCAT_WIN_URL, archive)
            except (urllib.error.URLError, OSError) as e:
                die(f"download failed: {e}")
        info("extracting the portable build")
        if not _extract_7z(archive, dest):
            die("couldn't extract the .7z — install 7-Zip (https://7-zip.org) or "
                f"unpack it into {dest} yourself, then re-run.")
        return _find_hashcat()
    if sys.platform == "darwin":
        if not shutil.which("brew"):
            die("Homebrew not found — install it (https://brew.sh) then re-run, "
                "or install hashcat by hand.")
        subprocess.run(["brew", "install", "hashcat"])
        return _find_hashcat()
    # linux
    apt = shutil.which("apt-get") or shutil.which("apt")
    if not apt:
        die("no apt found. Install hashcat with your package manager "
            "(dnf/pacman/zypper) or from https://hashcat.net, then re-run.")
    cmd = [apt, "install", "-y", "hashcat"]
    if hasattr(os, "geteuid") and os.geteuid() != 0 and shutil.which("sudo"):
        cmd = ["sudo"] + cmd
    subprocess.run(cmd)
    return _find_hashcat()


def cmd_hashcat(args):
    """Run the host's hashcat for GPU cracking (bootstrap it on first use)."""
    hc = _find_hashcat()
    if not hc:
        info("hashcat not on PATH — bootstrapping for this platform (one-time)")
        hc = _install_hashcat()
    if not hc:
        die("hashcat still not found after the install attempt")
    info(f"hashcat: {hc}")
    hc_path = Path(hc)
    rest = list(args.args or []) or ["--version"]
    # The portable Windows build resolves ./OpenCL/ (its kernels) relative to the
    # *cwd*, not the binary — so it must run from its own folder. To keep the
    # user's relative hash/wordlist paths valid across that cd, absolutize any arg
    # that exists relative to the original cwd. Args that DON'T exist there are
    # left alone, so the build's own relative assets still resolve from its dir
    # (e.g. `-r rules/best64.rule`). A not-yet-existing outfile lands in the
    # hashcat dir; pass an absolute path or read results back with `--show`.
    cwd = None
    if _hashcat_cache().resolve() in hc_path.resolve().parents:
        cwd = str(hc_path.parent)
        base = Path.cwd()
        rest = [str((base / a).resolve())
                if (not a.startswith("-") and Path(a).exists())
                else a
                for a in rest]
    try:
        r = subprocess.run([str(hc_path)] + rest, cwd=cwd)
    except OSError as e:
        die(f"failed to exec hashcat: {e}")
    sys.exit(r.returncode)


# --- host helper: wordlists (feed the host cracker) -------------------------
# SecLists password lists, fetched on demand to .roo/wordlists (gitignored) so
# `roo hashcat` has fuel. rockyou is the default; .tar.gz lists are unpacked with
# the stdlib tarfile. Accepts a known alias or any SecLists Passwords-relative
# path (e.g. "Leaked-Databases/rockyou.txt.tar.gz"). The resolved local path is
# printed to stdout (only that line) so a skill/script can capture it.
SECLISTS_RAW = os.environ.get(
    "ROO_SECLISTS_RAW",
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords")
WORDLISTS = {
    "rockyou": "Leaked-Databases/rockyou.txt.tar.gz",
    "darkweb2017-top10000": "darkweb2017-top10000.txt",
    "xato-1m": "xato-net-10-million-passwords-1000000.txt",
    "top-1m": "Common-Credentials/10-million-password-list-top-1000000.txt",
}


def _wordlist_cache():
    return Path(".roo") / "wordlists"


def cmd_wordlist(args):
    """Fetch (and cache) a SecLists password wordlist for the host cracker."""
    if args.list:
        info("known aliases (or pass any SecLists Passwords-relative path):")
        for k, v in WORDLISTS.items():
            print(f"  {k:22s} {v}")
        return
    name = args.name or "rockyou"
    rel = WORDLISTS.get(name, name)                 # alias → path, else treat as a path
    fname = rel.split("/")[-1]
    txt = fname[:-7] if fname.endswith(".tar.gz") else fname   # rockyou.txt.tar.gz → rockyou.txt
    cache = _wordlist_cache()
    cache.mkdir(parents=True, exist_ok=True)
    out = cache / txt
    if out.is_file() and out.stat().st_size > 0:
        info(f"wordlist cached: {out.resolve()}  ({out.stat().st_size // (1024*1024)} MB)")
        print(str(out.resolve()))
        return
    url = f"{SECLISTS_RAW}/{rel}"
    info(f"fetching wordlist '{name}' ({url})")
    tmp = cache / fname
    try:
        _download(url, tmp)
    except (urllib.error.URLError, OSError) as e:
        die(f"download failed: {e} — check the name (`roo wordlist --list`) or the path")
    if fname.endswith(".tar.gz"):
        info("unpacking .tar.gz")
        try:
            with tarfile.open(tmp) as tf:
                member = next((m for m in tf.getmembers()
                               if m.isfile() and m.name.endswith(".txt")), None)
                if member is None:
                    die("no .txt member inside the archive")
                with tf.extractfile(member) as src, open(out, "wb") as dst:
                    shutil.copyfileobj(src, dst)
        finally:
            tmp.unlink(missing_ok=True)
    else:
        tmp.replace(out)
    info(f"wordlist ready: {out.resolve()}  ({out.stat().st_size // (1024*1024)} MB)")
    print(str(out.resolve()))


# --- prebuilt Windows tooling: Forge → the shared /tools volume ---------------
# Forge (forgenet.pages.dev, ForgeNet21AR/forge) serves prebuilt .NET offensive
# tools (GhostPack/Rubeus, SharpHound, Certify, …). We list/resolve metadata
# host-side over the *public internet* (JSON only — never a binary on the host,
# and never the VPN), then download + unpack the bundle *inside* a container into
# the `roorecon-tools` volume, so the .exe lands in the Docker VM, not on a host
# path your EDR scans. Every `roo shell` sees them at /tools.
FORGE_BASE = os.environ.get("ROO_FORGE_BASE", "https://forgenet.pages.dev")


def _forge_releases():
    url = f"{FORGE_BASE}/api/releases"
    # Cloudflare 403s the default Python-urllib UA, so present a browser-ish one.
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) roo/1.0",
        "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.load(r).get("releases", [])
    except (urllib.error.URLError, OSError, ValueError) as e:
        die(f"could not reach Forge ({url}): {e}")


def _forge_group(rels):
    """Group releases by tool name (tag = tool/<name>/<commit>)."""
    g = {}
    for rel in rels:
        parts = rel.get("tag", "").split("/")
        if len(parts) >= 3 and parts[0] == "tool":
            g.setdefault(parts[1], []).append(rel)
    return g


def _forge_commit(rel):
    return rel.get("tag", "").split("/")[-1]


def _forge_label(rel):
    # name is "<tool> - <version-or-commit>"; take the part after the last " - ".
    return rel.get("name", "").rsplit(" - ", 1)[-1].strip()


def _forge_is_main(rel):
    """True if this build came off the default branch (no upstream release tag).

    Forge labels a build by its resolved version/tag; with no tag it falls back to
    the commit hash — so label == the tag's commit ⇒ a branch/main build. We prefer
    those: tools like Rubeus tag releases years apart, so the tagged build is stale
    (e.g. no BetterSuccessor) while the main build tracks current capability.
    """
    lbl = _forge_label(rel).lower()
    return bool(lbl) and lbl == _forge_commit(rel).lower()


def _forge_desc(rel):
    return f"main @{_forge_commit(rel)}" if _forge_is_main(rel) else f"release {_forge_label(rel)}"


def _forge_select(builds, ref=None, release=False):
    """Pick one build: an explicit ref, else newest main build, else newest tagged.

    Default prefers a main/branch build; --release forces the newest tagged build;
    --ref pins by commit-prefix or version label.
    """
    if ref:
        rl = ref.lower()
        return next((b for b in builds
                     if rl == _forge_label(b).lower()
                     or _forge_commit(b).lower().startswith(rl)), None)
    mains = [b for b in builds if _forge_is_main(b)]
    tags = [b for b in builds if not _forge_is_main(b)]
    pool = (tags or builds) if release else (mains or builds)
    return max(pool, key=lambda b: b.get("published_at", ""), default=None)


def cmd_tools(args):
    """Fetch prebuilt Windows tools from Forge into the shared, off-host /tools volume."""
    require_docker()
    action = args.action
    if action in ("list", "builds"):
        groups = _forge_group(_forge_releases())
        if action == "list":
            flt = (args.name or "").lower()
            info(f"Forge packages ({FORGE_BASE}) — `roo tools get <name>` pulls ★ (the default):")
            for nm in sorted(groups):
                if flt and flt not in nm.lower():
                    continue
                sel = _forge_select(groups[nm])
                extra = f"  (+{len(groups[nm]) - 1} more — `roo tools builds {nm}`)" if len(groups[nm]) > 1 else ""
                print(f"  {nm:24s} ★ {_forge_desc(sel)}{extra}")
            return
        if not args.name:
            die("usage: roo tools builds <name>")
        key = next((k for k in groups if k.lower() == args.name.lower()), None)
        if key is None:
            die(f"no Forge package named '{args.name}' — try `roo tools list {args.name}`")
        default = _forge_select(groups[key])
        info(f"{key} builds (newest first) — ★ = default; pin with `roo tools get {key} --ref <commit|version>`:")
        for b in sorted(groups[key], key=lambda x: x.get("published_at", ""), reverse=True):
            star = "★" if b is default else " "
            kind = "main" if _forge_is_main(b) else "rel "
            print(f"  {star} [{kind}] {_forge_label(b):16s} commit {_forge_commit(b)}  {b.get('published_at', '')}")
        return
    img = ensure_image("net-toolbox")
    if action == "installed":
        subprocess.run(["docker", "run", "--rm"] + _tools_mount() + [img,
                        "sh", "-c", "ls -la /tools 2>/dev/null || echo '(nothing installed yet)'"])
        return
    if action == "rm":
        if not args.name:
            die("usage: roo tools rm <name>")
        subprocess.run(["docker", "run", "--rm"] + _tools_mount() + [img,
                        "sh", "-c", f"rm -rf /tools/{shlex.quote(args.name.lower())}"])
        ok(f"removed /tools/{args.name.lower()}")
        return
    # get
    if not args.name:
        die("usage: roo tools get <name>   (see `roo tools list`)")
    groups = _forge_group(_forge_releases())
    key = next((k for k in groups if k.lower() == args.name.lower()), None)
    if key is None:
        die(f"no Forge package named '{args.name}' — try `roo tools list {args.name}`")
    builds = groups[key]
    rel = _forge_select(builds, ref=args.ref, release=args.release)
    if rel is None:
        die(f"no build of {key} matches --ref '{args.ref}' — see `roo tools builds {key}`")
    bundle = next((a["name"] for a in rel.get("assets", []) if a["name"].endswith("_bundle.zip")), None)
    if not bundle:
        die(f"'{key}' build {_forge_desc(rel)} has no _bundle.zip asset")
    url = (f"{FORGE_BASE}/api/releases/asset"
           f"?tag={urllib.parse.quote(rel['tag'], safe='')}&name={urllib.parse.quote(bundle, safe='')}")
    dest = f"/tools/{key.lower()}"
    info(f"selected {key}: {_forge_desc(rel)}  (built {rel.get('published_at', '?')}) → {dest}")
    if not args.ref and len(builds) > 1:
        force = "the newest tagged release with --release" if _forge_is_main(rel) else "a main build with --ref <commit>"
        info(f"  {len(builds) - 1} other build(s) — `roo tools builds {key}` (force {force})")
    info("egress: public internet (NOT the VPN); unpacks inside the container → the Docker volume, not your host")
    script = (
        f"set -e; rm -rf {dest}; mkdir -p {dest}; "
        f"curl -fSL {shlex.quote(url)} -o /tmp/forge.zip; "
        f"unzip -o /tmp/forge.zip -d {dest} >/dev/null; rm -f /tmp/forge.zip; "
        f"echo '--- contents ---'; ls -R {dest} | head -40"
    )
    r = subprocess.run(["docker", "run", "--rm"] + _tools_mount() + [img, "sh", "-c", script])
    if r.returncode != 0:
        die("download/unpack failed")
    ok(f"{key} ({_forge_desc(rel)}) ready at {dest} — shared across every `roo shell`, in the Docker volume (not on the host)")


def cmd_shell(args):
    """Interactive operator shell in the tunnel namespace (/work mounted)."""
    require_docker()
    _require_vpn("roo shell")
    ref = ensure_image("net-toolbox")
    cmd_args = args.args or []
    interactive = not cmd_args and sys.stdin.isatty() and sys.stdout.isatty()
    if not cmd_args:
        addr = _tun_addr()
        info(f"toolbox in the tunnel namespace — LHOST is {addr}, /work is your cwd")
        info("  reverse shell:  rlwrap ncat -lvnp 4444   (rlwrap = arrows/history)")
        info("  host a file:    python3 -m http.server 8000")
        info("  AD enum:        nxc smb|ldap|winrm <t> -u U -p P [--shares|--bloodhound]")
        info("  AD CS / shell:  certipy find -u U@dom -p P -dc-ip <t>  ·  evil-winrm -i <t> -u U -p P")
        info("  ad-hoc clients: smbclient // ldapsearch // dig // bloodyAD")
        info("  Kerberos skew:  clocksync <dc-ip>   (syncs this shell's clock to the DC; clocksync --off)")
    cmd = ["docker", "run", "--rm"]
    if interactive:
        cmd.append("-it")
    # Preload libfaketime so `clocksync <dc>` can put the whole shell on the DC's
    # clock (beats KRB_AP_ERR_SKEW) without CAP_SYS_TIME or touching the host clock
    # — a container can't own a real wall clock (CLOCK_REALTIME isn't namespaced).
    # The timestamp file lives in the container's ephemeral /tmp, so each shell
    # starts on real time and you re-sync per session; no offset = libfaketime no-op.
    LIBFAKETIME = "/usr/lib/x86_64-linux-gnu/faketime/libfaketimeMT.so.1"
    cmd += (["--network", f"container:{VPN_CONTAINER}",
             "-e", f"LD_PRELOAD={LIBFAKETIME}",
             "-e", "FAKETIME_TIMESTAMP_FILE=/tmp/.roo-faketime"]
            + _hosts_mount() + _home_mount() + _work_mount() + _tools_mount()
            + [ref] + list(cmd_args))
    r = subprocess.run(cmd)
    sys.exit(r.returncode)


def cmd_responder(args):
    """Run Responder in the tunnel namespace: LLMNR/NBT-NS/mDNS poisoning + capture.

    A namespace listener like `shell` — it binds the *tunnel* interface (tun0) so
    it poisons name resolution on the engagement LAN and captures NetNTLMv1/v2 from
    whoever answers. Captures stream to the console and persist to
    recon-results/responder/ (mounted over its logs/). Defaults to `-I tun0`; pass
    any extra Responder flags (e.g. -A to analyze passively, -wF for WPAD).
    """
    require_docker()
    _require_vpn("roo responder")
    ref = ensure_image("net-toolbox")
    extra = list(args.args or [])
    if not any(a in ("-I", "--interface") for a in extra):
        extra = ["-I", "tun0"] + extra          # default to the tunnel iface
    loot = Path("recon-results") / "responder"
    loot.mkdir(parents=True, exist_ok=True)
    cmd = ["docker", "run", "--rm"]
    if sys.stdin.isatty() and sys.stdout.isatty():
        cmd.append("-it")
    # Raw sockets for the poisoners/analyze, like the scanners get; root in the
    # container already owns the privileged rogue-server ports (137/445/80/53…).
    cmd += ["--network", f"container:{VPN_CONTAINER}",
            "--cap-add=NET_RAW", "--cap-add=NET_ADMIN"]
    cmd += _bind(loot, "/opt/Responder/logs")
    cmd += _hosts_mount() + _work_mount() + [ref, "responder"] + extra
    info(f"Responder in the tunnel namespace — captures stream below, persist to {loot}/")
    info("poisons LLMNR/NBT-NS/mDNS + rogue SMB/HTTP/…; Ctrl-C to stop")
    info("captured NetNTLMv1/v2 → crack with the hashcat skill (relay is dead when SMB signing is enforced)")
    r = subprocess.run(cmd)
    sys.exit(r.returncode)


def cmd_fwd(args):
    """Bridge a tunnel port to a listener on the real host (target -> host)."""
    require_docker()
    _require_vpn("roo fwd")
    port = str(args.port)
    if not port.isdigit() or not (0 < int(port) < 65536):
        die(f"port must be 1-65535 (got '{port}')", 2)
    # Each forward is one socat in its own net-toolbox container in the tunnel
    # namespace, named so we can stop it by removing the container — no tools in
    # the sidecar, no pkill. (A tool container can't use --add-host, so we hand
    # socat the host's literal IPv4 instead of the host.docker.internal name.)
    name = f"roo-fwd-{port}"
    if args.stop:
        r = subprocess.run(["docker", "rm", "-f", name],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ok(f"forward on tunnel :{port} stopped") if r.returncode == 0 else \
            info(f"no forward running on :{port}")
        return
    tun_ip = _tun_addr()
    if not tun_ip:
        die("sidecar is up but tun0 has no address yet")
    gw_ip = _host_gateway_ip()
    if not gw_ip:
        die("could not resolve the host gateway from the sidecar; can't forward")
    ref = ensure_image("net-toolbox")
    subprocess.run(["docker", "rm", "-f", name],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    # Bind to the tunnel IP only, so the forward accepts solely from the VPN side;
    # TCP4 to the host's literal IPv4 (host.docker.internal can resolve v6-only).
    listen = f"TCP-LISTEN:{port},bind={tun_ip},fork,reuseaddr"
    dest = f"TCP4:{gw_ip}:{port}"
    subprocess.run(
        ["docker", "run", "-d", "--rm", "--name", name,
         "--network", f"container:{VPN_CONTAINER}", ref, "socat", listen, dest],
        stdout=subprocess.DEVNULL, check=True)
    ok(f"forwarding tunnel {tun_ip}:{port} → host 127.0.0.1:{port}")
    info(f"  start your host listener first, e.g.:  nc -lvnp {port}")
    info(f"  set the target's callback to {tun_ip}:{port}")
    info(f"  stop it with:  roo fwd {port} --stop")


# --- subcommand: bloodhound (LOCAL CE analysis stack — the compose exception) --
# BloodHound CE is a 3-service stack (postgres + neo4j + the BloodHound API/web),
# not a per-tool image — and it is a *local analysis platform*, never target-facing.
# It ingests static collection zips and renders the graph for the operator, so
# unlike every other tool it does NOT join the VPN namespace: it runs on the docker
# host and you view it at 127.0.0.1:8080. `roo` just automates the tedium — bring
# the stack up, seed a known admin (in the compose env), ingest a zip over the REST
# API, open the browser. See ARCHITECTURE.md ("local analysis platform" exception).
BH_COMPOSE = DOCKER_DIR / "bloodhound" / "docker-compose.yml"
BH_PROJECT = "roorecon-bloodhound"
BH_URL = "http://127.0.0.1:8080"
# Must match the compose defaults (bhe_default_admin_*) so the API login works.
BH_ADMIN_USER = os.environ.get("BHE_ADMIN_USER", "admin")
BH_ADMIN_PASS = os.environ.get("BHE_ADMIN_PASS", "BloodHoundRoo!2026")


def _require_compose():
    if subprocess.run(["docker", "compose", "version"],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
        die("`docker compose` (v2) not found — needed for the BloodHound CE stack. "
            "Update Docker Desktop or install the compose plugin.")


def _compose(*args, check=True):
    cmd = ["docker", "compose", "-p", BH_PROJECT, "-f", str(BH_COMPOSE), *args]
    r = subprocess.run(cmd)
    if check and r.returncode != 0:
        die(f"`docker compose {' '.join(args)}` failed ({r.returncode})")
    return r


def _bh_http(method, path, token=None, data=None, body=None, ctype=None, timeout=30):
    """Minimal HTTP to the BloodHound API. Returns (status, bytes); never raises on
    an HTTP error status (returns it) — only on a transport failure."""
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    payload = None
    if data is not None:                       # JSON body
        payload = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    elif body is not None:                     # raw bytes body (a collection file)
        payload = body
        headers["Content-Type"] = ctype or "application/octet-stream"
    req = urllib.request.Request(BH_URL + path, data=payload, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _bh_running():
    r = subprocess.run(["docker", "compose", "-p", BH_PROJECT, "-f", str(BH_COMPOSE),
                        "ps", "-q", "bloodhound"],
                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    return bool(r.stdout.strip())


def _bh_ready():
    """True once the web API answers (any HTTP status = up; refused = not yet)."""
    try:
        with urllib.request.urlopen(BH_URL + "/api/version", timeout=5):
            return True
    except urllib.error.HTTPError:
        return True            # answered (e.g. 401) → server is up
    except (urllib.error.URLError, OSError):
        return False


def _bh_wait_ready(timeout=180):
    info("waiting for the BloodHound API to come up…")
    for _ in range(max(1, timeout // 3)):
        if _bh_ready():
            return True
        time.sleep(3)
    return _bh_ready()


def _bh_login():
    status, raw = _bh_http("POST", "/api/v2/login",
                           data={"login_method": "secret",
                                 "username": BH_ADMIN_USER, "secret": BH_ADMIN_PASS})
    if status != 200:
        die(f"BloodHound login failed ({status}) as {BH_ADMIN_USER}. If you changed "
            f"the admin password, set $BHE_ADMIN_PASS. Body: {raw[:200]!r}")
    token = json.loads(raw or b"{}").get("data", {}).get("session_token")
    if not token:
        die("BloodHound login returned no session token")
    return token


def _bh_ingest(token, zip_path):
    p = Path(zip_path)
    if not p.is_file():
        die(f"collection file not found: {zip_path}")
    ctype = "application/zip" if p.suffix.lower() == ".zip" else "application/json"
    status, raw = _bh_http("POST", "/api/v2/file-upload/start", token=token)
    if status not in (200, 201):
        die(f"could not start the upload job ({status}): {raw[:200]!r}")
    job = json.loads(raw)["data"]["id"]
    info(f"upload job {job} — sending {p.name} ({p.stat().st_size} bytes)…")
    status, raw = _bh_http("POST", f"/api/v2/file-upload/{job}", token=token,
                           body=p.read_bytes(), ctype=ctype, timeout=300)
    if status not in (200, 202):
        die(f"file upload failed ({status}): {raw[:200]!r}")
    status, raw = _bh_http("POST", f"/api/v2/file-upload/{job}/end", token=token)
    if status not in (200, 201):
        die(f"could not finalize the upload job ({status}): {raw[:200]!r}")
    ok(f"ingested {p.name} (job {job}) — BloodHound is processing + analysing it now")


def _bh_open():
    browser = _find_browser(None)
    if not browser:
        info(f"open {BH_URL} in your browser  (login {BH_ADMIN_USER} / {BH_ADMIN_PASS})")
        return
    profile = (Path(".roo") / "bloodhound-profile").resolve()
    profile.mkdir(parents=True, exist_ok=True)
    # Local stack → NO VPN proxy (unlike `roo browser`). A CDP port is still opened
    # so the agent can attach via the Playwright MCP and run queries/screenshots.
    cmd = [browser, f"--user-data-dir={profile}", "--no-first-run",
           "--no-default-browser-check", "--remote-debugging-port=9222",
           "--remote-allow-origins=*", BH_URL]
    try:
        _spawn_detached(cmd)
    except OSError as e:
        die(f"failed to launch browser: {e}")
    ok(f"browser → {BH_URL}  (login {BH_ADMIN_USER} / {BH_ADMIN_PASS})")


def cmd_bloodhound(args):
    """Local BloodHound CE: bring the stack up, ingest a collection, view the graph."""
    require_docker()
    if not BH_COMPOSE.is_file():
        die(f"compose file missing: {BH_COMPOSE}")
    _require_compose()

    if args.action == "down":
        info("stopping the BloodHound CE stack…")
        _compose("down", *(["-v"] if args.wipe else []), check=False)
        ok("BloodHound CE stopped" + (" + data volumes wiped" if args.wipe else ""))
        return

    if args.action == "status":
        if _bh_running() and _bh_ready():
            ok(f"BloodHound CE up — {BH_URL}  (login {BH_ADMIN_USER} / {BH_ADMIN_PASS})")
        elif _bh_running():
            info("stack containers are up but the API isn't ready yet")
        else:
            info("BloodHound CE is not running  (roo bloodhound up)")
        return

    if args.action == "open":
        if not _bh_ready():
            die("BloodHound isn't up — run `roo bloodhound up` first")
        _bh_open()
        return

    # up | ingest | view → ensure the stack is running and ready
    if not _bh_running():
        info("starting BloodHound CE (first run pulls ~2 GB: postgres + neo4j + bloodhound)…")
        _compose("up", "-d")
    if not _bh_wait_ready():
        die(f"BloodHound API did not come up. Check: docker compose -p {BH_PROJECT} "
            f"-f {BH_COMPOSE} logs")
    ok(f"BloodHound CE up — {BH_URL}  (login {BH_ADMIN_USER} / {BH_ADMIN_PASS})")

    if args.action in ("ingest", "view"):
        if not args.zip:
            die(f"`roo bloodhound {args.action}` needs a collection zip/json path")
        _bh_ingest(_bh_login(), args.zip)
    if args.action == "view":
        _bh_open()
    elif args.action == "up":
        info("next:  roo bloodhound ingest <zip>   ·   open the UI:  roo bloodhound open")


# --- CLI --------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(prog="roo", description="RooRecon containerized tooling CLI.")
    sub = p.add_subparsers(dest="cmd", required=True)

    pr = sub.add_parser("run", help="run a CLI in its container")
    pr.add_argument("tool")
    pr.add_argument("args", nargs=argparse.REMAINDER)
    pr.set_defaults(func=cmd_run)

    for name, fn in (("sweep", cmd_sweep), ("recon", cmd_recon)):
        sp = sub.add_parser(name, help=fn.__doc__)
        sp.add_argument("target")
        sp.add_argument("--out", default="recon-results", help="results base dir")
        sp.set_defaults(func=fn)

    pb = sub.add_parser("buckaroo", help="per-port enumeration")
    pb.add_argument("target")
    pb.add_argument("proto", choices=["tcp", "udp"])
    pb.add_argument("port")
    pb.add_argument("--out", default="recon-results")
    pb.set_defaults(func=cmd_buckaroo)

    pvh = sub.add_parser("vhost", help="vhost (Host-header) enum for an internal IP")
    pvh.add_argument("target", help="the IP serving the vhosts")
    pvh.add_argument("domain", help="base domain to fuzz, e.g. box.htb")
    pvh.add_argument("--scheme", default="http", choices=["http", "https"])
    pvh.add_argument("--wordlist", help="baked name, /wordlists path, or host file")
    pvh.add_argument("--out", default="recon-results")
    pvh.set_defaults(func=cmd_vhost)

    pdns = sub.add_parser("dns", help="DNS subdomain enum for an external domain")
    pdns.add_argument("domain")
    pdns.add_argument("--wordlist", help="baked name, /wordlists path, or host file")
    pdns.add_argument("--out", default="recon-results")
    pdns.set_defaults(func=cmd_dns)

    pdb = sub.add_parser("dirbust", help="recursive directory/file brute (SecLists)")
    pdb.add_argument("url", help="base URL, e.g. http://box.htb/ or http://box.htb/app/")
    pdb.add_argument("--wordlist", help="baked name (default common.txt), /wordlists path, or host file")
    pdb.add_argument("--depth", type=int, default=2, help="recursion depth (0 = no recursion; default 2)")
    pdb.add_argument("--ext", help="comma-separated extensions to also try, e.g. php,txt,html")
    pdb.add_argument("--threads", type=int, default=40, help="gobuster threads per level")
    pdb.add_argument("--max-dirs", type=int, default=60, dest="max_dirs",
                     help="hard cap on directories scanned (recursion guard)")
    pdb.add_argument("--skip", help="extra dir names to not recurse into (comma-separated; "
                                    "added to the built-in asset/noise list)")
    pdb.add_argument("--out", default="recon-results")
    pdb.set_defaults(func=cmd_dirbust)

    prep = sub.add_parser("report", help="assemble per-port facts + notes into report.md")
    prep.add_argument("target")
    prep.add_argument("--out", default="recon-results")
    prep.add_argument("--template", help="report template path (default templates/report.md "
                                         "or $ROO_REPORT_TEMPLATE)")
    prep.set_defaults(func=cmd_report)

    pvln = sub.add_parser("vulns", help="CVE + public PoC lookup for recon fingerprints (keyless)")
    pvln.add_argument("target", help="recon-results target dir name, or a label for ad-hoc --product")
    pvln.add_argument("--product", help="ad-hoc: product name (bypasses recon dir), e.g. nginx")
    pvln.add_argument("--version", help="ad-hoc: version, e.g. 1.18.0")
    pvln.add_argument("--cpe", help="ad-hoc: explicit CPE, e.g. cpe:/a:openbsd:openssh:8.9p1")
    pvln.add_argument("--port", help="restrict to one port dir, e.g. tcp-80")
    pvln.add_argument("--min-bucket", dest="min_bucket", default="MEDIUM",
                      choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                      help="discover PoCs for CVEs at/above this severity (default MEDIUM)")
    pvln.add_argument("--no-github", dest="no_github", action="store_true",
                      help="skip the GitHub PoC index")
    pvln.add_argument("--no-msf", dest="no_msf", action="store_true",
                      help="skip the Metasploit module lookup")
    pvln.add_argument("--no-searchsploit", dest="no_searchsploit", action="store_true",
                      help="skip the Exploit-DB lookup")
    pvln.add_argument("--refresh", action="store_true", help="bypass the on-disk cache")
    pvln.add_argument("--out", default="recon-results")
    pvln.set_defaults(func=cmd_vulns)

    pfp = sub.add_parser("fingerprint", help="web fingerprint via whatweb (tech + versions)")
    pfp.add_argument("url", help="target URL, e.g. http://box.htb/")
    pfp.add_argument("-a", "--aggression", type=int, default=3, choices=[1, 3, 4],
                     help="whatweb aggression (1 stealthy, 3 default, 4 heavy)")
    pfp.add_argument("--out", default="recon-results")
    pfp.set_defaults(func=cmd_fingerprint)

    pv = sub.add_parser("vpn", help="manage the OpenVPN sidecar")
    pv.add_argument("action", choices=["up", "down", "status"])
    pv.add_argument("config", nargs="?")
    pv.set_defaults(func=cmd_vpn)

    pp = sub.add_parser("proxy", help="SOCKS5 egress for host tools (browser/Burp/curl)")
    pp.add_argument("action", choices=["up", "down", "status"])
    pp.set_defaults(func=cmd_proxy)

    pbr = sub.add_parser("browser", help="launch a host browser, VPN-proxied + agent-drivable (CDP)")
    pbr.add_argument("url", nargs="?", help="optional start URL, e.g. http://box.htb/")
    pbr.add_argument("--browser", help="path to a Chromium-family browser "
                                       "(else auto-detect / $ROO_BROWSER)")
    pbr.add_argument("--cdp-port", dest="cdp_port", type=int, default=9222,
                     help="remote debugging port the agent attaches to (default 9222)")
    pbr.add_argument("--no-proxy", dest="no_proxy", action="store_true",
                     help="browse direct, not through the VPN SOCKS proxy")
    pbr.add_argument("--dry-run", dest="dry_run", action="store_true",
                     help="print the launch command without starting the browser")
    pbr.set_defaults(func=cmd_browser)

    psh = sub.add_parser("shell", help="interactive operator shell in the tunnel namespace")
    psh.add_argument("args", nargs=argparse.REMAINDER,
                     help="optional command to run instead of an interactive shell")
    psh.set_defaults(func=cmd_shell)

    prs = sub.add_parser("responder",
                         help="Responder (LLMNR/NBT-NS/mDNS poisoning + capture) on the tunnel iface")
    prs.add_argument("args", nargs=argparse.REMAINDER,
                     help="extra Responder flags (default: -I tun0)")
    prs.set_defaults(func=cmd_responder)

    pip = sub.add_parser("ip", help="print the tunnel IP (your LHOST)")
    pip.set_defaults(func=cmd_ip)

    pf = sub.add_parser("fwd", help="bridge a tunnel port to a host listener (target -> host)")
    pf.add_argument("port", help="port to forward (same number on tunnel and host)")
    pf.add_argument("--stop", action="store_true", help="tear down the forward for this port")
    pf.set_defaults(func=cmd_fwd)

    pbh = sub.add_parser("bloodhound",
                         help="local BloodHound CE: ingest a collection zip and view the graph")
    pbh.add_argument("action", choices=["up", "ingest", "open", "view", "down", "status"],
                     help="up | ingest <zip> | open | view <zip> (up+ingest+open) | down | status")
    pbh.add_argument("zip", nargs="?", help="collected zip/json (for ingest/view)")
    pbh.add_argument("--wipe", action="store_true",
                     help="down: also delete the neo4j/postgres data volumes")
    pbh.set_defaults(func=cmd_bloodhound)

    phc = sub.add_parser("hashcat",
                         help="run host hashcat for GPU cracking (auto-installs on first use)")
    phc.add_argument("args", nargs=argparse.REMAINDER,
                     help="arguments passed straight to hashcat (e.g. -m 19700 hash rockyou.txt)")
    phc.set_defaults(func=cmd_hashcat)

    pwl = sub.add_parser("wordlist",
                         help="fetch a SecLists password wordlist for host hashcat (default rockyou)")
    pwl.add_argument("name", nargs="?",
                     help="alias (rockyou, …) or a SecLists Passwords-relative path")
    pwl.add_argument("--list", action="store_true", help="list known aliases and exit")
    pwl.set_defaults(func=cmd_wordlist)

    pt = sub.add_parser("tools",
                        help="fetch prebuilt Windows tools (Forge) into the shared off-host /tools volume")
    pt.add_argument("action", choices=["list", "builds", "get", "installed", "rm"],
                    help="list | builds <name> | get <name> | installed | rm <name>")
    pt.add_argument("name", nargs="?", help="tool name (get/builds/rm) or a filter (list)")
    pt.add_argument("--ref", help="get: pin a specific build by commit-prefix or version label")
    pt.add_argument("--release", action="store_true",
                    help="get: take the newest tagged release instead of the default main/branch build")
    pt.set_defaults(func=cmd_tools)
    return p


def main():
    # hashcat is a verbatim pass-through to the host binary, so capture everything
    # after the verb ourselves — argparse REMAINDER drops a leading `-flag` (the
    # common `roo hashcat -m 19700 …` case). The subparser stays registered above
    # so the verb still shows in `roo --help`.
    argv = sys.argv[1:]
    if argv and argv[0] == "hashcat":
        return cmd_hashcat(argparse.Namespace(args=argv[1:], func=cmd_hashcat))
    if argv and argv[0] == "responder":
        return cmd_responder(argparse.Namespace(args=argv[1:], func=cmd_responder))
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
