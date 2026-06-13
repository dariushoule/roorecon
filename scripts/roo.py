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
  ip                              print the tunnel IP (your LHOST)
  fwd <port> [--stop]             bridge a tunnel port to a host listener

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
import os
import re
import shutil
import subprocess
import sys
import threading
import time
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
    df = _dockerfile(tool)
    if not df.is_file():
        return None
    digest = hashlib.sha256(df.read_bytes()).hexdigest()[:12]
    return f"{IMAGE_PREFIX}/{tool}:{digest}"


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
            stdout=subprocess.DEVNULL,
        )
        if r.returncode != 0:
            die(f"failed to build image for {tool}")
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
                quiet=False, extra_mounts=None):
    """Build (and optionally launch) a `docker run` for a tool image.

    stream=True -> Popen with stdout piped (for the sweep reader); otherwise a
    blocking subprocess.run. quiet=True silences the tool's stdout/stderr (used
    when we only care about the -oA/-oN files it writes). extra_mounts injects
    additional --mount specs (e.g. a custom wordlist).
    """
    cmd = ["docker", "run", "--rm"]
    if tty and sys.stdin.isatty() and sys.stdout.isatty():
        cmd.append("-it")
    if name:
        cmd += ["--name", name]
    cmd += (_caps(tool) + _net() + _hosts_mount() + (extra_mounts or [])
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
    _docker_run("nmap", ref, ["-Pn", "-n", *scan, f"-p{port}", "-oN", nmap_out, target], quiet=True)

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

    # Surface hostnames the box revealed (redirect target / cert CN+SAN). The
    # orchestrator adds these to ./hosts and feeds them to vhost/dns enum.
    hostnames = _extract_hostnames(nmap_txt + "\n" + scripts_txt, target)
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
        if not Path(explicit).is_file():
            die(f"config not found: {explicit}")
        return Path(explicit)
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


def cmd_proxy(args):
    """SOCKS5 egress so host tools reach the target through the tunnel."""
    require_docker()
    if args.action == "status":
        running = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", PROXY_CONTAINER],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True).stdout.strip() == "true"
        ok(f"SOCKS proxy running — host 127.0.0.1:{SOCKS_PORT}") if running else \
            info("SOCKS proxy is not running (roo proxy up)")
        return
    if args.action == "down":
        r = subprocess.run(["docker", "rm", "-f", PROXY_CONTAINER],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ok("SOCKS proxy stopped") if r.returncode == 0 else info("no SOCKS proxy running")
        return
    # up
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
    subprocess.run(
        ["docker", "run", "-d", "--name", PROXY_CONTAINER,
         "--network", f"container:{VPN_CONTAINER}", ref,
         "microsocks", "-i", bridge_ip, "-p", "1080"],
        stdout=subprocess.DEVNULL, check=True)
    # A ready-to-use proxychains config for host/container tools that want it.
    gen_dir = Path(".roo")
    gen_dir.mkdir(exist_ok=True)
    pc = gen_dir / "proxychains.conf"
    pc.write_text("strict_chain\nproxy_dns\n[ProxyList]\n"
                  f"socks5 127.0.0.1 {SOCKS_PORT}\n")
    ok(f"SOCKS proxy up — host 127.0.0.1:{SOCKS_PORT}")
    info(f"  curl:        curl --socks5h 127.0.0.1:{SOCKS_PORT} http://<target>/")
    info(f"  proxychains: proxychains -f {pc} <tool> <target>")
    info(f"  browser/Burp: SOCKS5 host 127.0.0.1 port {SOCKS_PORT} (remote DNS)")
    info("note: TCP-connect only — raw -sS/-sU scans must run as roo containers")


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
        info("  reverse shell:  ncat -lvnp 4444")
        info("  host a file:    python3 -m http.server 8000")
    cmd = ["docker", "run", "--rm"]
    if interactive:
        cmd.append("-it")
    cmd += (["--network", f"container:{VPN_CONTAINER}"]
            + _hosts_mount() + _work_mount() + [ref] + list(cmd_args))
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

    pv = sub.add_parser("vpn", help="manage the OpenVPN sidecar")
    pv.add_argument("action", choices=["up", "down", "status"])
    pv.add_argument("config", nargs="?")
    pv.set_defaults(func=cmd_vpn)

    pp = sub.add_parser("proxy", help="SOCKS5 egress for host tools (browser/Burp/curl)")
    pp.add_argument("action", choices=["up", "down", "status"])
    pp.set_defaults(func=cmd_proxy)

    psh = sub.add_parser("shell", help="interactive operator shell in the tunnel namespace")
    psh.add_argument("args", nargs=argparse.REMAINDER,
                     help="optional command to run instead of an interactive shell")
    psh.set_defaults(func=cmd_shell)

    pip = sub.add_parser("ip", help="print the tunnel IP (your LHOST)")
    pip.set_defaults(func=cmd_ip)

    pf = sub.add_parser("fwd", help="bridge a tunnel port to a host listener (target -> host)")
    pf.add_argument("port", help="port to forward (same number on tunnel and host)")
    pf.add_argument("--stop", action="store_true", help="tear down the forward for this port")
    pf.set_defaults(func=cmd_fwd)
    return p


def main():
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
