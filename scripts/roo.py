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
  recon <target>                  simple one-shot phased scan
  vpn <up|down|status> [config]   manage the OpenVPN sidecar

Wordlists (vhost/dns) are baked into the gobuster image from SecLists; select
with --wordlist <name|path> or $ROO_WORDLIST (default: subdomains-top1million-5000).

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

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCKER_DIR = Path(os.environ.get("ROO_DOCKER_DIR", REPO_ROOT / "docker"))
IMAGE_PREFIX = "roorecon"
VPN_CONTAINER = "roorecon-vpn"

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

    # -oA paths are relative so they land under /work (= cwd) in the container.
    tcp_oa = str((outdir / "tcp"))
    udp_oa = str((outdir / "udp"))
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
    nmap_out = str(d / "nmap.txt")
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
                     "-oN", str(d / "scripts.txt"), target], quiet=True)
        if (d / "scripts.txt").exists():
            scripts_txt = (d / "scripts.txt").read_text()

    svc_line = next((ln for ln in nmap_txt.splitlines()
                     if re.match(rf"^{port}/{proto}\s", ln)), "(no open service line)")
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


def _resolve_wordlist(w):
    """Return (container_path, extra_mounts) for a wordlist selector.

    Selector may be a baked name (e.g. combined_subdomains.txt) or an absolute
    /wordlists path -> used as-is; or a host file path -> mounted into the image.
    Falls back to $ROO_WORDLIST, then the fast default.
    """
    w = w or os.environ.get("ROO_WORDLIST") or DEFAULT_WORDLIST
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
                 "-oA", str(outdir / "all-ports"), target], quiet=True)

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
                 "-oA", str(outdir / "services"), target], quiet=True)

    svc_nmap = (outdir / "services.nmap").read_text() if (outdir / "services.nmap").exists() else ""
    svc_lines = [ln for ln in svc_nmap.splitlines() if re.match(r"^\d+/(tcp|udp)\s+open", ln)]
    summary = (f"Target:     {target}\nOpen ports: {','.join(ports)}\n\n"
               "== Services ==\n" + "\n".join(svc_lines) + "\n")
    (outdir / "summary.txt").write_text(summary)
    ok(f"done. results in {outdir}/")
    print("\n" + summary)


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
    subprocess.run(
        ["docker", "run", "-d", "--name", VPN_CONTAINER,
         "--cap-add=NET_ADMIN", "--device", "/dev/net/tun",
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
    ok(f"VPN up — tunnel address {addr}")
    info(f"route tools through it with:  ROO_NET=container:{VPN_CONTAINER} roo run <tool> ...")


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

    pv = sub.add_parser("vpn", help="manage the OpenVPN sidecar")
    pv.add_argument("action", choices=["up", "down", "status"])
    pv.add_argument("config", nargs="?")
    pv.set_defaults(func=cmd_vpn)
    return p


def main():
    args = build_parser().parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
