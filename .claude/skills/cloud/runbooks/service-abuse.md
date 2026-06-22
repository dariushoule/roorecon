# Runbook — cloud service abuse → code-exec / host root

Cherry-picked mechanics for turning an *allowed* cloud service into execution or a
host foothold. Read once you hold creds (or IAM-free backend access) and know which
services the principal can touch. Generic across AWS-emulator boxes — confirm each
primitive against the **emulator's own source** for the build you're facing.

## First: read the source for the build you're hitting
The privileged primitive lives in the emulator's code, and *which fields are
attacker-controlled* decides everything. Identify the product + exact version, clone
that tag, and grep the service handler before fuzzing (vuln-research → "reproduce
locally / clone the version"). A primitive that exists in `main` may be **patched, gated
by config, or dead in a native build** in the version the box runs — verify, don't assume.

## Queue → worker code execution
A queue (SQS) whose messages a background worker processes is often the foothold RCE:
the worker pulls a job and runs a field of it.
- **Read the worker source** (often leaked in an S3 artifacts bucket) to learn the
  *exact* exec field and interpreter — blind-guessing the job schema burns dozens of
  payloads. The field that runs code is rarely the obvious one (`command`); it might be
  `script` run via `python3 -c`, an unsafe-YAML body, etc.
- You usually only need `sqs:SendMessage` to one queue. The worker drains it and runs
  your job; exfil output to an S3 bucket you can read back (in-band), or a reverse shell
  if the worker has egress — **verify egress directly** (a port sweep from the worker)
  before concluding "no callback = no network"; a silent worker is usually the *wrong
  exec field*, not the network.
- Long jobs get killed at the worker's `timeout` — `os.fork()` + `os.setsid()` to detach
  a child (reverse shell, long scan) so it outlives the parent.
- Once the queue RCE is proven, standardize a **per-engagement harness** under
  `recon-results/<target>/exploit/`: one helper that submits the exact job schema,
  writes output to an object store or other in-band channel, and chunks/polls the
  result. Keep this local to the engagement unless the queue schema and exfil path are
  genuinely generic; most "run a job" wrappers are box-specific glue, not a durable
  `roo` command.

## Build/CI (CodeBuild) → privileged container → host root
The strongest planted primitive: a build service that honors an **attacker-controlled
`privilegedMode`** and runs your **buildspec** verbatim in that `--privileged` container
→ host root via `nsenter -t 1 …` or `mount /dev/sdaN`.
- The blocker is almost always the **build image**, not the bug. If the runner sets only
  `withCmd` (no entrypoint/user override) and keeps the container alive with `tail -f`,
  the image must be **present on the host AND entrypoint-free AND run as root** (so the
  fixed CMD runs and `mkdir`/escape succeed). Test present images:
  - a Lambda base image is root but its entrypoint exits on a non-handler CMD → dies;
  - the app's own worker image may be entrypoint-free but **uid≠0** → `mkdir` denied → dies;
  - and a uid≠0 process in a `--privileged` container still has an **empty cap set** → no `mount`/`nsenter`.
- **Reading the exact pull/exec error**: fire the task and read the literal Docker error
  from `describe_tasks` (`stoppedReason`) or the build's CloudWatch logs — that
  distinguishes *image-missing* (`failed to resolve reference … docker.io … i/o timeout`)
  from *present-but-nonroot* (permission denied) from *present-root-win*.
- **Map image reality, not the filename.** If source ships multiple Dockerfiles, inspect
  the publish workflow to learn which Dockerfile built the tag you are using (`latest`
  may be a native/UBI image while a nearby JVM Dockerfile is Alpine). Then cheaply probe
  the actual cached image before designing the escape: `/etc/os-release`, `uname -m`,
  `/bin/sh` target, `ENTRYPOINT`, default `USER`, `PATH`, and available tools. This
  catches false assumptions like "sh is BusyBox ash", "mount exists", or "the image
  runs as root".
- **Entrypoint root drops are sometimes bypassable without a new image.** If an
  entrypoint decides whether to `gosu`/`su-exec` based on shell command output
  (`id -u`, `whoami`, etc.), and the image's `/bin/sh` is Bash or otherwise imports
  shell functions, an exported function such as `BASH_FUNC_id%%='() { echo 1001; }'`
  can make the check skip the drop while the process remains real uid 0. Verify the
  shell first; this does not apply to BusyBox `ash`. Prefer this kind of narrow
  override to broad `PATH` tricks, which are brittle on usrmerge images and can hide
  support binaries the entrypoint needs.
- **Minimal images may be privileged but tool-poor.** Native/Graal/UBI micro images can
  have full caps and block devices but no `mount`, `nsenter`, Python, Perl, Java, or
  compiler. Inventory first; if the primitive is real, stage a small static helper
  through an already-reachable in-band path (object store, queue worker, internal HTTP)
  and fetch it from inside the build. Avoid target-side internet pulls on isolated labs.
- **Inspect existing mounts before guessing disks.** A device may already be mounted
  into the container only as narrow bind-backed paths (`/app/data`, `/etc/hosts`, etc.).
  Read `/proc/mounts`, `/proc/self/mountinfo`, and `/proc/partitions`; then try typed
  mount variants (`-t ext4`, `rw` vs `ro,noload`) rather than treating one failed
  `mount /dev/sdaN` as proof the privileged path is dead.
- **Delivering your own image** is the hard part on an isolated box — see the
  image-delivery footgun in `SKILL.md`. Treat it as a rabbit hole; exhaust *present*
  images and non-image primitives first.

## ECS / EKS / Lambda → code exec (often unprivileged)
- **ECS / Lambda (image)** typically let you run an arbitrary command as **uid 0** in a
  spawned container (entrypoint/cmd override) — but those containers are usually
  **unprivileged & isolated** (default caps, no `docker.sock`, no host mount): good for
  recon/exec, *not* a host escape by themselves.
- **EKS** may hardcode `--privileged` for its k3s node — but it needs the k3s **image
  present**; on an isolated box that pull fails (verify with one `RunTask`/`CreateCluster`
  and read the error — don't *infer* "missing" from "it's a docker.io image").
- The split to remember: **one service has privilege, another has the entrypoint/user
  override, and they rarely compose.** Map which is which from the source.

## Emulator process itself → docker.sock → host root
The emulator container usually mounts the host **`/var/run/docker.sock`** (it needs it
to spawn service containers) and runs its process in the `docker` group. So **code-exec
*inside the emulator process* = host root** (create a privileged container mounting `/`).
Hunt for a way in:
- **Init-hook executors** that run scripts as the emulator user — but they're usually
  gated to startup/shutdown lifecycle (no runtime HTTP trigger) and read from root-owned
  `/etc` dirs you can't write. Confirm both the trigger and a write primitive exist.
- **Template engines** (e.g. API-Gateway VTL/Velocity, mapping templates) → SSTI → RCE
  if unsandboxed. **But verify the engine actually runs in this build first** — a
  native-image emulator can ship the feature broken (every template 500s). Probe empty
  vs non-empty input; if even a literal string 500s, the sink is dead (see vuln-research
  → reproduce locally to read the real stack trace).
- **Unsafe deserialization / YAML / file-write traversal** in any handler that ingests
  attacker data (CFN templates, Lambda zip extraction, S3 object writes). Well-written
  emulators guard these (`SafeConstructor`, `startsWith(base)` zip-slip checks) — read
  the sink before assuming.
- If you get a write-anywhere-as-the-emulator-user primitive, target something the
  emulator (or host) later executes; `docker.sock` access then trivially yields host root.

## Don't get tunnel-visioned on one plane
These boxes split a **data plane** (SQS/S3/SSM — often IAM-free, where the foothold
lives) from an **identity plane** (a custom IAM/STS mock holding the real principals and
SSH-key/approval logic). If the data plane is walled for root, the answer is usually a
**privileged principal on the identity plane** (whose AKID leaks somewhere reachable —
worker env, app source, a resource policy) or a host-side mechanism, not more data-plane
grinding. Re-read where the foothold's creds actually came from before assuming root is
"more of the same service."
