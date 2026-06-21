---
name: cloud
description: Cloud-emulator and AWS-compatible-API attack methodology for authorized pentesting and CTF. Use when a target exposes an AWS-shaped API (LocalStack, moto, or a custom/look-alike mock), an instance metadata service (IMDS / 169.254.169.254) reachable via SSRF, or you hold cloud credentials and need to map principals, abuse a cloud service, and escalate. Triggers on "cloud", "AWS", "IMDS", "metadata service", "LocalStack", "moto", "S3/SQS/STS/IAM endpoint", "cloud creds", "instance profile", "I have an access key", "cloud-emulator box".
---

# Cloud / AWS-emulator attack path

Boxes that emulate a cloud control plane are a **genre**, and they all run the same
arc: an **SSRF reaches the metadata service** for credentials → those creds talk to an
**AWS-compatible API** → the win is abusing a cloud **service** (build/CI, container,
function, queue) into code execution or a more-privileged principal. This skill maps
that surface and drives **`./roo aws`** to enumerate and act.

Recon hands off here when it spots an AWS-shaped endpoint (STS/S3/SQS/IAM error XML,
`x-amz-*` headers, a `/latest/meta-data/` path, a `_localstack`/`moto-api` banner, or
port 4566). Start here directly when you already hold an access key.

## Scope guardrail
Authorized targets only — CTF boxes, lab ranges, signed scope. Enumerate principals
and permissions before abusing a service; the actual privesc/exec step is
operator-approved.

## Workflow

### 1. Get credentials — usually SSRF → IMDS
The metadata service (`169.254.169.254`) hands out the instance role's creds with no
auth. Emulator/CTF IMDS is almost always **IMDSv1** (no token needed):
`/latest/meta-data/iam/security-credentials/<role>`.
- If an SSRF filter blocks `169.254.169.254`, **alternate-encode the IP** — decimal
  (`2852039166`), octal, hex, `0`-padded — filters are usually literal-substring.
- Other common cred sources: a leaked env (`AWS_ACCESS_KEY_ID`/`_SECRET`), a worker
  process env, S3/SSM/Secrets objects you can read, an `.aws/credentials` on a shell.

### 2. Map the topology — *which* endpoint, and is it enforcing?
The single highest-value question on these boxes: **is there an IAM-enforcing front
*and* an IAM-free backend?** Emulators frequently run behind a gateway that checks
signatures/policy, while the raw backend (often LocalStack-style on `:4566`) enforces
nothing and is reachable directly on the internal network.
- Hit the **backend directly** to bypass IAM entirely for reads/writes (list buckets,
  read objects, send queue messages) that the gateway would `AccessDenied`.
- **Name the exact endpoint you are hitting in every note.** Conflating the enforcing
  gateway with the IAM-free backend (they often share a hostname/port scheme but are
  *different services with different keystores*) wrecks your mental model — be precise.

### 3. Enumerate the principal — oracle, don't guess
Drive **`./roo aws`** (containerized AWS CLI, tunnel-aware, `./hosts` mounted):
```
ROO_AWS_ENDPOINT=http://<api-host> ROO_AWS_ENV=recon-results/<t>/exploit/creds.env \
  ROO_NET=container:roorecon-vpn ./roo aws sts get-caller-identity
... ./roo aws sqs list-queues   |   iam list-users   |   s3api list-objects-v2 --bucket X
```
- **`AccessDenied` is a permission oracle** — it leaks the exact `action` + `resource`
  evaluated. A *non*-AccessDenied (NoSuchKey/empty/200) means the principal *is*
  allowed there. Sweep actions to map the real allow-set instead of guessing names.
- **Test whether the mock actually validates the signature.** Custom/mock IAM often
  authenticates by **AccessKeyId alone** — re-send a request with a *tampered* secret/
  signature; if it still works, any *known* AKID = full impersonation **without the
  secret**. Then the whole game is locating a privileged principal's AKID.

### 4. Abuse a service → RCE / privesc
The principal's allowed services are your toolbox. Common primitives (deep mechanics in
the runbook): a **queue** whose messages a worker executes; **build/CI** (CodeBuild)
running attacker commands in a `--privileged` container → host root; **container/function**
services (ECS/EKS/Lambda) running your code; the **emulator process itself** (if it
mounts `docker.sock`, code-exec inside it = host root). → `runbooks/service-abuse.md`.

## Footgun & judgment cheat-sheet
- **Enforcing gateway vs IAM-free backend is the crux** — always test the raw backend.
- **Oracle over guessing** — `AccessDenied` leaks action+resource; enumerate, don't fuzz names.
- **Does the mock check signatures?** Tamper the secret; AKID-only auth is a common plant.
- **Verify a service/feature actually *executes* before building on it.** Emulators
  compiled to a native image (GraalVM) can ship **dead features** that throw on every
  call and return an **opaque 500** — probe a trivial input first (e.g. empty vs
  non-empty template) to confirm the sink runs at all. Don't craft payloads against a
  broken sink. (See vuln-research → "reproduce locally" to read the suppressed error.)
- **Image delivery on an isolated box is hard.** No egress → `docker.io` is DNS-dead;
  your own registry is refused because **containerd wants HTTPS** (and `insecure-
  registries` is dockerd-only, not containerd). Cheaply test "can the box pull `<ref>`?"
  with one task *before* standing up registry infra — don't rabbit-hole on delivery.
- **Read the emulator's source.** These are OSS; the privileged primitive (and which
  knobs are attacker-controlled) is in the code. Identify product+version → vuln-research.

## Runbooks
- `runbooks/service-abuse.md` — turning a cloud service into code-exec/host-root:
  queue→worker, CodeBuild privileged-container escape, ECS/EKS/Lambda code-exec, and
  emulator-process → `docker.sock` → host. Read when you hold creds and a service to abuse.
