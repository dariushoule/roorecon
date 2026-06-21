# AWS CLI for interacting with AWS or AWS-compatible APIs in scope during an
# engagement (real AWS, or a service emulating it behind a custom endpoint).
# pip awscli (v1) honors --endpoint-url and the standard AWS_* env vars, which is
# all that's needed to point at an arbitrary endpoint instead of public AWS.
# jq is bundled because nearly every AWS response is JSON worth slicing.
FROM python:3.12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends jq ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && pip install --no-cache-dir awscli \
 && aws --version
# Force path-style S3 addressing: against a custom --endpoint-url the CLI would
# otherwise use virtual-host style (bucket.<endpoint-host>), which often won't
# resolve for a non-AWS host. Path style keeps it as <endpoint-host>/bucket.
RUN mkdir -p /root/.aws \
 && printf '[default]\ns3 =\n    addressing_style = path\n' > /root/.aws/config
# roo passes only the aws subcommand + flags (e.g. `sts get-caller-identity`),
# so `aws` is the entrypoint. jq is available via `--entrypoint jq` if needed.
ENTRYPOINT ["aws"]
