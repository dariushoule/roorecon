<!--
  RooRecon report template. `roo report <target>` fills the {{TOKENS}} below and
  writes recon-results/<target>/report.md — edit this layout freely; only the
  tokens are substituted.
  Available tokens:
    {{TARGET}}            the scanned host/IP
    {{SWEEP_STATUS}}      "complete" | "in progress / not run"
    {{PORT_COUNT}}        number of ports with a facts.md
    {{FINGERPRINT_ROWS}}  markdown table rows: | port | proto | service | version |
    {{HOSTNAMES}}         bullet list of discovered hostnames (or a placeholder)
    {{PER_PORT_DETAIL}}   each port's facts.md + operator notes.md, concatenated
    {{VULN_FINDINGS}}     ranked CVEs + public PoCs from `roo vulns` (or a placeholder)
  Unknown tokens are left as-is. Override this file with --template or $ROO_REPORT_TEMPLATE.
-->
# Recon report — {{TARGET}}

## Status
- Port sweep: {{SWEEP_STATUS}}
- Open ports with facts: {{PORT_COUNT}}

## Open ports & technology fingerprint

| Port | Proto | Service | Version / banner |
|------|-------|---------|------------------|
{{FINGERPRINT_ROWS}}

## Discovered hostnames

{{HOSTNAMES}}

## Attack surface & priorities

<!-- TODO (operator/agent): rank what to attack first and why, citing the
     port/service/version evidence below. -->

## Known vulnerabilities & exploits

{{VULN_FINDINGS}}

## Per-port detail

{{PER_PORT_DETAIL}}
