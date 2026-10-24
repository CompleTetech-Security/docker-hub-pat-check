# docker-hub-pat-check

**Docker Hub account-conversion PAT reassignment**  
By [CompleteTech LLC](https://complete.tech)

> **Repository initialized; checker implementation pending.**
> This project currently contains research and an implementation checklist.
> It does not assess systems or provide an executable detection rule.

## One exploit, one repository

| Field | Scope |
| --- | --- |
| Exploit identifier | `CVE-2026-105445` |
| Aliases for this same exploit | None recorded |
| Research verification date | 2026-10-23 |
| Implementation state | `vendor_evidence_only` |
| Detection rule | **Disabled — research only** |

This repository is dedicated to **CVE-2026-105445**. Aliases and multiple affected
products identify this same exploit; they do not create additional scanner scopes.
Future fixes for different vulnerabilities belong in independent repositories.

This advisory requires vendor or account-specific evidence. Public version or response metadata alone cannot establish affected status.

## Advisory snapshot

The following is source-backed research for implementation planning. It is not a
test result, a live rule feed, or an attestation that a deployed system is patched.

### Affected versions or conditions

```json
{
  "exposure_start": "2024-08-26T20:33:00Z",
  "type": "Historical service-side exposure; vendor notification required"
}
```

### Reported fixes or remediation

```json
{
  "fixed_at": "2026-09-30T19:10:00Z",
  "type": "Vendor service remediation; no local version threshold"
}
```

### Deployment preconditions to establish

- vendor identified account conversion exposure

### Evidence notes and limitations

- No meaningful client or Docker version rule exists. Use administrator-supplied vendor notification and remediation evidence; do not infer exposure by probing Hub or testing tokens.
- Vendor sent impacted-user/owner notifications on October 2 and says unnotified accounts were not exposed. This is a separate distinct exploit even though report discourages a standalone scanner.

## Planned checker behavior

The intended checker follows the evidence and reporting conventions of
[node2shell-check](https://github.com/CompleteTech-LLC/node2shell-check) and [php2shell-check](https://github.com/CompleteTech-LLC/php2shell-check):

- Prefer offline version, inventory, or configuration evidence appropriate to this exploit.
- Keep version state, documented preconditions, evidence provenance, and uncertainty separate.
- Preserve `exploitability: not_tested`; never run exploit payloads or confirm compromise.
- Keep missing, malformed, conflicting, vendor-qualified, prerelease, and uncovered versions `unknown`.
- Produce human-readable findings and machine-readable JSON/CSV; document each output before release.
- Add bounded, explicitly selected passive network behavior only if it provides useful evidence.

These capabilities are **planned**, not implemented. There are currently no
checker commands, downloadable binaries, test results, or CI claims.

## Start here

1. Review [advisory.json](advisory.json) and the primary sources below.
2. Work through the exploit-specific [implementation checklist](docs/IMPLEMENTATION.md).
3. Read [AGENTS.md](AGENTS.md), [CONTRIBUTING.md](CONTRIBUTING.md), and
   [SECURITY.md](SECURITY.md) before contributing.

## Primary sources

1. [www.docker.com](https://www.docker.com/blog/docker-hub-security-advisory-cve-2026-105445/)

The research date records the supplied verification snapshot. Recheck primary
advisories before enabling any detection logic, and retain contradictory evidence.

## License

[AGPL-3.0](LICENSE), or a separate commercial agreement with CompleteTech LLC.
See [LICENSING.md](LICENSING.md) and the
[contribution terms](CONTRIBUTING.md#licensing-of-contributions).
Names and branding are governed by [BRAND_ASSETS.md](BRAND_ASSETS.md).

Copyright © 2026 CompleteTech LLC.
