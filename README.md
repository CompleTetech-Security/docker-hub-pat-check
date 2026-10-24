<p align="center">
  <img src="docs/images/banner.png" alt="docker-hub-pat-check by CompleteTech LLC" width="100%">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/status-implementation%20pending-B45309" alt="Status: implementation pending">
  <img src="https://img.shields.io/badge/checker-planned-1E3A8A" alt="Checker planned">
  <a href="LICENSING.md"><img src="https://img.shields.io/badge/license-AGPL--3.0%20%7C%20commercial-64748B" alt="AGPL-3.0 or commercial license"></a>
</p>

<p align="center">
  <b>Docker Hub account-conversion PAT reassignment</b><br>
  CVE-2026-105445 · research foundation for a planned checker · vendor-evidence only
</p>

---

> **Repository initialized; checker implementation pending.**
> This project currently contains research and an implementation checklist.
> It does not assess systems or provide an executable detection rule.

`docker-hub-pat-check` is the dedicated repository for **CVE-2026-105445**, a historical, service-side Docker Hub exposure. The planned checker would help an administrator organize vendor-supplied notification and remediation evidence. Because no client or Docker version rule exists, it must not infer exposure by probing Docker Hub or testing tokens.

## Status and what is planned

Nothing is runnable yet: there are no checker commands, install steps, downloadable binaries, test results, or CI claims.

1. Review [advisory.json](advisory.json) and the [primary sources](#primary-sources).
2. Work through the exploit-specific [implementation checklist](docs/IMPLEMENTATION.md).
3. Read [AGENTS.md](AGENTS.md), [CONTRIBUTING.md](CONTRIBUTING.md), and [SECURITY.md](SECURITY.md) before contributing.

## Planned report layout

The planned checker is intended to produce human-readable findings plus machine-readable JSON/CSV. The image below is only a sketch of that layout.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/images/report-dark.png">
    <img src="docs/images/report-light.png" alt="Illustrative placeholder layout of a planned report; no checker is implemented" width="900">
  </picture>
</p>

<p align="center"><sub><b>Illustrative only.</b> No checker exists and no assessment was performed. Placeholder rows use reserved <code>example.*</code> names.</sub></p>

## Planned status vocabulary

**Planned, not implemented.** These are the statuses the repository's conventions describe for a future checker.

| Status | Planned meaning |
| --- | --- |
| `potentially_affected` | Evidence matches this advisory's documented condition. Not confirmed exploitability. |
| `fixed_version_reported` | A supported comparison reports remediation. Not a safety guarantee. |
| `unknown` | Evidence is missing, malformed, conflicting, or otherwise insufficient. Never a clean result. |

`exploitability` stays `not_tested` for every future finding.

## Fix and exposure evidence

Research only, taken from [advisory.json](advisory.json); not a test result.

| Item | Recorded value |
| --- | --- |
| Exposure start | 2024-08-26T20:33:00Z |
| Remediation | 2026-09-30T19:10:00Z (vendor service remediation) |
| Local version threshold | None; no meaningful client or Docker version rule exists |

> [!IMPORTANT]
> **Nothing here is an assessment.** Only the vendor can determine historical exposure for an account. Public version or response metadata cannot establish affected status, and the checker must never probe Docker Hub or test tokens. Any examples must use synthetic placeholders only.

## How it will work

The intended checker follows the conventions of [node2shell-check](https://github.com/CompleteTech-LLC/node2shell-check) and [php2shell-check](https://github.com/CompleteTech-LLC/php2shell-check); see [Planned checker behavior](#planned-checker-behavior) below. This is a plan, not a description of existing behavior.

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

## Primary sources

1. [www.docker.com](https://www.docker.com/blog/docker-hub-security-advisory-cve-2026-105445/)

The research date records the supplied verification snapshot. Recheck primary
advisories before enabling any detection logic, and retain contradictory evidence.

## Documentation

- [Implementation checklist](docs/IMPLEMENTATION.md)
- [Advisory research record](advisory.json)
- [Contributing](CONTRIBUTING.md) · [Security policy](SECURITY.md) · [Licensing](LICENSING.md) · [Brand assets](BRAND_ASSETS.md)

## License

[AGPL-3.0](LICENSE), or a separate commercial agreement with CompleteTech LLC.
See [LICENSING.md](LICENSING.md) and the
[contribution terms](CONTRIBUTING.md#licensing-of-contributions).
Names and branding are governed by [BRAND_ASSETS.md](BRAND_ASSETS.md).

Copyright © 2026 CompleteTech LLC.
