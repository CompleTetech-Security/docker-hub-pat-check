<p align="center">
  <img src="docs/images/banner.png" alt="docker-hub-pat-check by CompleteTech LLC" width="100%">
</p>

<p align="center">
  <a href="https://github.com/CompleTetech-Security/docker-hub-pat-check/actions"><img src="https://img.shields.io/github/actions/workflow/status/CompleTetech-Security/docker-hub-pat-check/tests.yml?label=tests" alt="Tests"></a>
  <img src="https://img.shields.io/badge/python-3.10%2B-1E3A8A" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/dependencies-none-067647" alt="No runtime dependencies">
  <a href="LICENSING.md"><img src="https://img.shields.io/badge/license-AGPL--3.0%20%7C%20commercial-64748B" alt="AGPL-3.0 or commercial license"></a>
</p>

# docker-hub-pat-check

<p align="center">
  <b>Docker Hub account-conversion PAT reassignment (CVE-2026-105445)</b><br>
  An offline vendor-evidence recorder, not a scanner
</p>

## Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Interpreting results](#interpreting-results)
- [Reports and output](#reports-and-output)
- [Safety and limitations](#safety-and-limitations)
- [Vendor-reported facts and sources](#vendor-reported-facts-and-sources)
- [Documentation](#documentation)
- [Contributing and security](#contributing-and-security)
- [License](#license)

## Overview

`docker-hub-pat-check` is the dedicated repository for **CVE-2026-105445**, a historical, service-side Docker Hub exposure. Docker reports that account-to-organization conversion re-assigned personal access tokens (PATs) to the named new owner without rotating the token secret. The exposure ran from 2024-08-26 20:33 UTC until Docker's fix at about 2026-09-30 19:10 UTC.

There is **no client or Docker version rule**. Only Docker can say which accounts were exposed. This tool records evidence that an administrator already holds (whether Docker's notification arrived, when, and what remediation was done) and turns it into a consistent, reportable status. It never contacts Docker Hub, never tests a token, and never reads one.

> [!IMPORTANT]
> **"Not notified" is Docker's claim, not proof.** Docker says accounts that received no email were not exposed. The tool records that attribution and still reports `unknown`. Docker also reports no evidence of exploitation; that is a vendor finding, not something this tool verifies. Registry logs show token use, not token existence, as the vendor itself notes.

## Requirements

- Python 3.10 or later on Windows, macOS or Linux.
- Standard library only: nothing to install, no network access needed.
- Evidence you already hold: the Docker notification (or its absence) and your own remediation record.

## Quick start

```sh
python docker_hub_pat_check.py --notification received --notification-date 2026-10-02 \
  --remediation operator_revoked_or_rotated --remediation-date 2026-10-05 \
  --retained-listed-tokens no --label example-account --format json

python docker_hub_pat_check.py --inventory examples/evidence.example.json --format html --output report.html
python docker_hub_pat_check.py --evidence-csv examples/evidence.example.csv --format csv
python docker_hub_pat_check.py --help
```

Run the tests with `python -m unittest -v`.

## Usage

Each record describes one account's evidence. Records can come from the command line, JSON files, CSV files, or any combination; a run is limited to 10,000 records.

| Input | Option | Notes |
| --- | --- | --- |
| One record | `--label`, `--notification`, `--notification-date`, `--remediation`, `--remediation-date`, `--retained-listed-tokens`, `--evidence-source` | Supplying any of these creates one record from the command line. |
| JSON | `--inventory FILE` (repeatable) | One object or an array; each needs `"schema_version": 1`. See [examples/evidence.example.json](examples/evidence.example.json). |
| CSV | `--evidence-csv FILE` (repeatable) | UTF-8 with a header row. See [examples/evidence.example.csv](examples/evidence.example.csv). |

Record fields:

| Field | Values |
| --- | --- |
| `label` | Pseudonymous text, at most 512 characters (default `unlabeled`) |
| `notification` | `received`, `not_received`, `unknown` |
| `notification_date` | `YYYY-MM-DD` |
| `remediation` | `operator_revoked_or_rotated`, `vendor_deactivated`, `not_done`, `unknown` |
| `remediation_date` | `YYYY-MM-DD` |
| `retained_listed_tokens` | `yes`, `no`, `unknown` (whether a token listed in the notice was knowingly kept) |
| `evidence_source` | `vendor_email`, `vendor_support`, `vendor_statement`, `operator_attestation` |

Other options:

| Option | Purpose |
| --- | --- |
| `--format csv\|json\|html` | Report format (default `csv`). |
| `--output FILE` | Write the report to a new file; without it the report goes to stdout. |
| `--force` | Replace an existing output file. |
| `--brand NAME` | Organization name shown in the HTML report (default `CompleteTech LLC`). |
| `--fail-on-finding` | Exit 1 when any result is `potentially_affected`. |
| `--version`, `--help` | Show the tool version or full option help. |

Empty or absent values count as not supplied; values are trimmed and case-insensitive. [docs/REFERENCE.md](docs/REFERENCE.md) documents every field, limit, output column and rule.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Completed. Findings do not change this unless `--fail-on-finding` is set. |
| `1` | `--fail-on-finding` was set and at least one `potentially_affected` result exists. |
| `2` | Argument, input or output error. Takes precedence over `1`. |
| `130` | Interrupted. Completed observations are preserved where possible; see [interruption and recovery](#interruption-and-recovery). |

### Input errors versus assessment results

Structurally invalid input is an **operational error** (exit 2), not an assessment: unsupported fields, duplicate JSON keys, wrong types, control characters, malformed CSV or JSON, files over 4 MiB, over-long strings, unreadable files, and any value that looks like a Docker token. Error messages never echo supplied text. An unrecognized enum value or an invalid date inside an otherwise valid record is an **assessment result**: `unknown` with `malformed_evidence`.

## Interpreting results

| Status | Meaning here |
| --- | --- |
| `potentially_affected` | The operator reports that Docker's notification was received, so the vendor considers a transferred PAT in scope, and remediation is not fully reported. Not confirmed exploitation. |
| `fixed_version_reported` | The notification was received and the operator reports remediation with a date and no knowingly retained listed token. There is no version comparison; this means "remediation reported", never a guarantee. |
| `unknown` | Evidence is missing, malformed, conflicting, out of the vendor timeline, or says only that no notification arrived. Never a clean result. |

`unsupported_runtime` does not apply: there is no runtime lifecycle, and there is no `version_status`. `docker_hub_pat_evidence_status` gives the reason (for example `vendor_unnotified_claim`, `conflicting_evidence`, `remediation_reported`; the full list is in [docs/REFERENCE.md](docs/REFERENCE.md#assessment)), and `docker_hub_pat_exploitability` is always `not_tested`. `fixed_version_reported` reflects remediation the operator reports, not a verified deployed patch.

Dates are checked against the vendor timeline using the machine's UTC date. A notification date must not precede Docker's 2026-10-02 emails; an operator's own remediation date may fall on any day from the exposure start (2024-08-26) to today, because 2026-09-30 is Docker's service-fix date, not a limit on when an operator could revoke tokens; a `vendor_deactivated` claim dated before Docker's 2026-10-08 deactivation is `conflicting_evidence`. Future dates are rejected. Rules are fixed as of the build you run, so an old copy does not pick up later changes.

## Reports and output

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/images/report-dark.png">
    <img src="docs/images/report-light.png" alt="Screenshot of the HTML report rendered from the synthetic example file" width="900">
  </picture>
</p>

<p align="center"><sub>Rendered from the synthetic <a href="examples/evidence.example.json">example evidence</a> (reserved <code>example-*</code> labels). Source: <a href="docs/example-report.html">docs/example-report.html</a>. It describes no real account.</sub></p>

- **CSV** (default): one flat row per record with a `complete` column, a `record_type` column (`result`, or `summary` for a zero-result report) and the same fields as JSON.
- **JSON**: an object with `tool`, `tool_version`, `schema_version`, `rules_as_of`, `generated_at`, `complete`, `rules` (each with statement, source URL and review date) and `results`.
- **HTML**: one self-contained, script-free page with a restrictive Content-Security-Policy, escaped values, light and dark themes and print styles.

Every format identifies `docker-hub-pat-check` and its tool version. Reports keep the per-record UTC assessment time (`checked_at`, labeled **Assessment time (UTC)** in HTML) separate from the UTC report-generation time. CSV appends `tool`, `tool_version` and `generated_at` after the existing columns, including zero-result summaries. A CLI run keeps one generation time through interrupted-rendering recovery. Neither time is an evidence-acquisition time or attests vendor remediation. The result fields (`docker_hub_pat_status`, `docker_hub_pat_evidence_status`, `docker_hub_pat_exploitability`, `docker_hub_pat_cves`, `docker_hub_pat_rules_as_of`, `docker_hub_pat_sources`, `docker_hub_pat_notes`, `docker_hub_pat_recommendation` and the echoed inputs) are listed in [docs/REFERENCE.md](docs/REFERENCE.md#result-fields).

### Output protection

- Existing output files are refused without `--force`, and the output must differ from every input file even with `--force`. Its directory must already exist.
- Files are written to a temporary file and published atomically. Without `--force` this uses a hard link, so the destination filesystem must support hard links.
- On POSIX systems a file written with `--output` has owner-only permissions (mode 0600). Stdout and Windows files follow ordinary platform defaults.
- Reports contain whatever labels and dates you supply and can be sensitive. Use pseudonymous labels, keep inputs and reports out of version control (`reports/`, `private/` and `inventories/` are already ignored) and apply your own retention policy.

### Interruption and recovery

Reports are fully rendered and UTF-8 checked before output starts. An interruption before publication can trigger one incomplete-report attempt (`complete` is then `false`); a second interruption stops recovery. After stdout starts, no second report is appended and the stream may be truncated. After atomic file publication succeeds, the completed bytes and their completeness flag are preserved, even if the interruption arrives before success is recorded. If publication cannot be verified, the outcome is reported as unknown and is not retried. Details are in [docs/REFERENCE.md](docs/REFERENCE.md#report-publication-and-interruption).

## Safety and limitations

- It does not probe Docker Hub, call any API, test tokens, or have a network option.
- It never accepts tokens. Any value containing a Docker-prefixed token pattern (`dckr_` plus three letters and an underscore) is rejected as an input error, without echoing it. Tokens in other formats are not detected, so never paste any credential.
- It is not a generic scanner and does not infer exposure from versions, banners or account metadata.
- It does not store, log or upload anything. Reports contain only what you supplied.
- It does not verify evidence. `fixed_version_reported` is a record of reported remediation, not a verified patch or safety guarantee, and exploitability is never tested.

## Vendor-reported facts and sources

Reviewed against the [vendor advisory](https://www.docker.com/blog/docker-hub-security-advisory-cve-2026-105445/) on 2026-10-24:

| Item | Vendor-reported value |
| --- | --- |
| Exposure start | 2024-08-26 20:33 UTC |
| Fix deployed | 2026-09-30, about 19:10 UTC (vendor approximation); this is the service fix, not a limit on when an operator may have revoked tokens |
| Notification emails | 2026-10-02 to users whose accounts received transferred PATs and to their organization owners |
| Vendor deactivation of transferred PATs | 2026-10-08, except tokens whose owners asked to keep them |
| Vendor guidance | Review PATs under Account settings, Personal access tokens; revoke any you do not recognize or no longer use; use organization access tokens for organization automation; contact Docker Support |

The vendor post is the primary source and wins any disagreement. The CVE record and the NVD entry agree on the exposure window (2024-08-26T20:33:00Z up to 2026-09-30T19:10:00Z) and no disagreement was found; the notification and deactivation details come from the vendor post and the [researchers' write-up](https://ghostpat.com/) and are not independently verified here.

### Primary sources

1. [Docker Hub security advisory: personal access tokens transferred during account-to-organization conversions](https://www.docker.com/blog/docker-hub-security-advisory-cve-2026-105445/), reviewed 2026-10-24.
2. [CVE record](https://cveawg.mitre.org/api/cve/CVE-2026-105445) and [NVD entry](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-105445), checked 2026-10-24: same window as the vendor post.

### Scope: one exploit, one repository

| Field | Scope |
| --- | --- |
| Exploit identifier | `CVE-2026-105445` |
| Aliases for this same exploit | None recorded |
| Research verification date | 2026-10-24 |
| Implementation state | `vendor_evidence_only`, implemented |

Aliases and affected products share this scope. Different vulnerabilities belong in independent repositories.

## Documentation

- [Reference](docs/REFERENCE.md): fields, assessment rules, outputs, limits and publication behavior
- [Implementation checklist](docs/IMPLEMENTATION.md) and [advisory research record](advisory.json)
- [Brand assets](BRAND_ASSETS.md): logo and artwork terms

## Contributing and security

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request, and run `python -m unittest -v` first. Tests use synthetic input only and make no network requests; GitHub Actions runs them on Linux and Windows with Python 3.10 and 3.14. Report flaws that need private disclosure as described in [SECURITY.md](SECURITY.md). This checker has no network mode and must not gain one.

## License

[AGPL-3.0](LICENSE), or a separate commercial agreement with CompleteTech LLC.
See [LICENSING.md](LICENSING.md) and the
[contribution terms](CONTRIBUTING.md#licensing-of-contributions).
Names and branding are governed by [BRAND_ASSETS.md](BRAND_ASSETS.md).

Copyright © 2026 CompleteTech LLC.
