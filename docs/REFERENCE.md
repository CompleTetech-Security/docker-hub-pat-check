# docker-hub-pat-check: reference

`docker_hub_pat_check.py` is a standard-library-only Python 3.10+ program that
records operator-supplied vendor evidence for CVE-2026-105445. It runs on
Windows, macOS and Linux. It is **offline only**: there is no network mode,
because no public metadata can answer whether an account was exposed. It never
contacts Docker Hub, never tests tokens and never collects them.

## Inputs

Each record describes one account's evidence. Combine inputs freely; a run is
limited to 10,000 records.

| Field | Values | Meaning |
| --- | --- | --- |
| `label` | Text, at most 512 characters | Operator-chosen pseudonymous label. Defaults to `unlabeled`. Do not use a real username if you can avoid it. |
| `notification` | `received`, `not_received`, `unknown` | Whether Docker's notification email (sent 2026-10-02) reached the operator. |
| `notification_date` | `YYYY-MM-DD` | Date the notice was received. |
| `remediation` | `operator_revoked_or_rotated`, `vendor_deactivated`, `not_done`, `unknown` | Remediation of the tokens listed in the notice. |
| `remediation_date` | `YYYY-MM-DD` | Date remediation was done or observed. |
| `retained_listed_tokens` | `yes`, `no`, `unknown` | Whether any token listed in the notice was knowingly kept. The vendor did not deactivate tokens whose owners asked to keep them. |
| `evidence_source` | `vendor_email`, `vendor_support`, `vendor_statement`, `operator_attestation` | Where the evidence came from. A fixed list avoids recording personal data. |

Empty or absent values are treated as not supplied. Values are trimmed and
case-insensitive.

### Command line

```sh
python docker_hub_pat_check.py --label example-account --notification received \
  --notification-date 2026-10-02 --remediation vendor_deactivated \
  --remediation-date 2026-10-08 --retained-listed-tokens no --evidence-source vendor_email
```

Supplying any record option creates one record from the command line.

### JSON (`--inventory FILE`, repeatable)

A single object or an array of objects. Each needs `"schema_version": 1` and may
use only the fields above (`null` means not supplied). See
[examples/evidence.example.json](../examples/evidence.example.json).

### CSV (`--evidence-csv FILE`, repeatable)

UTF-8 with a header row naming only the fields above. See
[examples/evidence.example.csv](../examples/evidence.example.csv).

### Input safety

Files are limited to 4 MiB and 10,000 records; strings to 512 characters.
Unsupported fields, duplicate JSON keys, non-finite numbers, wrong types,
control characters, wrong column counts, stray or unterminated CSV quotes, symlink loops and unreadable files, and invalid JSON or CSV are **operational
errors** (exit 2). A value containing a Docker-prefixed token pattern (`dckr_` plus three
letters and an underscore) is also an error, and the value is not echoed. Only that prefix is detected; other credential formats are not, so never supply any credential.
The output path and `--brand` are validated before any input is read. Error messages never echo supplied text (field names, column names, paths, argument values); they describe the problem by position or count. Unrecognized enum values and invalid dates in an otherwise valid record are
assessment results: `unknown` with `malformed_evidence`.

## Assessment

| Status | Condition |
| --- | --- |
| `potentially_affected` | `notification` is `received` and remediation is not fully reported. |
| `fixed_version_reported` | `notification` is `received`, `remediation` is `operator_revoked_or_rotated` or `vendor_deactivated`, a `remediation_date` is supplied and `retained_listed_tokens` is `no`. No version is compared. |
| `unknown` | Everything else. |

`evidence_status` explains the outcome:

| Value | Status | Reason |
| --- | --- | --- |
| `remediation_reported` | `fixed_version_reported` | Complete remediation evidence. Not a guarantee. |
| `remediation_not_reported` | `potentially_affected` | Remediation reported as `not_done`. |
| `remediation_unknown` | `potentially_affected` | Notice received; remediation missing or `unknown`. |
| `remediation_incomplete` | `potentially_affected` | Remediation reported but the date is missing or retained tokens are not confirmed absent. |
| `vendor_unnotified_claim` | `unknown` | `not_received`. Docker's claim that unnotified accounts were not exposed is recorded and attributed, not accepted as proof. |
| `conflicting_evidence` | `unknown` | `not_received` combined with a notification date, remediation date, completed remediation or a retained-token answer; or `received` with a remediation date but no completed remediation (for example `not_done` plus a date). |
| `evidence_incomplete` | `unknown` | Other evidence without a notification status. |
| `evidence_absent` | `unknown` | No evidence. Absence is never clean. |
| `malformed_evidence` | `unknown` | Unrecognized value or invalid date. |
| `conflicting_evidence` (deactivation date) | `unknown` | `vendor_deactivated` with a remediation date before 2026-10-08, the date Docker reports. |
| `date_outside_vendor_timeline` | `unknown` | Notification date before 2026-10-02, remediation date before the exposure start (2024-08-26), or either date in the future. |

`exploitability` is always `not_tested`. `version_status` does not exist because
there is no version rule. The tool compares dates against the vendor timeline
using the machine's UTC date, so a local date that is still tomorrow in UTC is rejected as in the future. The date bounds are source-backed and separate. An operator's own revocation or rotation may be dated any day from the exposure start (2024-08-26) to today, because 2026-09-30 is Docker's service-fix date and not an earliest date for an operator's action. The notification date must not precede Docker's 2026-10-02 emails. A `vendor_deactivated` claim must not be dated before Docker's 2026-10-08 deactivation, otherwise it is `conflicting_evidence`. Rerunning an old copy does not update its rules.

## Outputs

`--format csv|json|html` (default `csv`), `--output FILE`, `--force`, `--brand NAME`.

- **CSV** has one flat row per record with a `complete` column (`true` or `false`), every field quoted, `\n` line endings, and the same fields as JSON including `schema_version`, rules date and sources. Lists are joined with ` | `. Values that
  start with `=`, `+`, `-`, `@`, tab or carriage return get a leading apostrophe.
- **JSON** is an object with `tool`, `tool_version`, `schema_version`, `rules_as_of`, `generated_at`,
  `complete`, `rules` (each with statement, source URL and review date) and `results`.
- **HTML** (a table with label, assessment, notification, remediation, retained tokens, evidence source and next steps) is one self-contained, script-free page with a restrictive
  Content-Security-Policy, escaped values, light/dark themes and print styles.
  [docs/example-report.html](example-report.html) is rendered from synthetic data.

Existing output files are refused without `--force`. Output is written to a
temporary file and published atomically (a hard link without `--force`, so the
destination filesystem must support hard links). The output must differ from every
input file, even with `--force`, and its directory must already exist. With no
`--output`, the report goes to stdout.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Completed. Findings do not change this unless `--fail-on-finding` is set. |
| `1` | `--fail-on-finding` was set and at least one `potentially_affected` result exists. |
| `2` | Argument, input or output error. Takes precedence over `1`. |
| `130` | Interrupted. Completed observations are preserved where possible; the publication rules below distinguish pre-publication recovery, interrupted stdout and an already-published report. |

## Result fields

`schema_version` (`1`), `label`, `source` (`cli`, `inventory`, `csv`), the seven input fields echoed as
supplied after trimming, `docker_hub_pat_status`, `docker_hub_pat_evidence_status`,
`docker_hub_pat_exploitability`, `docker_hub_pat_cves`, `docker_hub_pat_rules_as_of`,
`docker_hub_pat_sources`, `docker_hub_pat_notes`, `docker_hub_pat_recommendation`
and `checked_at`.

## Source verification

The vendor post is the primary source and wins any disagreement. On 2026-10-24 the CVE record ([CVE.org record](https://cveawg.mitre.org/api/cve/CVE-2026-105445)) and the [NVD entry](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-105445) were also checked. Both give the affected window as 2024-08-26T20:33:00Z up to (`lessThan`) 2026-09-30T19:10:00Z, matching the vendor post, with the vendor as the assigner. NVD shows the entry as awaiting analysis. The researchers' write-up at <https://ghostpat.com/> repeats the vendor's 2026-10-02 notification and 2026-10-08 deactivation dates. No disagreement was found. The vendor describes the fix time as approximate and labels the notification time "EST" in October; only dates are used.

## Rules and sources

All rules come from <https://www.docker.com/blog/docker-hub-security-advisory-cve-2026-105445/>,
reviewed 2026-10-24: the exposure window, the 2026-10-02 notification, the claim that
unnotified accounts were not exposed, the 2026-10-08 vendor deactivation and the
absence of a version rule. The post does not describe an audit-log review procedure,
so none is encoded; it says the vendor now records token ownership changes.

## Handling reports

A report written with `--output` is created with owner-only permissions (mode 0600 on POSIX systems, through a temporary file). Report data printed to stdout, and files on Windows, follow ordinary platform defaults.


Reports contain whatever labels and dates you supply and can be sensitive.
Use pseudonymous labels, keep inputs and reports outside version control, and
apply your own retention policy. The tool does not retain anything.

## Development checks

```sh
python -m unittest -v
python docker_hub_pat_check.py --help
git diff --check
```

Tests use synthetic input and a temporary directory only; they make no network
requests. GitHub Actions runs them on Linux and Windows with Python 3.10 and 3.14.

## Report publication and interruption

Reports are fully rendered and UTF-8 checked before output starts. An interruption before publication can trigger one incomplete-report attempt; a second interruption can prevent recovery. After stdout starts, no second report is appended and the stream may be truncated. After atomic file publication succeeds, the completed bytes and their original completeness flag are preserved, including when interruption arrives before Python records success. Destination identity is reconciled against the staged inode; an unrelated competing file is not treated as our report. A retry barrier is set inside the guarded try before mutation. If destination metadata cannot be read or a second interruption occurs during reconciliation, the outcome remains unknown and the barrier prevents retry without claiming success. Proven absence or a different inode clears the barrier; matching the staged inode proves publication. The original no-clobber/`--force` choice remains in effect.

CSV retains its existing column order and appends `record_type`: `result` for asset observations, `summary` for a zero-result report. A summary preserves the completeness flag, schema/rule metadata and `not_tested` without inventing an asset finding; consumers must distinguish it from an asset row. NUL-containing CSV input/output is an operational error (exit 2) before stdout, new-file publication or forced replacement. Existing stricter control-character input policies remain in effect. Formula prefixes are neutralized after mixed leading whitespace, including Unicode whitespace.
