# Implementation checklist

**docker-hub-pat-check · CVE-2026-105445 · implemented (vendor-evidence only)**

This is the work plan and status for one exploit. Checked items are done and
covered by `python -m unittest -v`; items marked n/a do not apply to a tool with
no network mode and no version rule.
Use [node2shell-check](https://github.com/CompleteTech-LLC/node2shell-check) and [php2shell-check](https://github.com/CompleteTech-LLC/php2shell-check) as format and quality references, while adapting evidence
collection to the specific product and advisory.

## 1. Confirm this exploit's contract

- [x] Re-read the primary sources listed in [README.md](../README.md#primary-sources).
- [x] Confirm `CVE-2026-105445` and its aliases refer to the same vulnerability.
- n/a Affected ranges, supported branches and fixed-build exceptions: there is no version rule. The exposure window and vendor timeline are encoded instead.
- [x] Resolve source discrepancies explicitly or keep the disputed cases `unknown`.
- [x] Record the source URL, retrieval/review date, evidence type, and relevant product for each rule.
- [x] Treat platform conditions and configuration mitigations separately from patch state.

### Affected evidence to encode

```json
{
  "exposure_start": "2024-08-26T20:33:00Z",
  "type": "Historical service-side exposure; vendor notification required"
}
```

### Fix evidence to encode

```json
{
  "fixed_at": "2026-09-30T19:10:00Z",
  "type": "Vendor service remediation; no local version threshold"
}
```

### Preconditions to collect without exploitation

- vendor identified account conversion exposure

### Outstanding caveats

- No meaningful client or Docker version rule exists. Use administrator-supplied vendor notification and remediation evidence; do not infer exposure by probing Hub or testing tokens.
- Vendor sent impacted-user and organization-owner notifications on October 2, 2026 and says accounts that received no email were not exposed. This is the vendor's claim, not verified here.
- Vendor deactivated identified transferred PATs on October 8, 2026, except tokens whose owners asked to keep them.

## Vendor evidence gate

- [x] Specify the vendor notification, support statement, account history, or authenticated export needed (`evidence_source`).
- [x] Record the kind of evidence source (`evidence_source`, a fixed list) and the notification and remediation dates the operator supplies, without credentials or personal account data. `checked_at` is the tool's run time, not when the evidence was supplied.
- [x] Return `unknown` when authoritative evidence is unavailable; do not substitute a generic version comparison.
- [x] Document cases where only the vendor can determine historical exposure.

## 2. Implement the minimum useful evidence collector

- [x] Define a small input schema for vendor notification and remediation evidence (see REFERENCE.md); no version or build provenance applies.
- [x] Prefer a standalone Python 3.10+ standard-library implementation when it fits the product.
- [x] Make offline modes perform no network requests and execute no application code.
- [x] Use explicit operator-provided facts only; there is no collector.
- [x] Do not import the application, decode attacker-controlled input, execute uploaded code, or exercise the vulnerable path.
- [x] Avoid collecting credentials, environment variables, hostnames, process arguments, or application data.
- [x] Bound file size, file count, recursion, and parsing work for supplied evidence; keep symlink/archive handling explicit.
- n/a Source patterns are not examined.

## 3. Preserve uncertainty in the assessment

- [x] Keep evidence status, notification/remediation observations, and `exploitability` separate (there is no `version_status`).
- [x] Emit `exploitability: not_tested` for every future finding.
- [x] Use `potentially_affected` only when evidence matches this advisory's documented range or condition.
- [x] Use `fixed_version_reported` only for complete reported remediation evidence (no version comparison exists), without claiming verified remediation.
- [x] Keep missing, malformed, conflicting, out-of-timeline and contradictory evidence `unknown`. Date bounds are source-backed: notification not before 2026-10-02, vendor deactivation not before 2026-10-08, operator remediation not before the exposure start; the 2026-09-30 service fix is not an operator bound. Prerelease, custom-build, backport and uncovered-version cases are n/a: no version is compared.
- [x] No `unsupported_runtime` status: there is no runtime lifecycle.
- [x] Never convert absent source matches, hidden versions, authentication walls, or blocked requests into a clean result.
- [x] Recommend only the vendor's own guidance; no version threshold exists.

## 4. Add usable reports and documented operation

- [x] Define JSON and CSV fields, schema version, evidence confidence, rule date, sources, and remediation.
- [x] Add a self-contained, script-free HTML report with escaped values and synthetic examples when useful.
- [x] Protect CSV consumers from formula injection and keep private paths/data out of shared examples.
- [x] Provide actual CLI help, input examples, exit-status semantics, and output-overwrite behavior.
- [x] Findings (exit 1) are distinct from operational errors (exit 2). An interrupt while inputs load writes the already-loaded records with `complete: false` and exits 130 (tested with an injected `KeyboardInterrupt`). An interrupt during rendering or writing triggers one further write attempt with `complete: false` (tested); the write itself is atomic.
- [x] `--brand` names the organization in the HTML report. No logo option is provided.

## 5. Gate any optional network mode

- [x] Establish whether passive metadata can answer this exploit's question: it cannot. Only the vendor can say which accounts were exposed, so **no network mode exists** and none may be added.
- n/a Verified TLS, robots policy, User-Agent, pacing, bounds, redirects and proxy handling: no requests are made.
- [x] Keep real assessment targets and data out of automated tests and repository history.

## 6. Verify behavior and release honestly

- [x] Add focused synthetic tests for each relevant affected/fixed boundary and disputed case.
- [x] Cover malformed inputs, absent evidence, contradictory evidence and output safety. Custom builds and collectors are n/a.
- [x] Use local mocks or loopback fixtures; do not scan public targets in tests.
- [x] Avoid tests that merely assert documentation wording or mirror implementation details.
- [x] Run documented commands against the actual executable; add CI only after meaningful tests exist.
- [x] Distinguish local validation from hosted CI status for the published commit.
- [x] Review the diff for secrets, real inventories, unlicensed assets, and scope expansion.
- [x] Update README implementation status only after a usable checker and its documented behavior are verified.
- [x] `advisory.json` updated in the reviewed implementation change; history preserved in git.

## Current acceptance result

**Implemented as a vendor-evidence recorder.** Sources were reviewed on 2026-10-24
against the vendor post. The tool performs no scanning, exploit verification or
token testing, and makes no production-readiness claim. Hosted CI status is
reported on the pull request for the exact published commit.
