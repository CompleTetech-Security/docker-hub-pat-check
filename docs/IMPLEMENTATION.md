# Implementation checklist

**docker-hub-pat-check · CVE-2026-105445 · implementation pending**

This is the local work plan for one exploit. Unchecked items are outstanding;
repository initialization does not satisfy the implementation or release gates.
Use [node2shell-check](https://github.com/CompleteTech-LLC/node2shell-check) and [php2shell-check](https://github.com/CompleteTech-LLC/php2shell-check) as format and quality references, while adapting evidence
collection to the specific product and advisory.

## 1. Confirm this exploit's contract

- [ ] Re-read the primary sources listed in [README.md](../README.md#primary-sources).
- [ ] Confirm `CVE-2026-105445` and its aliases refer to the same vulnerability.
- [ ] Preserve the exact affected ranges, supported branches, and fixed-build exceptions.
- [ ] Resolve source discrepancies explicitly or keep the disputed cases `unknown`.
- [ ] Record the source URL, retrieval/review date, evidence type, and relevant product for each rule.
- [ ] Treat platform conditions and configuration mitigations separately from patch state.

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
- Vendor sent impacted-user/owner notifications on October 2 and says unnotified accounts were not exposed. This is a separate distinct exploit even though report discourages a standalone scanner.

## Vendor evidence gate

- [ ] Specify the vendor notification, support statement, account history, or authenticated export needed.
- [ ] Record who supplied the evidence and when, without recording credentials or personal account data.
- [ ] Return `unknown` when authoritative evidence is unavailable; do not substitute a generic version comparison.
- [ ] Document cases where only the vendor can determine historical exposure.

## 2. Implement the minimum useful evidence collector

- [ ] Define a small input schema for version/build provenance and this exploit's preconditions.
- [ ] Prefer a standalone Python 3.10+ standard-library implementation when it fits the product.
- [ ] Make offline modes perform no network requests and execute no application code.
- [ ] Use explicit operator-provided facts or narrowly scoped local metadata collection.
- [ ] Do not import the application, decode attacker-controlled input, execute uploaded code, or exercise the vulnerable path.
- [ ] Avoid collecting credentials, environment variables, hostnames, process arguments, or application data.
- [ ] Bound file size, file count, recursion, and parsing work for supplied evidence; keep symlink/archive handling explicit.
- [ ] If source patterns are examined, label them as review hints, not proof of reachability or taint.

## 3. Preserve uncertainty in the assessment

- [ ] Keep `version_status`, precondition observations, and `exploitability` separate.
- [ ] Emit `exploitability: not_tested` for every future finding.
- [ ] Use `potentially_affected` only when evidence matches this advisory's documented range or condition.
- [ ] Use `fixed_version_reported` only for a supported comparison, without claiming verified deployed patches.
- [ ] Keep missing, malformed, conflicting, prerelease, vendor/custom-build, possible-backport, and uncovered-future cases `unknown`.
- [ ] Document unsupported-version handling only where the vendor's lifecycle evidence supports it.
- [ ] Never convert absent source matches, hidden versions, authentication walls, or blocked requests into a clean result.
- [ ] Recommend a supported remediation based on the applicable vendor branch; avoid a universal threshold across incompatible branches.

## 4. Add usable reports and documented operation

- [ ] Define JSON and CSV fields, schema version, evidence confidence, rule date, sources, and remediation.
- [ ] Add a self-contained, script-free HTML report with escaped values and synthetic examples when useful.
- [ ] Protect CSV consumers from formula injection and keep private paths/data out of shared examples.
- [ ] Provide actual CLI help, input examples, exit-status semantics, and output-overwrite behavior.
- [ ] Preserve completed results during interruption; distinguish findings from operational errors.
- [ ] Add report branding controls only when the reporting implementation exists.

## 5. Gate any optional network mode

- [ ] Establish whether passive metadata can answer this exploit's question; omit network mode if it cannot.
- [ ] Require explicit target selection and ordinary, bounded requests with verified TLS.
- [ ] Follow robots policy where applicable; use a descriptive User-Agent, pacing, bounded bodies, and conservative redirects.
- [ ] Do not inherit environment proxies, downgrade HTTPS, bypass authentication, retry around restrictions, or request sensitive paths.
- [ ] Keep real assessment targets and data out of automated tests and repository history.

## 6. Verify behavior and release honestly

- [ ] Add focused synthetic tests for each relevant affected/fixed boundary and disputed case.
- [ ] Cover malformed inputs, absent evidence, custom builds, and collector/output safety where implemented.
- [ ] Use local mocks or loopback fixtures; do not scan public targets in tests.
- [ ] Avoid tests that merely assert documentation wording or mirror implementation details.
- [ ] Run documented commands against the actual executable; add CI only after meaningful tests exist.
- [ ] Distinguish local validation from hosted CI status for the published commit.
- [ ] Review the diff for secrets, real inventories, unlicensed assets, and scope expansion.
- [ ] Update README implementation status only after a usable checker and its documented behavior are verified.
- [ ] Enable a detection rule only in a reviewed implementation change; keep this research record's origin and history.

## Current acceptance result

**Foundation only.** No checker implementation, scanning, exploit verification,
or production readiness is claimed. The advisory metadata is deliberately disabled.
