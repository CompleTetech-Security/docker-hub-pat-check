# Repository instructions

Read [README.md](README.md), [CONTRIBUTING.md](CONTRIBUTING.md),
[SECURITY.md](SECURITY.md), and [docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md)
before changing this project.

## Scope and current state

This repository covers only **CVE-2026-105445** (Docker Hub account-conversion PAT reassignment). Its aliases
refer to the same exploit. Keep unrelated vulnerabilities in separate repositories.
The repository contains an offline vendor-evidence recorder (`docker_hub_pat_check.py`)
with unit tests and a CI workflow. There is no version rule and no network mode;
never add either, never probe Docker Hub, and never accept or log tokens.

## Project map

- `docker_hub_pat_check.py`: standalone stdlib-only checker (assessment, inputs, CSV/JSON/HTML reports).
- `test_assessment.py`: boundary and safety tests (`python -m unittest -v`).
- `examples/`: synthetic evidence files. `docs/example-report.html` and `docs/images/report-*.png` are rendered from them.
- `.github/workflows/tests.yml`: Linux/Windows, Python 3.10 and 3.14.
- `advisory.json`: source-reviewed record for the vendor-evidence rule.
- `README.md`, `docs/REFERENCE.md`: usage, vocabulary, fields, limits, exit codes.
- `docs/IMPLEMENTATION.md`: implementation and verification checklist.
- `LICENSING.md`, `CONTRIBUTING.md`, `BRAND_ASSETS.md`: licensing and contribution terms.

## Implementation constraints

Follow the established [node2shell-check](https://github.com/CompleteTech-LLC/node2shell-check) and [php2shell-check](https://github.com/CompleteTech-LLC/php2shell-check) conventions. Prefer a small, auditable,
dependency-free checker when appropriate. Do not turn this project into a generic
product scanner or execute exploit payloads.

Version claims are evidence, not verified runtime state. Keep missing, conflicting,
malformed, prerelease, vendor/custom-build, backport, and uncovered-future cases
uncertain. Never equate `potentially_affected` with confirmed exploitability or
`fixed_version_reported` with a safety guarantee. Exploitability remains
`not_tested`. Configuration hints and source patterns are not proven reachability.

Keep offline modes offline. Any future collector must avoid application imports,
secrets, environment variables, hostnames, process arguments, and application data.
If passive fetching is justified, preserve verified TLS, relevant robots policy,
an honest User-Agent, pacing, bounds, conservative redirects, and no inherited
environment proxy. Editing this repository does not authorize scanning real targets.

Update sources and verification dates only after primary-source review. Preserve
all advisory caveats and document unresolved conflicts. A claim of no vendor
notification is the vendor's claim and stays `unknown`.

## Validation and delivery

Use focused synthetic cases and local-only fixtures for behavior tests. Do not invent passing tests, add prose-only tests, or publish
private assessments. Keep CLI, schemas, methodology, and README aligned. Distinguish
local results from hosted CI on the exact published commit. Preserve unrelated
work and follow the licensing and brand policies linked above.
