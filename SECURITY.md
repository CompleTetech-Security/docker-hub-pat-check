# Security policy

## Reporting a flaw in this project

Use the repository's **Security → Report a vulnerability** option when available
for issues needing private disclosure. Otherwise contact CompleteTech LLC
through [complete.tech](https://complete.tech) to arrange private reporting.
Include the affected commit, a minimal local reproduction, expected and actual
behavior, and impact. Omit credentials, real target lists, and third-party data.
Do not publish sensitive details in a public issue while private review is underway.

Only the current default branch is maintained. Reproduce against its latest
revision when possible. No response-time guarantee is made.

## Advisory scope and implementation status

This project is dedicated to **CVE-2026-105445**, a historical, service-side
Docker Hub exposure. It provides an offline recorder for administrator-supplied
vendor notification and remediation evidence. It has no network mode, never
contacts Docker Hub, and never tests, accepts or stores tokens. Input that looks
like a Docker token is rejected.

Output distinguishes vendor-reported evidence from confirmed exposure.
Exploitability remains `not_tested`, a claim of no notification stays `unknown`,
and reported remediation is not a guarantee. Reports contain the labels and dates
you supply; keep real inputs and reports outside the repository and apply your own
retention policy.

For a vulnerability in the affected upstream product or a service you assess,
follow that vendor's or service owner's published security-reporting process.
