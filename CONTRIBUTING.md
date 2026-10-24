# Contributing

This repository covers **CVE-2026-105445**. Start with the
[implementation checklist](docs/IMPLEMENTATION.md) and [docs/REFERENCE.md](docs/REFERENCE.md).
Submit focused pull requests for this exploit. Report flaws requiring private
disclosure according to [SECURITY.md](SECURITY.md).

## Development expectations

Follow [AGENTS.md](AGENTS.md). Prefer a standalone Python 3.10+ checker with no
third-party runtime/test dependencies when suitable. Validate primary sources
before encoding affected or fixed ranges. Preserve evidence provenance and
`unknown` for missing or conflicting facts. Keep exploitability `not_tested`.

Use offline inventories, synthetic examples, mocks, and local fixtures. Do not
commit credentials, real target lists, private reports, or exploit payloads.
Network detection must be justified, optional, ordinary, bounded, and authorized.
This checker has no network mode and must not gain one. Document implemented
behavior and actual commands, and run `python -m unittest -v` before submitting.

## Licensing of contributions

docker-hub-pat-check follows the AGPL-3.0 / commercial licensing model described in
[LICENSING.md](LICENSING.md). By submitting a contribution, you confirm that you
have the right to submit it. You license it to the public under AGPL-3.0 and
grant CompleteTech LLC a perpetual, worldwide, royalty-free, irrevocable license
to use, modify, sublicense, and distribute it under any license, including a
commercial license. You keep the copyright in your contribution.
