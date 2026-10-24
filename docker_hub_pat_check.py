#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-CompleteTech-Commercial
# Copyright (c) 2026 CompleteTech LLC. See LICENSING.md.
"""Offline vendor-evidence recorder for CVE-2026-105445 (Docker Hub PAT reassignment). Python 3.10+.

Records administrator-supplied Docker notification and remediation evidence. It
never contacts Docker Hub, never tests or collects tokens, and has no network mode.
"""

from __future__ import annotations

import argparse
import csv
import html
import io
import json
import os
import re
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path

TOOL_VERSION = "1.0.0"
MAX_INPUT = 4 * 1024 * 1024
MAX_RECORDS = 10000
MAX_FIELD = 512

RULES_DATE = "2026-10-24"
CVES = ("CVE-2026-105445",)
SOURCE = "https://www.docker.com/blog/docker-hub-security-advisory-cve-2026-105445/"
SOURCES = (SOURCE,)

# Vendor timeline (UTC). Dates come from the vendor post; the post gives US Eastern
# times, converted here to UTC. The remediation time is the vendor's approximation.
EXPOSURE_START = "2024-08-26T20:33:00Z"
VENDOR_FIX_AT = "2026-09-30T19:10:00Z"
FIX_DAY = date(2026, 9, 30)
NOTIFICATION_DAY = date(2026, 10, 2)

RULES = (
    {"id": "exposure-window", "statement": f"Vendor-reported exposure window: {EXPOSURE_START} to about {VENDOR_FIX_AT}.",
     "source": SOURCE, "reviewed": RULES_DATE},
    {"id": "vendor-notification", "statement": "Vendor says it emailed users whose accounts received transferred PATs, and their organization owners, on 2026-10-02.",
     "source": SOURCE, "reviewed": RULES_DATE},
    {"id": "unnotified-claim", "statement": "Vendor says an account that received no email was not exposed. This is the vendor's claim and is not independently verified here.",
     "source": SOURCE, "reviewed": RULES_DATE},
    {"id": "vendor-deactivation", "statement": "Vendor says it deactivated identified transferred PATs on 2026-10-08, except tokens whose owners asked to keep them.",
     "source": SOURCE, "reviewed": RULES_DATE},
    {"id": "no-version-rule", "statement": "The exposure was service-side and historical. No client or Docker version threshold applies.",
     "source": SOURCE, "reviewed": RULES_DATE},
)

NOTIFICATION_VALUES = ("received", "not_received", "unknown")
REMEDIATION_VALUES = ("operator_revoked_or_rotated", "vendor_deactivated", "not_done", "unknown")
REMEDIATION_DONE = ("operator_revoked_or_rotated", "vendor_deactivated")
RETAINED_VALUES = ("yes", "no", "unknown")
EVIDENCE_SOURCES = ("vendor_email", "vendor_support", "vendor_statement", "operator_attestation")
INPUT_FIELDS = ("label", "notification", "notification_date", "remediation", "remediation_date",
                "retained_listed_tokens", "evidence_source")
TOKEN_PATTERN = re.compile(r"dckr_[a-z]{3}_", re.I)
DATE_PATTERN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")

BASE_NOTES = (
    "Assessment of administrator-supplied evidence only. Docker Hub was not contacted and no token was tested or collected.",
    "Only the vendor can determine historical exposure for an account. No client or Docker version rule exists.",
    "Exploitability is not tested. Vendor-reported remediation is not a guarantee.",
)
VENDOR_GUIDANCE = (
    "Follow the vendor guidance: review personal access tokens in Docker Hub under Account settings, Personal access tokens, "
    "revoke any you do not recognize or no longer use, use organization access tokens for organization automation, "
    "and contact Docker Support with questions."
)


def _field_name(name):
    return f"docker_hub_pat_{name}"


@dataclass
class Result:
    label: str = "unlabeled"
    source: str = "cli"
    notification: str = ""
    notification_date: str = ""
    remediation: str = ""
    remediation_date: str = ""
    retained_listed_tokens: str = ""
    evidence_source: str = ""
    docker_hub_pat_status: str = "unknown"
    docker_hub_pat_evidence_status: str = "evidence_absent"
    docker_hub_pat_exploitability: str = "not_tested"
    docker_hub_pat_cves: list = field(default_factory=lambda: list(CVES))
    docker_hub_pat_rules_as_of: str = RULES_DATE
    docker_hub_pat_sources: list = field(default_factory=lambda: list(SOURCES))
    docker_hub_pat_notes: list = field(default_factory=list)
    docker_hub_pat_recommendation: str = ""
    checked_at: str = ""


class InputError(ValueError):
    """Structurally invalid input; an operational error, not an assessment result."""


def _clean(value):
    return value.strip() if isinstance(value, str) else value


def parse_day(value):
    """Return a date for a strict ASCII YYYY-MM-DD string, otherwise None."""
    if not isinstance(value, str) or not DATE_PATTERN.fullmatch(value):
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def assess_pat_evidence(
    notification="", notification_date="", remediation="", remediation_date="",
    retained_listed_tokens="", evidence_source="", *, today=None,
):
    """Assess operator-supplied vendor evidence without any network or token access.

    Absent evidence is unknown. A claim of no notification is the vendor's claim and
    is never reported as clean. Reported remediation is not a guarantee.
    """
    today = today or datetime.now(timezone.utc).date()
    result = {
        "status": "unknown",
        "evidence_status": "evidence_absent",
        "exploitability": "not_tested",
        "notes": list(BASE_NOTES),
        "recommendation": "Obtain the vendor notification status for this account from Docker (the vendor-listed support channel) and record it. " + VENDOR_GUIDANCE,
    }
    notes = result["notes"]
    raw = [notification, notification_date, remediation, remediation_date, retained_listed_tokens, evidence_source]
    if any(value is not None and not isinstance(value, str) for value in raw):
        result["evidence_status"] = "malformed_evidence"
        notes.append("Non-text evidence values cannot be interpreted.")
        return result
    n, nd, r, rd, kept, src = (str(value or "").strip().lower() for value in raw)

    def bad(message):
        result["evidence_status"] = "malformed_evidence"
        notes.append(message)
        return result

    if n and n not in NOTIFICATION_VALUES:
        return bad("Unrecognized notification value.")
    if r and r not in REMEDIATION_VALUES:
        return bad("Unrecognized remediation value.")
    if kept and kept not in RETAINED_VALUES:
        return bad("Unrecognized retained-token value.")
    if src and src not in EVIDENCE_SOURCES:
        return bad("Unrecognized evidence source.")
    n_day = r_day = None
    if nd:
        n_day = parse_day(nd)
        if n_day is None:
            return bad("Notification date must be a real YYYY-MM-DD date.")
    if rd:
        r_day = parse_day(rd)
        if r_day is None:
            return bad("Remediation date must be a real YYYY-MM-DD date.")
    for day, minimum, name in ((n_day, NOTIFICATION_DAY, "notification"), (r_day, FIX_DAY, "remediation")):
        if day is not None and (day < minimum or day > today):
            result["evidence_status"] = "date_outside_vendor_timeline"
            notes.append(
                f"The {name} date is outside the vendor timeline: it must not precede {minimum.isoformat()} "
                "or be in the future. The evidence is not accepted."
            )
            return result

    supplied = any((n_day, r_day, r, kept, src)) or n_day is not None
    if n in ("", "unknown"):
        if supplied:
            result["evidence_status"] = "evidence_incomplete"
            notes.append("Other evidence was supplied, but the vendor notification status is missing or unknown.")
        else:
            notes.append("No evidence was supplied. Missing evidence is unknown, never a clean result.")
        return result

    if n == "not_received":
        if n_day is not None or r in REMEDIATION_DONE or r_day is not None:
            result["evidence_status"] = "conflicting_evidence"
            notes.append("A notification date or reported remediation conflicts with a statement that no notification was received.")
            return result
        result["evidence_status"] = "vendor_unnotified_claim"
        notes.append(
            "No notification was reported. The vendor says accounts it did not email were not exposed; this is the vendor's claim "
            "and is not proof. It is not treated as a clean result."
        )
        result["recommendation"] = (
            "Keep the vendor statement attributed to Docker. If doubt remains, ask Docker Support to confirm the account's status. " + VENDOR_GUIDANCE
        )
        return result

    # Notification received: the vendor's own notice indicates exposure, not abuse.
    result["status"] = "potentially_affected"
    notes.append("The vendor notified this account, which indicates a transferred PAT was in scope. The vendor reports no evidence of exploitation; that is not a guarantee.")
    if n_day is None:
        notes.append("The notification date was not supplied.")
    complete = r in REMEDIATION_DONE and r_day is not None and kept == "no"
    if complete:
        result["status"] = "fixed_version_reported"
        result["evidence_status"] = "remediation_reported"
        notes.append("Remediation was reported by the operator. It is not verified here and is not a safety guarantee. No version comparison is involved.")
        result["recommendation"] = "Retain the vendor notice and remediation record under your own policy. Re-review personal access tokens periodically. " + VENDOR_GUIDANCE
        return result
    if r in REMEDIATION_DONE:
        result["evidence_status"] = "remediation_incomplete"
        notes.append("Remediation was reported but the remediation date is missing, or retained tokens are not confirmed absent. The vendor says tokens whose owners asked to keep them were not deactivated.")
    elif r == "not_done":
        result["evidence_status"] = "remediation_not_reported"
        notes.append("Remediation of the listed tokens was reported as not done.")
    else:
        result["evidence_status"] = "remediation_unknown"
        notes.append("Remediation of the listed tokens was not reported.")
    result["recommendation"] = "Find the tokens listed in the vendor notification (by description and creation date) and revoke or rotate those you do not need. " + VENDOR_GUIDANCE
    return result


def _reject_text(value, where):
    if len(value) > MAX_FIELD:
        raise InputError(f"{where}: value exceeds {MAX_FIELD} characters")
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise InputError(f"{where}: control characters are not allowed")
    if TOKEN_PATTERN.search(value):
        raise InputError(f"{where}: a value resembles a Docker access token; never supply tokens")


def make_result(record: dict, source: str, where: str, today=None) -> Result:
    unknown = sorted(set(record) - set(INPUT_FIELDS) - {"schema_version"})
    if unknown:
        raise InputError(f"{where}: unsupported field(s): {', '.join(k[:64] for k in unknown)}")
    values = {}
    for key in INPUT_FIELDS:
        value = record.get(key)
        if value is None:
            value = ""
        if not isinstance(value, str):
            raise InputError(f"{where}: {key} must be text or null")
        _reject_text(value, f"{where}: {key}")
        values[key] = value.strip()
    label = values.pop("label") or "unlabeled"
    outcome = assess_pat_evidence(**values, today=today)
    return Result(
        label=label, source=source, **values,
        docker_hub_pat_status=outcome["status"], docker_hub_pat_evidence_status=outcome["evidence_status"],
        docker_hub_pat_exploitability=outcome["exploitability"], docker_hub_pat_notes=outcome["notes"],
        docker_hub_pat_recommendation=outcome["recommendation"],
        checked_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def _read_bounded(path: Path, what: str) -> str:
    with path.open("rb") as stream:
        raw = stream.read(MAX_INPUT + 1)
    if len(raw) > MAX_INPUT:
        raise InputError(f"{what} exceeds the 4 MiB limit")
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise InputError(f"{what} is not valid UTF-8") from exc


def _no_duplicates(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise InputError("duplicate JSON key")
        seen[key] = value
    return seen


def _reject_constant(name):
    raise InputError("non-finite JSON number")


def load_inventory(path: Path, today=None) -> list[Result]:
    text = _read_bounded(path, "Inventory file")
    try:
        data = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise InputError("Inventory is not valid JSON") from exc
    records = data if isinstance(data, list) else [data]
    if not 1 <= len(records) <= MAX_RECORDS:
        raise InputError(f"Inventory must contain 1 to {MAX_RECORDS} records")
    results = []
    for index, record in enumerate(records, 1):
        where = f"inventory record {index}"
        if not isinstance(record, dict):
            raise InputError(f"{where}: must be an object")
        schema = record.get("schema_version")
        if type(schema) is not int or schema != 1:
            raise InputError(f"{where}: schema_version must be the integer 1")
        results.append(make_result(record, "inventory", where, today))
    return results


def load_csv(path: Path, today=None) -> list[Result]:
    text = _read_bounded(path, "CSV file")
    try:
        reader = csv.DictReader(io.StringIO(text, newline=""), strict=True)
        header = reader.fieldnames or []
        if len(set(header)) != len(header) or not header:
            raise InputError("CSV needs a header row with unique column names")
        extra = sorted(set(header) - set(INPUT_FIELDS))
        if extra:
            raise InputError("CSV has unsupported column(s): " + ", ".join(c[:64] for c in extra))
        results = []
        for index, row in enumerate(reader, 1):
            if index > MAX_RECORDS:
                raise InputError(f"CSV is limited to {MAX_RECORDS} rows")
            if None in row or None in row.values():
                raise InputError(f"CSV row {index}: wrong number of columns")
            results.append(make_result(row, "csv", f"CSV row {index}", today))
    except csv.Error as exc:
        raise InputError("CSV is malformed") from exc
    if not results:
        raise InputError("CSV contains no data rows")
    return results


def csv_safe(value):
    if isinstance(value, list):
        value = " | ".join(value)
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + value
    return value


REPORT_CSS = """
:root{--bg:#F8FAFC;--surface:#FFFFFF;--surface-2:#EEF2FF;--ink:#0F172A;--ink-2:#1E293B;--ink-3:#64748B;--line:#E2E8F0;
--accent:#1E3A8A;--accent-text:#1E3A8A;--on-accent:#FFFFFF;--bad:#B42318;--bad-bg:#FEE4E2;--ok:#067647;--ok-bg:#DCFAE6;--unk:#475467;--unk-bg:#EAECF0}
@media (prefers-color-scheme:dark){:root{--bg:#0F172A;--surface:#1E293B;--surface-2:#273449;--ink:#F1F5F9;--ink-2:#CBD5E1;--ink-3:#94A3B8;
--line:#334155;--accent-text:#93C5FD;--bad:#FDA29B;--bad-bg:#55160C;--ok:#75E0A7;--ok-bg:#053321;--unk:#D0D5DD;--unk-bg:#344054}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 Arial,system-ui,sans-serif}
main{max-width:1080px;margin:0 auto;padding:24px 16px 48px}
header{padding:20px 0;border-bottom:3px solid var(--accent);margin-bottom:20px}
.eyebrow{font-size:12px;letter-spacing:.12em;font-weight:700;color:var(--accent-text);text-transform:uppercase}
h1{margin:2px 0;font-size:26px}.sub{color:var(--ink-3);margin:0}h2{margin:32px 0 10px;font-size:18px;color:var(--ink-2)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.tile{background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:14px}
.tile b{display:block;font-size:28px;color:var(--accent-text)}.tile span{color:var(--ink-3);font-size:13px}
.tile.bad b{color:var(--bad)}.tile.ok b{color:var(--ok)}
.wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;background:var(--surface);border:1px solid var(--line)}
th{background:var(--accent);color:var(--on-accent);text-align:left;padding:8px 10px;font-size:13px;white-space:nowrap}
td{padding:8px 10px;border-top:1px solid var(--line);vertical-align:top;font-size:14px}tr:nth-child(even) td{background:var(--surface-2)}
td.notes{color:var(--ink-3);font-size:13px;min-width:240px}
code{font:13px Consolas,monospace}
.pill{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12px;font-weight:700;white-space:nowrap}
.pill.potentially_affected{color:var(--bad);background:var(--bad-bg)}.pill.fixed_version_reported{color:var(--ok);background:var(--ok-bg)}
.pill.unknown{color:var(--unk);background:var(--unk-bg)}
.callout{background:var(--surface);border:1px solid var(--line);border-left:4px solid var(--accent);border-radius:8px;padding:12px 16px;color:var(--ink-2)}
footer{margin-top:40px;padding-top:12px;border-top:1px solid var(--line);color:var(--ink-3);font-size:12px}
a{color:var(--accent-text)}
details{max-width:430px}summary{cursor:pointer;color:var(--accent-text)}details ul{padding-left:18px}
@media print{body{background:#fff}tr,.tile{break-inside:avoid}details>summary{display:none}}
"""

STATUS_ORDER = {"potentially_affected": 0, "unknown": 1, "fixed_version_reported": 2}
STATUS_LABELS = {"potentially_affected": "Potentially affected", "unknown": "Unknown",
                 "fixed_version_reported": "Remediation reported"}


def render_html(rows, *, brand="CompleteTech LLC", generated_at=None, complete=True) -> str:
    def esc(value):
        return html.escape("" if value is None else str(value), quote=True)

    generated_at = generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    key = _field_name("status")
    rows = sorted(rows, key=lambda row: STATUS_ORDER.get(row.get(key), 1))
    counts = {k: sum(row.get(key) == k for row in rows) for k in STATUS_ORDER}
    tiles = [("", len(rows), "Records assessed"), ("bad", counts["potentially_affected"], "Potentially affected"),
             ("", counts["unknown"], "Unknown"), ("ok", counts["fixed_version_reported"], "Remediation reported")]
    body = []
    for row in rows:
        status = row.get(key) if row.get(key) in STATUS_ORDER else "unknown"
        notes = "".join(f"<li>{esc(n)}</li>" for n in dict.fromkeys(row.get(_field_name("notes"), [])))
        body.append(
            "<tr>"
            f"<td>{esc(row.get('label'))}</td>"
            f"<td><span class='pill {status}'>{STATUS_LABELS[status]}</span><br><code>{esc(row.get(_field_name('evidence_status')))}</code></td>"
            f"<td>{esc(row.get('notification') or '—')}<br><code>{esc(row.get('notification_date') or '—')}</code></td>"
            f"<td>{esc(row.get('remediation') or '—')}<br><code>{esc(row.get('remediation_date') or '—')}</code></td>"
            f"<td>{esc(row.get('retained_listed_tokens') or '—')}</td>"
            f"<td class='notes'><p>{esc(row.get(_field_name('recommendation')))}</p>"
            f"<details><summary>Evidence and limitations</summary><ul>{notes}</ul></details></td></tr>"
        )
    tile_html = "".join(f"<div class='tile {cls}'><b>{value}</b><span>{esc(label)}</span></div>" for cls, value, label in tiles)
    rules = "".join(f"<tr><td><code>{esc(r['id'])}</code></td><td>{esc(r['statement'])}</td><td>{esc(r['reviewed'])}</td></tr>" for r in RULES)
    sources = " · ".join(f"<a href='{esc(url)}'>{esc(url)}</a>" for url in SOURCES)
    incomplete = "" if complete else "<p class='callout'><b>Interrupted run.</b> Only completed records are shown.</p>"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Docker Hub PAT Vendor-Evidence Report</title><style>{REPORT_CSS}</style></head><body><main>
<header><div class="eyebrow">{esc(brand)}</div><h1>Docker Hub PAT Vendor-Evidence Report</h1>
<p class="sub">CVE-2026-105445 · generated {esc(generated_at)} · rules as of {RULES_DATE}</p></header>
<p class="callout"><b>Operator-supplied vendor evidence, not a test.</b> Docker Hub was not contacted and no token was tested.
Every result has exploitability <code>not_tested</code>. A claim of no notification is the vendor's claim, not proof, and stays unknown.
Reported remediation is not a guarantee.</p>
{incomplete}<div class="tiles">{tile_html}</div>
<h2>Results</h2><div class="wrap"><table><thead><tr><th>Label</th><th>Assessment</th><th>Notification</th>
<th>Remediation</th><th>Listed tokens retained</th><th>Next step and evidence</th></tr></thead>
<tbody>{''.join(body) or '<tr><td colspan="6">No completed results.</td></tr>'}</tbody></table></div>
<h2>Vendor-reported rules</h2><div class="wrap"><table><thead><tr><th>Rule</th><th>Statement</th><th>Reviewed</th></tr></thead><tbody>{rules}</tbody></table></div>
<footer>{esc(brand)} · docker-hub-pat-check {TOOL_VERSION} · {sources}</footer>
</main></body></html>
"""


def write_report(output, rows, *, format="csv", brand="CompleteTech LLC", complete=True):
    if format == "csv":
        writer = csv.DictWriter(output, fieldnames=list(Result.__dataclass_fields__))
        writer.writeheader()
        for row in rows:
            writer.writerow({k: csv_safe(v) for k, v in row.items()})
    elif format == "json":
        json.dump({"tool": "docker-hub-pat-check", "tool_version": TOOL_VERSION, "rules_as_of": RULES_DATE,
                   "generated_at": datetime.now(timezone.utc).isoformat(), "complete": complete,
                   "rules": list(RULES), "results": rows}, output, ensure_ascii=False, indent=2)
        output.write("\n")
    else:
        output.write(render_html(rows, brand=brand, complete=complete))


def save_report(path, rows, *, force=False, **options):
    """Publish a complete file atomically, refusing an existing path by default."""
    if path is None:
        write_report(sys.stdout, rows, **options)
        return
    path = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="", dir=path.parent, prefix=".docker-hub-pat-", delete=False) as stream:
            temporary = Path(stream.name)
            write_report(stream, rows, **options)
            stream.flush()
            os.fsync(stream.fileno())
        if force:
            os.replace(temporary, path)
        else:
            os.link(temporary, path)  # Atomic no-clobber publication.
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog="Exit codes: 0 completed; 1 --fail-on-finding and a potentially_affected result; 2 input/output error; 130 interrupted.",
    )
    parser.add_argument("--version", action="version", version=f"docker-hub-pat-check {TOOL_VERSION}")
    parser.add_argument("--label", help="Operator-chosen pseudonymous label for the single record below (not a token)")
    parser.add_argument("--notification", help="Vendor notification status: " + ", ".join(NOTIFICATION_VALUES))
    parser.add_argument("--notification-date", metavar="YYYY-MM-DD", help="Date the vendor notice was received")
    parser.add_argument("--remediation", help="Remediation status: " + ", ".join(REMEDIATION_VALUES))
    parser.add_argument("--remediation-date", metavar="YYYY-MM-DD", help="Date remediation was done")
    parser.add_argument("--retained-listed-tokens", help="Whether any token listed in the notice was knowingly kept: " + ", ".join(RETAINED_VALUES))
    parser.add_argument("--evidence-source", help="Where the evidence came from: " + ", ".join(EVIDENCE_SOURCES))
    parser.add_argument("--inventory", action="append", default=[], type=Path, metavar="FILE", help="Evidence JSON object or array (schema_version 1); repeatable")
    parser.add_argument("--evidence-csv", action="append", default=[], type=Path, metavar="FILE", help="Evidence CSV with a header row; repeatable")
    parser.add_argument("--format", choices=("csv", "json", "html"), default="csv", help="Output format (default: csv)")
    parser.add_argument("--output", type=Path, help="Save report to a new file; default: stdout")
    parser.add_argument("--force", action="store_true", help="Replace an existing output file explicitly")
    parser.add_argument("--brand", default="CompleteTech LLC", help="Organization name for the HTML report")
    parser.add_argument("--fail-on-finding", action="store_true", help="Exit 1 for potentially_affected results (errors still exit 2)")
    args = parser.parse_args(argv)
    cli = {"label": args.label, "notification": args.notification, "notification_date": args.notification_date,
           "remediation": args.remediation, "remediation_date": args.remediation_date,
           "retained_listed_tokens": args.retained_listed_tokens, "evidence_source": args.evidence_source}
    rows = []
    try:
        if any(v is not None for v in cli.values()):
            rows.append(make_result(cli, "cli", "command line"))
        for path in args.inventory:
            rows.extend(load_inventory(path))
        for path in args.evidence_csv:
            rows.extend(load_csv(path))
        if not rows:
            parser.error("provide --notification (or other evidence options), --inventory, or --evidence-csv")
        if len(rows) > MAX_RECORDS:
            raise InputError(f"A run is limited to {MAX_RECORDS} records")
        if args.output:
            inputs = [*args.inventory, *args.evidence_csv]
            if any(args.output.resolve() == p.resolve() for p in inputs):
                raise InputError("--output must differ from every input file, even with --force")
            if args.output.exists() and not args.force:
                raise InputError("Output exists; use a new path or explicitly pass --force")
            if not args.output.parent.is_dir():
                raise InputError("Output directory must already exist")
    except (OSError, ValueError, UnicodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    results = [asdict(r) for r in rows]
    try:
        save_report(args.output, results, force=args.force, format=args.format, brand=args.brand)
    except (OSError, ValueError) as exc:
        print(f"Cannot write report: {exc}", file=sys.stderr)
        return 2
    if args.fail_on_finding and any(r["docker_hub_pat_status"] == "potentially_affected" for r in results):
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        raise SystemExit(130)
