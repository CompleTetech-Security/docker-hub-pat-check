"""Boundary tests for the offline vendor-evidence assessment. Synthetic inputs only; no network."""

import csv
import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import date
from pathlib import Path

import docker_hub_pat_check as tool
from docker_hub_pat_check import assess_pat_evidence, main, render_html

TODAY = date(2026, 10, 24)
HERE = Path(__file__).resolve().parent


def assess(**kwargs):
    return assess_pat_evidence(today=TODAY, **kwargs)


FULL = dict(notification="received", notification_date="2026-10-02", remediation="vendor_deactivated",
            remediation_date="2026-10-08", retained_listed_tokens="no", evidence_source="vendor_email")


class AssessmentTests(unittest.TestCase):
    def test_every_result_keeps_exploitability_not_tested(self):
        for case in (FULL, {}, {"notification": "not_received"}, {"notification": "bogus"}, {"notification": "received"}):
            with self.subTest(case=case):
                self.assertEqual("not_tested", assess(**case)["exploitability"])

    def test_absent_and_unknown_evidence_stay_unknown(self):
        for case in ({}, {"notification": "unknown"}, {"notification": "  "}):
            with self.subTest(case=case):
                outcome = assess(**case)
                self.assertEqual("unknown", outcome["status"])
                self.assertEqual("evidence_absent", outcome["evidence_status"])

    def test_other_evidence_without_notification_status_is_incomplete_unknown(self):
        outcome = assess(remediation="vendor_deactivated", remediation_date="2026-10-08")
        self.assertEqual(("unknown", "evidence_incomplete"), (outcome["status"], outcome["evidence_status"]))

    def test_not_received_is_never_clean_or_fixed(self):
        outcome = assess(notification="not_received")
        self.assertEqual(("unknown", "vendor_unnotified_claim"), (outcome["status"], outcome["evidence_status"]))

    def test_not_received_with_dates_or_remediation_conflicts(self):
        for extra in ({"notification_date": "2026-10-02"}, {"remediation": "operator_revoked_or_rotated"}, {"remediation_date": "2026-10-08"}):
            with self.subTest(extra=extra):
                outcome = assess(notification="not_received", **extra)
                self.assertEqual(("unknown", "conflicting_evidence"), (outcome["status"], outcome["evidence_status"]))

    def test_received_with_full_remediation_reports_remediation_only(self):
        for kind in ("vendor_deactivated", "operator_revoked_or_rotated"):
            outcome = assess(**{**FULL, "remediation": kind})
            self.assertEqual(("fixed_version_reported", "remediation_reported"), (outcome["status"], outcome["evidence_status"]))

    def test_received_without_complete_remediation_is_potentially_affected(self):
        cases = {
            "remediation_not_reported": dict(notification="received", remediation="not_done"),
            "remediation_unknown": dict(notification="received"),
            "remediation_incomplete": {**FULL, "remediation_date": ""},
        }
        cases["remediation_incomplete_retained_yes"] = {**FULL, "retained_listed_tokens": "yes"}
        cases["remediation_incomplete_retained_unknown"] = {**FULL, "retained_listed_tokens": ""}
        for name, case in cases.items():
            with self.subTest(name=name):
                outcome = assess(**case)
                self.assertEqual("potentially_affected", outcome["status"])
                self.assertEqual(name.split("_retained")[0], outcome["evidence_status"])

    def test_received_without_date_is_still_potentially_affected(self):
        outcome = assess(notification="received", notification_date="")
        self.assertEqual("potentially_affected", outcome["status"])

    def test_date_boundaries(self):
        cases = [
            ("notification_date", "2026-10-01", "date_outside_vendor_timeline"),
            ("notification_date", "2026-10-02", None),
            ("notification_date", "2026-10-24", None),
            ("notification_date", "2026-10-25", "date_outside_vendor_timeline"),
            ("remediation_date", "2026-09-29", "date_outside_vendor_timeline"),
            ("remediation_date", "2026-09-30", None),
            ("remediation_date", "2026-10-25", "date_outside_vendor_timeline"),
        ]
        for key, value, expected in cases:
            with self.subTest(key=key, value=value):
                outcome = assess(**{**FULL, key: value})
                if expected:
                    self.assertEqual(("unknown", expected), (outcome["status"], outcome["evidence_status"]))
                else:
                    self.assertEqual("fixed_version_reported", outcome["status"])

    def test_malformed_values_are_unknown(self):
        bad = [
            {"notification": "yes"}, {"notification": "Received!"}, {"notification": 1}, {"notification": True},
            {**FULL, "notification_date": "2026-13-01"}, {**FULL, "notification_date": "2026-10-2"},
            {**FULL, "notification_date": "２０２６-10-02"}, {**FULL, "notification_date": "2026-02-30"},
            {**FULL, "remediation": "fixed"}, {**FULL, "remediation_date": "yesterday"},
            {**FULL, "retained_listed_tokens": "maybe"}, {**FULL, "evidence_source": "rumor"},
        ]
        for case in bad:
            with self.subTest(case=case):
                outcome = assess(**case)
                self.assertEqual(("unknown", "malformed_evidence"), (outcome["status"], outcome["evidence_status"]))

    def test_case_and_whitespace_are_normalized(self):
        outcome = assess(**{**FULL, "notification": " RECEIVED ", "remediation": "Vendor_Deactivated"})
        self.assertEqual("fixed_version_reported", outcome["status"])


class InputTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.root = Path(self.dir.name)

    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            try:
                code = main([str(a) for a in argv])
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def write(self, name, text):
        path = self.root / name
        path.write_bytes(text.encode("utf-8"))
        return path

    def test_exit_codes_distinguish_findings_from_errors(self):
        args = ("--notification", "received")
        self.assertEqual(0, self.run_main(*args)[0])
        self.assertEqual(1, self.run_main(*args, "--fail-on-finding")[0])
        self.assertEqual(0, self.run_main("--notification", "not_received", "--fail-on-finding")[0])
        self.assertEqual(2, self.run_main("--inventory", self.root / "missing.json")[0])
        self.assertEqual(2, self.run_main(*args, "--fail-on-finding", "--inventory", self.root / "missing.json")[0])
        self.assertEqual(2, self.run_main()[0])

    def test_json_envelope_and_fields(self):
        code, out, _ = self.run_main("--notification", "received", "--format", "json")
        self.assertEqual(0, code)
        data = json.loads(out)
        self.assertTrue(data["complete"])
        self.assertEqual(tool.RULES_DATE, data["rules_as_of"])
        self.assertEqual("potentially_affected", data["results"][0]["docker_hub_pat_status"])
        self.assertEqual("not_tested", data["results"][0]["docker_hub_pat_exploitability"])

    def test_inventory_accepts_object_or_array(self):
        one = self.write("one.json", json.dumps({"schema_version": 1, "notification": "received"}))
        many = self.write("many.json", json.dumps([{"schema_version": 1}, {"schema_version": 1, "notification": "not_received"}]))
        code, out, _ = self.run_main("--inventory", one, "--inventory", many, "--format", "json")
        self.assertEqual(0, code)
        self.assertEqual(3, len(json.loads(out)["results"]))

    def test_invalid_inventories_are_operational_errors(self):
        good = {"schema_version": 1}
        cases = {
            "badjson": "{", "empty_array": "[]", "scalar": "3", "no_schema": "{}",
            "schema2": json.dumps({"schema_version": 2}), "schema_bool": '{"schema_version": true}',
            "unknown_field": json.dumps({**good, "username": "x"}),
            "wrong_type": json.dumps({**good, "notification": 5}),
            "dup_key": '{"schema_version": 1, "schema_version": 1}',
            "nan": '{"schema_version": NaN}',
            "long": json.dumps({**good, "label": "a" * 513}),
            "control": json.dumps({**good, "label": "a\u0007b"}),
            "token_label": json.dumps({**good, "label": "dckr_pat_" + "x" * 20}),
            "token_in_source": json.dumps({**good, "evidence_source": "DCKR_PAT_abc"}),
            "nonobject": json.dumps([good, 1]),
        }
        for name, text in cases.items():
            with self.subTest(name=name):
                code, out, err = self.run_main("--inventory", self.write(name + ".json", text))
                self.assertEqual(2, code)
                self.assertNotIn("dckr_pat_xxx", err)

    def test_inventory_size_and_count_bounds(self):
        big = self.write("big.json", " " * (tool.MAX_INPUT + 1))
        self.assertEqual(2, self.run_main("--inventory", big)[0])
        many = self.write("many.json", json.dumps([{"schema_version": 1}] * (tool.MAX_RECORDS + 1)))
        self.assertEqual(2, self.run_main("--inventory", many)[0])

    def test_csv_list_input(self):
        path = self.write("e.csv", "label,notification,remediation\r\nacct,received,not_done\r\nother,not_received,\r\n")
        code, out, _ = self.run_main("--evidence-csv", path, "--format", "json")
        self.assertEqual(0, code)
        statuses = [r["docker_hub_pat_status"] for r in json.loads(out)["results"]]
        self.assertEqual(["potentially_affected", "unknown"], statuses)

    def test_invalid_csv_is_an_operational_error(self):
        cases = {"extra_col": "label,username\r\na,b\r\n", "no_rows": "label\r\n", "short": "label,notification\r\na\r\n",
                 "long_row": "label\r\na,b\r\n", "dup": "label,label\r\na,b\r\n", "empty": ""}
        for name, text in cases.items():
            with self.subTest(name=name):
                self.assertEqual(2, self.run_main("--evidence-csv", self.write(name + ".csv", text))[0])

    def test_csv_output_neutralizes_formulas(self):
        for prefix in ("=", "+", "-", "@"):
            with self.subTest(prefix=prefix):
                code, out, _ = self.run_main("--label=" + prefix + "HYPERLINK(1)", "--notification", "received")
                self.assertEqual(0, code)
                row = next(csv.DictReader(io.StringIO(out)))
                self.assertTrue(row["label"].startswith("'" + prefix))
        self.assertEqual("'=1", tool.csv_safe("=1"))
        self.assertEqual("a | b", tool.csv_safe(["a", "b"]))

    def test_html_is_script_free_and_escapes_values(self):
        payload = "<script>alert(1)</script>\"'&"
        code, out, _ = self.run_main("--label", payload, "--notification", "received", "--format", "html", "--brand", payload)
        self.assertEqual(0, code)
        self.assertNotIn("<script", out.lower())
        self.assertNotIn(payload, out)
        self.assertIn("&lt;script&gt;", out)
        self.assertIn("default-src 'none'", out)
        for forbidden in ("http-equiv=\"refresh\"", " src=", "<link", "<iframe", "onerror="):
            self.assertNotIn(forbidden, out)

    def test_html_orders_findings_first(self):
        rows = [dict(label=l, **{"docker_hub_pat_status": s}) for l, s in
                (("zz-fixed", "fixed_version_reported"), ("mm-unknown", "unknown"), ("aa-affected", "potentially_affected"))]
        text = render_html(rows, generated_at="x")
        self.assertLess(text.index("aa-affected"), text.index("mm-unknown"))
        self.assertLess(text.index("mm-unknown"), text.index("zz-fixed"))

    def test_output_is_not_overwritten_without_force(self):
        target = self.root / "report.json"
        self.assertEqual(0, self.run_main("--notification", "received", "--format", "json", "--output", target)[0])
        first = target.read_text(encoding="utf-8")
        code, _, err = self.run_main("--notification", "not_received", "--format", "json", "--output", target)
        self.assertEqual(2, code)
        self.assertEqual(first, target.read_text(encoding="utf-8"))
        self.assertEqual(0, self.run_main("--notification", "not_received", "--format", "json", "--output", target, "--force")[0])
        self.assertNotEqual(first, target.read_text(encoding="utf-8"))
        self.assertEqual([target.name], sorted(p.name for p in self.root.iterdir()))

    def test_output_cannot_replace_an_input_even_with_force(self):
        source = self.write("in.json", json.dumps({"schema_version": 1}))
        before = source.read_text(encoding="utf-8")
        code, _, _ = self.run_main("--inventory", source, "--output", source, "--force")
        self.assertEqual(2, code)
        self.assertEqual(before, source.read_text(encoding="utf-8"))

    def test_missing_output_directory_is_an_error(self):
        self.assertEqual(2, self.run_main("--notification", "received", "--output", self.root / "nope" / "r.csv")[0])

    def test_bundled_examples_are_valid_and_synthetic(self):
        for name, flag in (("evidence.example.json", "--inventory"), ("evidence.example.csv", "--evidence-csv")):
            with self.subTest(name=name):
                code, out, _ = self.run_main(flag, HERE / "examples" / name, "--format", "json")
                self.assertEqual(0, code)
                for row in json.loads(out)["results"]:
                    self.assertTrue(row["label"].startswith("example-"))

    def test_cli_help_and_version_run(self):
        base = [sys.executable, str(HERE / "docker_hub_pat_check.py")]
        helped = subprocess.run([*base, "--help"], capture_output=True, text=True, timeout=30)
        self.assertEqual(0, helped.returncode)
        self.assertIn("--inventory", helped.stdout)
        self.assertEqual(0, subprocess.run([*base, "--version"], capture_output=True, text=True, timeout=30).returncode)

    def test_module_has_no_network_imports(self):
        source = (HERE / "docker_hub_pat_check.py").read_text(encoding="utf-8")
        for name in ("socket", "urllib", "http.client", "ssl", "requests"):
            self.assertNotRegex(source, rf"(?m)^\s*(import|from)\s+{name}\b")


if __name__ == "__main__":
    unittest.main()
