"""Synthetic report provenance regressions; no accounts or tokens."""
import contextlib
import csv
from dataclasses import asdict
import io
import json
import unittest
from unittest.mock import patch

import docker_hub_pat_check as checker


class ProvenanceTests(unittest.TestCase):
    def test_csv_identity_is_appended_authoritative_and_complete(self):
        row = asdict(checker.make_result({'notification': 'unknown'}, 'cli', 'synthetic'))
        row.update(tool='=untrusted', tool_version='=untrusted', generated_at='=untrusted')
        for complete, rows in ((True, [row]), (False, [row]), (True, []), (False, [])):
            with self.subTest(complete=complete, count=len(rows)):
                output = io.StringIO()
                checker.write_report(output, rows, format='csv', complete=complete,
                                     generated_at='2026-10-26T00:00:00+00:00')
                reader = csv.DictReader(io.StringIO(output.getvalue()))
                self.assertEqual(list(checker.Result.__dataclass_fields__) +
                                 ['complete', 'record_type', 'tool', 'tool_version', 'generated_at'], reader.fieldnames)
                value = list(reader)[0]
                self.assertEqual('docker-hub-pat-check', value['tool'])
                self.assertEqual(checker.TOOL_VERSION, value['tool_version'])
                self.assertEqual('2026-10-26T00:00:00+00:00', value['generated_at'])
                self.assertEqual(str(complete).lower(), value['complete'])
                self.assertEqual('result' if rows else 'summary', value['record_type'])

    def test_html_observation_time_is_distinct_and_escaped(self):
        row = asdict(checker.make_result({'notification': 'unknown'}, 'cli', 'synthetic'))
        row['checked_at'] = '2026-10-25T01:00:00+00:00'
        first = checker.render_html([row], generated_at='fixed render')
        row['checked_at'] = '<script>different</script>'
        second = checker.render_html([row], generated_at='fixed render')
        self.assertNotEqual(first, second)
        self.assertIn('Assessment time (UTC)', first)
        self.assertIn('2026-10-25T01:00:00+00:00', first)
        self.assertIn('Report generated', first)
        self.assertIn('&lt;script&gt;different&lt;/script&gt;', second)
        self.assertNotIn('<script>different</script>', second)

    def test_interrupted_render_reuses_run_timestamp(self):
        original = checker.write_report
        times = []
        def render(output, rows, **options):
            times.append(options.get('generated_at'))
            if len(times) == 1:
                raise KeyboardInterrupt
            return original(output, rows, **options)
        for fmt in ('json', 'csv', 'html'):
            times.clear()
            output = io.StringIO()
            with patch.object(checker, 'write_report', render), contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
                code = checker.main(['--notification', 'unknown', '--format', fmt])
            self.assertEqual(130, code)
            self.assertEqual(2, len(times))
            self.assertTrue(times[0])
            self.assertEqual(times[0], times[1])
            text = output.getvalue()
            if fmt == 'json':
                self.assertEqual(times[0], json.loads(text)['generated_at'])
            elif fmt == 'csv':
                self.assertEqual(times[0], next(csv.DictReader(io.StringIO(text)))['generated_at'])
            else:
                self.assertIn(times[0], text)


if __name__ == '__main__':
    unittest.main()
