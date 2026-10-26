"""Bounded recovery of completed synthetic evidence during conversion."""
import contextlib
import csv
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import docker_hub_pat_check as checker


class ConversionRecoveryTests(unittest.TestCase):
    def run_interrupted(self, fmt, interrupt_at, output=None, repeated=False):
        rows = [checker.make_result({'notification': 'unknown', 'label': label}, 'cli', 'synthetic')
                for label in ('first', 'second')]
        original = checker.asdict
        calls = []
        def convert(row):
            calls.append(row)
            if len(calls) == interrupt_at or (repeated and len(calls) > interrupt_at):
                raise KeyboardInterrupt
            return original(row)
        stdout = io.StringIO()
        options = ['--inventory', 'synthetic.json', '--format', fmt]
        if output is not None:
            options += ['--output', str(output)]
        with patch.object(checker, 'load_inventory', return_value=rows), patch.object(checker, 'asdict', convert), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            code = checker.main(options)
        return code, stdout.getvalue(), len(calls)

    def assert_report(self, fmt, text):
        if fmt == 'json':
            value = json.loads(text)
            self.assertFalse(value['complete'])
            self.assertEqual(['first', 'second'], [r['label'] for r in value['results']])
        elif fmt == 'csv':
            rows = list(csv.DictReader(io.StringIO(text)))
            self.assertEqual(['first', 'second'], [r['label'] for r in rows])
            self.assertTrue(all(r['complete'] == 'false' for r in rows))
        else:
            self.assertIn('Interrupted run.', text)
            self.assertIn('first', text)
            self.assertIn('second', text)

    def test_first_and_later_conversion_recover_all_completed_rows(self):
        for fmt in ('json', 'csv', 'html'):
            for position in (1, 2):
                with self.subTest(fmt=fmt, position=position):
                    code, text, calls = self.run_interrupted(fmt, position)
                    self.assertEqual(130, code)
                    self.assertEqual(position + 2, calls)
                    self.assert_report(fmt, text)

    def test_repeated_conversion_interrupt_stops_without_publication(self):
        for fmt in ('json', 'csv', 'html'):
            with self.subTest(fmt=fmt), tempfile.TemporaryDirectory() as directory:
                code, text, calls = self.run_interrupted(fmt, 1, repeated=True)
                self.assertEqual((130, '', 2), (code, text, calls))
                target = Path(directory)/'report'
                code, text, calls = self.run_interrupted(fmt, 1, target, repeated=True)
                self.assertEqual(130, code)
                self.assertEqual(2, calls)
                self.assertEqual('', text)
                self.assertFalse(target.exists())
                self.assertEqual([], list(Path(directory).iterdir()))

    def test_recovery_publishes_once_without_clobber(self):
        for fmt in ('json', 'csv', 'html'):
            with self.subTest(fmt=fmt), tempfile.TemporaryDirectory() as directory:
                target = Path(directory)/'report'
                code, text, _ = self.run_interrupted(fmt, 2, target)
                self.assertEqual(130, code)
                self.assertEqual('', text)
                self.assert_report(fmt, target.read_text(encoding='utf-8'))
                target.write_bytes(b'existing synthetic evidence')
                code, text, _ = self.run_interrupted(fmt, 1, target)
                self.assertEqual(2, code)
                self.assertEqual('', text)
                self.assertEqual(b'existing synthetic evidence', target.read_bytes())
                self.assertEqual([target], list(Path(directory).iterdir()))

    def test_output_created_during_conversion_is_preserved(self):
        for fmt in ('json', 'csv', 'html'):
            with self.subTest(fmt=fmt), tempfile.TemporaryDirectory() as directory:
                target = Path(directory)/'report'
                row = checker.make_result({'notification': 'unknown'}, 'cli', 'synthetic')
                original = checker.asdict
                calls = []
                def convert(value):
                    calls.append(value)
                    if len(calls) == 1:
                        target.write_bytes(b'concurrent synthetic evidence')
                        raise KeyboardInterrupt
                    return original(value)
                stdout = io.StringIO()
                with patch.object(checker, 'load_inventory', return_value=[row]), patch.object(checker, 'asdict', convert), contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
                    code = checker.main(['--inventory', 'synthetic.json', '--format', fmt, '--output', str(target)])
                self.assertEqual(2, code)
                self.assertEqual('', stdout.getvalue())
                self.assertEqual(2, len(calls))
                self.assertEqual(b'concurrent synthetic evidence', target.read_bytes())
                self.assertEqual([target], list(Path(directory).iterdir()))


if __name__ == '__main__':
    unittest.main()
