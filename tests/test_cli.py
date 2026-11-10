"""End-to-end CLI tests: codes, JSON, SARIF, no-overwrite, policy assertions."""
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from sudoboundary.cli import main

EX = Path(__file__).resolve().parents[1] / 'examples'


def run(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        status = main(list(args))
    return status, out.getvalue(), err.getvalue()


class EndToEndTests(unittest.TestCase):
    def test_audit_baseline_pass(self):
        code, out, err = run('audit', '--policy', str(EX/'baseline.json'))
        self.assertEqual(0, code, err)
        self.assertEqual('audit', json.loads(out)['mode'])

    def test_audit_candidate_blocked(self):
        code, out, err = run('audit', '--policy', str(EX/'candidate-risky.json'))
        self.assertEqual(1, code, err)
        self.assertTrue(json.loads(out)['findings'])

    def test_compare_blocks_access_expansion(self):
        code, out, err = run('compare', '--baseline', str(EX/'baseline.json'), '--candidate', str(EX/'candidate-risky.json'), '--queries', str(EX/'queries.json'))
        self.assertEqual(1, code, err)
        self.assertIn('access_expanded', [x['kind'] for x in json.loads(out)['changes']])

    def test_explain_allowed(self):
        code, out, err = run('explain', '--policy', str(EX/'baseline.json'), '--request', str(EX/'request.json'))
        self.assertEqual(0, code, err)
        self.assertTrue(json.loads(out)['allowed'])

    def test_assert_baseline_pass(self):
        code, out, err = run('assert', '--policy', str(EX/'baseline.json'), '--queries', str(EX/'queries.json'))
        self.assertEqual(0, code, err)
        result = json.loads(out)
        self.assertEqual(result['queries_checked'], result['passed'])

    def test_assert_candidate_fails(self):
        code, out, err = run('assert', '--policy', str(EX/'candidate-risky.json'), '--queries', str(EX/'queries.json'))
        self.assertEqual(1, code, err)
        self.assertLess(json.loads(out)['passed'], 4)

    def test_fail_on_none_unblocks_audit(self):
        code, out, err = run('audit', '--policy', str(EX/'candidate-risky.json'), '--fail-on', 'none')
        self.assertEqual(0, code, err)

    def test_bad_json_is_exit_2(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'bad'; p.write_text('not json')
            code, _, err = run('audit', '--policy', str(p))
            self.assertEqual(2, code)
            self.assertIn('rejeitada', err)

    def test_sarif_created(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'scan.sarif'
            code, out, err = run('audit', '--policy', str(EX/'candidate-risky.json'), '--sarif', str(path))
            self.assertEqual(1, code, err)
            self.assertEqual('2.1.0', json.loads(path.read_text())['version'])

    def test_output_no_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'report.json'; p.write_text('keep')
            code, out, err = run('audit', '--policy', str(EX/'baseline.json'), '--output', str(p))
            self.assertEqual(2, code)
            self.assertEqual('keep', p.read_text())

    def test_json_report_created(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'report.json'
            code, out, err = run('audit', '--policy', str(EX/'baseline.json'), '--output', str(p))
            self.assertEqual(0, code, err)
            self.assertEqual('audit', json.loads(p.read_text())['mode'])

    def test_text_report(self):
        code, out, err = run('audit', '--policy', str(EX/'baseline.json'), '--format', 'text')
        self.assertEqual(0, code, err)
        self.assertIn('SudoBoundary', out)

    def test_assert_missing_expected_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'q.json'
            obj = json.loads((EX/'queries.json').read_text())
            obj['queries'][0].pop('expected'); p.write_text(json.dumps(obj))
            code, _, err = run('assert', '--policy', str(EX/'baseline.json'), '--queries', str(p))
            self.assertEqual(2, code)

    def test_compare_json_and_sarif(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'risk.sarif'
            code, out, err = run('compare', '--baseline', str(EX/'baseline.json'), '--candidate', str(EX/'candidate-risky.json'), '--queries', str(EX/'queries.json'), '--sarif', str(p))
            self.assertEqual(1, code, err)
            sarif = json.loads(p.read_text())
            self.assertIn('SB100', [f['ruleId'] for f in sarif['runs'][0]['results']])


if __name__ == '__main__': unittest.main()
