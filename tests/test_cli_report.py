import io
import json
import tempfile
import unittest
from pathlib import Path
from contextlib import redirect_stdout, redirect_stderr
from ci_trustgraph.cli import main
from ci_trustgraph.engine import scan
from ci_trustgraph.model import Workflow, Finding, Edge
from ci_trustgraph.report import result, render_text, render_sarif, diff


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.finding = Finding('TG006', 'high', '.github/workflows/a.yml', 'job', 2, 'unsafe', 'untrusted', 'fix', ('source', 'sink'))

    def test_json_report(self):
        o = result([self.finding], [Edge('a', 'b', 'flow')])
        self.assertEqual(o['summary'], {'high': 1})
        self.assertEqual(len(o['findings'][0]['fingerprint']), 24)

    def test_text_report(self):
        s = render_text([self.finding], [])
        self.assertIn('TG006', s)
        self.assertIn('source -> sink', s)

    def test_sarif_schema(self):
        obj = render_sarif([self.finding])
        self.assertEqual(obj['version'], '2.1.0')
        self.assertEqual(obj['runs'][0]['results'][0]['ruleId'], 'TG006')
        self.assertEqual(obj['runs'][0]['results'][0]['level'], 'error')

    def test_sarif_empty(self):
        self.assertEqual(render_sarif([])['runs'][0]['results'], [])

    def test_diff(self):
        self.assertEqual(diff([], [self.finding])['unchanged'], 0)
        self.assertEqual(len(diff([], [self.finding])['introduced']), 1)
        self.assertEqual(diff([self.finding.to_dict()], [self.finding])['unchanged'], 1)
        self.assertEqual(len(diff([self.finding.to_dict()], [])['resolved']), 1)

    def test_fingerprint_change_evidence(self):
        b = Finding('TG006', 'high', '.github/workflows/a.yml', 'job', 2, 'unsafe', 'other', 'fix')
        self.assertNotEqual(b.fingerprint, self.finding.fingerprint)

    def test_cli_empty(self):
        with tempfile.TemporaryDirectory() as td, redirect_stdout(io.StringIO()) as out:
            self.assertEqual(main([td]), 0)
            self.assertIn('0 finding', out.getvalue())

    def test_cli_report_json(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td);(base/'.github/workflows').mkdir(parents=True)
            (base/'.github/workflows/x.yml').write_text('on: [push]\njobs:\n  test:\n    steps: []\n')
            out = base/'report.json'
            self.assertEqual(main([td, '--format', 'json', '--output', str(out), '--fail-on', 'off']), 0)
            self.assertEqual(json.loads(out.read_text())['findings'][0]['rule_id'], 'TG001')

    def test_cli_fail_high(self):
        with tempfile.TemporaryDirectory() as td, redirect_stdout(io.StringIO()):
            base = Path(td);(base/'.github/workflows').mkdir(parents=True)
            (base/'.github/workflows/x.yml').write_text('on: [push]\njobs:\n  test:\n    steps:\n      - run: "echo ${{ github.head_ref }}"\n')
            self.assertEqual(main([td]), 2)

    def test_cli_severity_threshold(self):
        with tempfile.TemporaryDirectory() as td, redirect_stdout(io.StringIO()):
            base = Path(td);(base/'.github/workflows').mkdir(parents=True)
            (base/'.github/workflows/x.yml').write_text('on: [push]\njobs:\n  test:\n    steps: []\n')
            self.assertEqual(main([td, '--fail-on', 'high']), 0)
            self.assertEqual(main([td, '--fail-on', 'medium']), 2)

    def test_cli_error(self):
        with redirect_stderr(io.StringIO()) as out:
            self.assertEqual(main(['/path/that/is/not/there']), 3)
            self.assertIn('invalid input', out.getvalue())

    def test_cli_sarif_graph_baseline(self):
        with tempfile.TemporaryDirectory() as td, redirect_stdout(io.StringIO()):
            base = Path(td);(base/'.github/workflows').mkdir(parents=True)
            (base/'.github/workflows/x.yml').write_text('on: push\njobs:\n  test:\n    steps: []\n')
            json_path, sarif, graph = (base/'prev.json', base/'report.sarif', base/'graph.json')
            self.assertEqual(main([td, '--format', 'json', '--output', str(json_path), '--fail-on', 'off']), 0)
            with redirect_stderr(io.StringIO()) as err:
                self.assertEqual(main([td, '--baseline', str(json_path), '--format', 'sarif', '--output', str(sarif), '--graph', str(graph), '--fail-on', 'low']), 0)
            self.assertIn('unchanged', err.getvalue())
            self.assertEqual(json.loads(sarif.read_text())['version'], '2.1.0')
            self.assertIn('edges', json.loads(graph.read_text()))

    def test_cli_bad_baseline(self):
        with tempfile.TemporaryDirectory() as td, redirect_stderr(io.StringIO()), redirect_stdout(io.StringIO()):
            base=Path(td); (base/'prev.json').write_text('{}')
            self.assertEqual(main([td, '--baseline', str(base/'prev.json')]), 3)
