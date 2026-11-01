"""Deterministic, table-driven and randomized regression checks."""
import random
import tempfile
import unittest
from pathlib import Path

from ci_trustgraph.engine import scan
from ci_trustgraph.model import Workflow
from ci_trustgraph.parser import InputError, load_workflows, _read_yaml


class PropertyTests(unittest.TestCase):
    def test_1000_artifact_boundary_cases(self):
        rng = random.Random(10092026)
        for _ in range(1000):
            event = rng.choice(['push', 'pull_request', 'workflow_dispatch', 'issue_comment'])
            is_upload = rng.choice([False, True])
            has_link = rng.choice([False, True])
            downloads = rng.choice([False, True])
            executes = rng.choice([False, True])
            write = rng.choice([False, True])
            producer = Workflow('producer.yml', 'Build', frozenset([event]), {
                'name': 'Build', 'on': event, 'permissions': {'contents': 'read'},
                'jobs': {'build': {'steps': [{'uses': 'actions/upload-artifact@v4'}] if is_upload else []}}})
            trigger_name = 'Build' if has_link else 'Other'
            steps = ([{'uses': 'actions/download-artifact@v4'}] if downloads else []) + ([{'run': 'python ./process.py'}] if executes else [])
            consumer = Workflow('consumer.yml', 'Publish', frozenset(['workflow_run']), {
                'name': 'Publish', 'on': {'workflow_run': {'workflows': [trigger_name]}},
                'permissions': {'contents': 'write' if write else 'read'},
                'jobs': {'release': {'steps': steps}}})
            findings, edges = scan([producer, consumer])
            expected = event != 'push' and is_upload and has_link and downloads and executes
            matches = [f for f in findings if f.rule_id == 'TG009']
            self.assertEqual(bool(matches), expected)
            self.assertEqual(any(e.relation == 'artifact_to_execution' for e in edges), expected)
            if expected:
                self.assertEqual(matches[0].severity, 'critical' if write else 'high')

    def test_500_permission_decisions(self):
        rng = random.Random(426262)
        for _ in range(500):
            event = rng.choice(['push', 'pull_request', 'workflow_run', 'pull_request_target'])
            job_perm = rng.choice(['read', 'write', None])
            wf_perm = rng.choice(['read', 'write', None])
            job = {'steps': []}
            if job_perm is not None:
                job['permissions'] = {'contents': job_perm}
            raw = {'on': event, 'jobs': {'build': job}}
            if wf_perm is not None:
                raw['permissions'] = {'contents': wf_perm}
            flow = Workflow('w.yml', 'wf', frozenset({event}), raw)
            findings = scan([flow])[0]
            expected_write = (job_perm if job_perm is not None else wf_perm) == 'write'
            expected_implicit = job_perm is None and wf_perm is None
            self.assertEqual(any(f.rule_id == 'TG002' for f in findings), expected_write)
            self.assertEqual(any(f.rule_id == 'TG001' for f in findings), expected_implicit)

    def test_max_number_of_workflows(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td)/'.github/workflows';d.mkdir(parents=True)
            for i in range(201):
                (d/f'w{i:03}.yml').write_text('jobs: {}')
            with self.assertRaises(InputError):
                load_workflows(Path(td))

    def test_yaml_nested_duplicate_keys(self):
        with self.assertRaises(InputError):
            _read_yaml(b'jobs:\n  build:\n    runs-on: linux\n    runs-on: windows\n', 'test.yml')

    def test_repeated_aliases_rejected(self):
        with self.assertRaises(InputError):
            _read_yaml(b'a: &here [1, 2]\nb: *here\njobs: {}\n', 'test.yml')

    def test_json_style_inline_yaml(self):
        obj = _read_yaml(b'{"on": ["push"], "jobs": {"x": {"steps": []}}}', 'inline.yml')
        self.assertEqual(list(obj['jobs']), ['x'])

    def test_explicit_false_checkout(self):
        obj = _read_yaml(b'jobs: {a: {steps: [{uses: actions/checkout@v4, with: {persist-credentials: false}}]}}', 'inline.yml')
        self.assertIn(str(obj['jobs']['a']['steps'][0]['with']['persist-credentials']).lower(), ('false',))
