import tempfile
import unittest
from pathlib import Path
from ci_trustgraph.parser import InputError, WorkflowLoader, load_workflows, _read_yaml, get_events, load_policy, MAX_BYTES
import yaml


class ParseTests(unittest.TestCase):
    def test_on_not_boolean(self):
        self.assertEqual(_read_yaml(b'on: [push]\njobs: {}\n', 'a')['on'], ['push'])

    def test_duplicate_key(self):
        with self.assertRaises(InputError):
            _read_yaml(b'jobs: {}\njobs: {}\n', 'a')

    def test_unhashable_key(self):
        with self.assertRaises(InputError):
            _read_yaml(b'jobs: {}\n? [one, two]\n: 3\n', 'a')

    def test_non_mapping(self):
        with self.assertRaises(InputError):
            _read_yaml(b'[one, two]', 'a')

    def test_jobs_not_mapping(self):
        with self.assertRaises(InputError):
            _read_yaml(b'jobs: []', 'a')

    def test_wrong_on(self):
        with self.assertRaises(InputError):
            _read_yaml(b'on: 1\njobs: {}', 'a')

    def test_non_utf8(self):
        with self.assertRaises(InputError):
            _read_yaml(b'\xff', 'a')

    def test_yaml_attack_tag(self):
        with self.assertRaises(InputError):
            _read_yaml(b'jobs: !!python/object/apply:os.system ["echo hacked"]', 'a')

    def test_yaml_aliases(self):
        with self.assertRaises(InputError):
            _read_yaml(b'a: &a [*a]\njobs: {}', 'a')

    def test_yaml_syntax(self):
        with self.assertRaises(InputError):
            _read_yaml(b'jobs: [bad', 'a')

    def test_events(self):
        self.assertEqual(get_events({'on': 'push'}), frozenset({'push'}))
        self.assertEqual(get_events({'on': ['push', 'pull_request']}), frozenset({'push', 'pull_request'}))
        self.assertEqual(get_events({'on': {'workflow_run': {}}}), frozenset({'workflow_run'}))

    def test_real_file(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); (root/'.github/workflows').mkdir(parents=True)
            (root/'.github/workflows/ci.yml').write_text('name: My CI\non: [push]\njobs:\n  build:\n    steps: []\n')
            flows = load_workflows(root)
            self.assertEqual(len(flows), 1)
            self.assertEqual(flows[0].name, 'My CI')

    def test_empty_dir(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(load_workflows(Path(td)), [])

    def test_bad_dir(self):
        with self.assertRaises(InputError):
            load_workflows(Path('/path/that/does/not/exist'))

    def test_symlink_input(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); (root/'.github/workflows').mkdir(parents=True)
            src = root/'actual.txt'; src.write_text('jobs: {}')
            (root/'.github/workflows/evil.yml').symlink_to(src)
            with self.assertRaises(InputError):
                load_workflows(root)

    def test_oversized_input(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td); (root/'.github/workflows').mkdir(parents=True)
            (root/'.github/workflows/large.yaml').write_bytes(b' ' * (MAX_BYTES + 1))
            with self.assertRaises(InputError):
                load_workflows(root)

    def test_policy(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)/'p.json';p.write_text('{"severity":"high"}')
            self.assertEqual(load_policy(p)['severity'], 'high')

    def test_bad_policy(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)/'p.json';p.write_text('[]')
            with self.assertRaises(InputError):
                load_policy(p)
