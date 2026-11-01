import unittest
from ci_trustgraph.engine import scan, _is_sha_pinned, _permission, _artifact_consumer
from ci_trustgraph.model import Workflow

SHA = 'a' * 40


def workflow(event, jobs, name='ci', path='.github/workflows/ci.yml', permissions=None):
    obj = {'name': name, 'on': event, 'jobs': jobs}
    if permissions is not None: obj['permissions'] = permissions
    return Workflow(path, name, frozenset(event if isinstance(event, list) else event.keys() if isinstance(event, dict) else [event]), obj)


def ids(flows):
    return [f.rule_id for f in scan(flows)[0]]


class EngineTests(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(scan([]), ([], []))

    def test_explicit_minimal_permissions(self):
        self.assertEqual(ids([workflow('push', {'build': {'permissions': {'contents': 'read'}, 'steps': []}})]), [])

    def test_implicit_permissions(self):
        self.assertIn('TG001', ids([workflow('push', {'build': {'steps': []}})]))

    def test_workflow_read_permission(self):
        self.assertNotIn('TG001', ids([workflow('push', {'build': {'steps': []}}, permissions={'contents': 'read'})]))

    def test_job_override_write(self):
        self.assertIn('TG002', ids([workflow('push', {'build': {'permissions': {'contents': 'write'}, 'steps': []}}, permissions={'contents': 'read'})]))

    def test_job_override_read(self):
        self.assertNotIn('TG002', ids([workflow('push', {'build': {'permissions': {'contents': 'read'}, 'steps': []}}, permissions={'contents': 'write'})]))

    def test_write_all(self):
        self.assertIn('TG002', ids([workflow('push', {'build': {'permissions': 'write-all', 'steps': []}})]))

    def test_privileged_target_write(self):
        self.assertIn('TG003', ids([workflow('pull_request_target', {'build': {'steps': []}}, permissions={'contents': 'write'})]))

    def test_privileged_workflow_run_secret(self):
        self.assertIn('TG003', ids([workflow('workflow_run', {'build': {'steps': [{'run': 'echo ${{ secrets.KEY }}'}]}})]))

    def test_no_privilege_for_plain_pr(self):
        self.assertNotIn('TG003', ids([workflow('pull_request', {'build': {'steps': []}}, permissions={'contents': 'write'})]))

    def test_self_hosted_pr(self):
        self.assertIn('TG004', ids([workflow('pull_request', {'build': {'runs-on': ['self-hosted', 'linux'], 'steps': []}})]))

    def test_hosted_pr(self):
        self.assertNotIn('TG004', ids([workflow('pull_request', {'build': {'runs-on': 'ubuntu-latest', 'steps': []}})]))

    def test_tag_action(self):
        self.assertIn('TG005', ids([workflow('push', {'build': {'steps': [{'uses': 'actions/setup-python@v5'}]}}, permissions={'contents': 'read'})]))

    def test_sha_action(self):
        self.assertNotIn('TG005', ids([workflow('push', {'build': {'steps': [{'uses': f'actions/setup-python@{SHA}'}]}}, permissions={'contents': 'read'})]))

    def test_local_action(self):
        self.assertNotIn('TG005', ids([workflow('push', {'build': {'steps': [{'uses': './.github/actions/lint'}]}}, permissions={'contents': 'read'})]))

    def test_docker_digest(self):
        self.assertTrue(_is_sha_pinned('docker://alpine@sha256:' + 'a' * 64))

    def test_docker_tag(self):
        self.assertFalse(_is_sha_pinned('docker://alpine:latest'))

    def test_action_missing_ref(self):
        self.assertFalse(_is_sha_pinned('vendor/action'))

    def test_injection_title(self):
        self.assertIn('TG006', ids([workflow('pull_request', {'build': {'steps': [{'run': 'echo ${{ github.event.pull_request.title }}'}]}}, permissions={'contents': 'read'})]))

    def test_injection_comment(self):
        self.assertIn('TG006', ids([workflow('issue_comment', {'build': {'steps': [{'run': 'echo ${{ github.event.comment.body }}'}]}}, permissions={'contents': 'read'})]))

    def test_injection_head_ref(self):
        self.assertIn('TG006', ids([workflow('pull_request', {'build': {'steps': [{'run': 'echo ${{ github.head_ref }}'}]}}, permissions={'contents': 'read'})]))

    def test_injection_not_env(self):
        self.assertNotIn('TG006', ids([workflow('pull_request', {'build': {'steps': [{'env': {'TITLE': '${{ github.event.pull_request.title }}'}, 'run': 'echo "$TITLE"'}]}}, permissions={'contents': 'read'})]))

    def test_no_injection_trusted_expr(self):
        self.assertNotIn('TG006', ids([workflow('push', {'build': {'steps': [{'run': 'echo ${{ github.sha }}'}]}}, permissions={'contents': 'read'})]))

    def test_checkout_pr_head_critical(self):
        steps = [{'uses': f'actions/checkout@{SHA}', 'with': {'ref': '${{ github.event.pull_request.head.sha }}'}}]
        f = scan([workflow('pull_request_target', {'build': {'steps': steps}}, permissions={'contents': 'write'})])[0]
        self.assertEqual(next(x for x in f if x.rule_id == 'TG007').severity, 'critical')

    def test_checkout_pr_head_high_without_write(self):
        steps = [{'uses': f'actions/checkout@{SHA}', 'with': {'ref': '${{ github.head_ref }}'}}]
        f = scan([workflow('pull_request_target', {'build': {'steps': steps}}, permissions={'contents': 'read'})])[0]
        self.assertEqual(next(x for x in f if x.rule_id == 'TG007').severity, 'high')

    def test_checkout_pr_head_not_regular_pr(self):
        steps = [{'uses': f'actions/checkout@{SHA}', 'with': {'ref': '${{ github.head_ref }}'}}]
        self.assertNotIn('TG007', ids([workflow('pull_request', {'build': {'steps': steps}}, permissions={'contents': 'read'})]))

    def test_checkout_persist_creds_default(self):
        self.assertIn('TG008', ids([workflow('push', {'build': {'steps': [{'uses': f'actions/checkout@{SHA}'}]}}, permissions={'contents': 'write'})]))

    def test_checkout_persist_creds_disabled(self):
        self.assertNotIn('TG008', ids([workflow('push', {'build': {'steps': [{'uses': f'actions/checkout@{SHA}', 'with': {'persist-credentials': False}}]}}, permissions={'contents': 'write'})]))

    def test_job_level_creds(self):
        steps = [{'uses': f'actions/checkout@{SHA}'}]
        self.assertIn('TG008', ids([workflow('push', {'build': {'permissions': {'contents': 'write'}, 'steps': steps}}, permissions={'contents': 'read'})]))

    def test_cross_workflow_artifact(self):
        prod = workflow('pull_request', {'test': {'steps': [{'uses': f'actions/upload-artifact@{SHA}'}]}}, 'Untrusted', '.github/workflows/untrusted.yml', {'contents': 'read'})
        cons = workflow({'workflow_run': {'workflows': ['Untrusted'], 'types': ['completed']}}, {'publish': {'steps': [{'uses': f'actions/download-artifact@{SHA}'}, {'run': 'python build.py'}]}}, 'Publish', '.github/workflows/publish.yml', {'contents': 'write'})
        findings, edges = scan([prod, cons])
        f = next(x for x in findings if x.rule_id == 'TG009')
        self.assertEqual(f.severity, 'critical')
        self.assertEqual(len(f.trace), 5)
        self.assertIn('artifact_to_execution', [e.relation for e in edges])

    def test_cross_workflow_readonly(self):
        prod = workflow('pull_request', {'test': {'steps': [{'uses': f'actions/upload-artifact@{SHA}'}]}}, 'Untrusted', 'untrusted.yml', {'contents': 'read'})
        cons = workflow({'workflow_run': {'workflows': ['Untrusted']}}, {'consumer': {'steps': [{'uses': f'actions/download-artifact@{SHA}'}, {'run': 'bash verify.sh'}]}}, 'Reader', 'reader.yml', {'contents': 'read'})
        findings = scan([prod, cons])[0]
        self.assertEqual(next(x for x in findings if x.rule_id == 'TG009').severity, 'high')

    def test_no_path_without_download(self):
        prod = workflow('pull_request', {'test': {'steps': [{'uses': f'actions/upload-artifact@{SHA}'}]}}, 'Untrusted', 'untrusted.yml')
        cons = workflow({'workflow_run': {'workflows': ['Untrusted']}}, {'consumer': {'steps': [{'run': 'python build.py'}]}}, 'Reader', 'reader.yml')
        self.assertNotIn('TG009', ids([prod, cons]))

    def test_no_path_without_execution(self):
        prod = workflow('pull_request', {'test': {'steps': [{'uses': f'actions/upload-artifact@{SHA}'}]}}, 'Untrusted', 'untrusted.yml')
        cons = workflow({'workflow_run': {'workflows': ['Untrusted']}}, {'consumer': {'steps': [{'uses': f'actions/download-artifact@{SHA}'}, {'run': 'echo ok'}]}}, 'Reader', 'reader.yml')
        self.assertNotIn('TG009', ids([prod, cons]))

    def test_no_path_for_trusted_producer(self):
        prod = workflow('push', {'test': {'steps': [{'uses': f'actions/upload-artifact@{SHA}'}]}}, 'Trusted', 'trusted.yml')
        cons = workflow({'workflow_run': {'workflows': ['Trusted']}}, {'consumer': {'steps': [{'uses': f'actions/download-artifact@{SHA}'}, {'run': 'python build.py'}]}}, 'Reader', 'reader.yml')
        self.assertNotIn('TG009', ids([prod, cons]))

    def test_no_path_for_non_matching_name(self):
        prod = workflow('pull_request', {'test': {'steps': [{'uses': f'actions/upload-artifact@{SHA}'}]}}, 'Untrusted', 'untrusted.yml')
        cons = workflow({'workflow_run': {'workflows': ['Other']}}, {'consumer': {'steps': [{'uses': f'actions/download-artifact@{SHA}'}, {'run': 'python build.py'}]}}, 'Reader', 'reader.yml')
        self.assertNotIn('TG009', ids([prod, cons]))

    def test_artifact_execution_order(self):
        self.assertIsNone(_artifact_consumer({'steps': [{'run': 'python build.py'}, {'uses': 'actions/download-artifact@v4'}]}))

    def test_fingerprint_deterministic(self):
        a = scan([workflow('push', {'build': {'steps': []}})])[0]
        b = scan([workflow('push', {'build': {'steps': []}})])[0]
        self.assertEqual([f.fingerprint for f in a], [f.fingerprint for f in b])

    def test_sorted_findings(self):
        find, _ = scan([workflow('pull_request_target', {'build': {'steps': [{'run': 'echo ${{ github.head_ref }}'}]}}, permissions={'contents': 'write'})])
        self.assertEqual(find[0].severity, 'high')

    def test_edge_topology(self):
        _, edges = scan([workflow('push', {'one': {'steps': []}, 'two': {'steps': []}})])
        self.assertEqual(len([e for e in edges if e.relation == 'contains_job']), 2)

    def test_permissions_variants(self):
        for value, expected in [('read-all', False), ('write-all', True), ({'issues': 'write'}, True), ({'contents': 'read'}, False), ('none', False)]:
            with self.subTest(value=value):
                self.assertEqual(_permission(value), expected)

    def test_many_steps(self):
        steps = [{'run': 'echo hi'}] * 100 + [{'run': 'echo ${{ github.head_ref }}'}]
        findings, _ = scan([workflow('pull_request', {'build': {'steps': steps}}, permissions={'contents': 'read'})])
        self.assertEqual(next(f for f in findings if f.rule_id == 'TG006').step, 101)
