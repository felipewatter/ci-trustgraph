"""Provenance and untrusted-expression trust-boundary regression cases."""
import unittest
from ci_trustgraph.engine import scan
from ci_trustgraph.model import Workflow

SHA = "a" * 40


def make(name, event, steps, permission="read", path=None):
    raw = {
        "name": name,
        "on": event,
        "permissions": {"contents": permission},
        "jobs": {"task": {"steps": steps}},
    }
    events = frozenset(event.keys() if isinstance(event, dict) else [event])
    return Workflow(path or (name.lower() + ".yml"), name, events, raw)


class TrustBoundaryTests(unittest.TestCase):
    def test_untrusted_pr_metadata_interpolation_is_detected(self):
        for expression in [
            "github.event.pull_request.title",
            "github.event.pull_request.body",
            "github.event.pull_request.head.ref",
        ]:
            with self.subTest(expression=expression):
                job = make("PR", "pull_request",
                           [{"run": "echo " + "$" + "{{ " + expression + " }}"}])
                rule_ids = {f.rule_id for f in scan([job])[0]}
                self.assertIn("TG006", rule_ids)

    def test_untrusted_metadata_as_data_in_env_is_not_direct_script_injection(self):
        job = make("PR", "pull_request",
                   [{"env": {"PR_TITLE": "$" + "{{ github.event.pull_request.title }}"},
                     "run": 'printf "%s" "$PR_TITLE"'}])
        self.assertNotIn("TG006", {f.rule_id for f in scan([job])[0]})

    def test_privileged_checkout_untrusted_ref_is_critical_with_write_token(self):
        job = make("Release", "pull_request_target",
                   [{"uses": "actions/checkout@" + SHA,
                     "with": {"ref": "$" + "{{ github.event.pull_request.head.sha }}",
                              "persist-credentials": False}}],
                   permission="write")
        report = scan([job])[0]
        self.assertEqual(next(f.severity for f in report if f.rule_id == "TG007"), "critical")

    def test_pr_artifact_to_writable_workflow_run_execution_has_trace(self):
        producer = make("Untrusted Build", "pull_request",
                        [{"uses": "actions/upload-artifact@" + SHA}], path="untrusted.yml")
        consumer = make(
            "Privileged Publish",
            {"workflow_run": {"workflows": ["Untrusted Build"]}},
            [{"uses": "actions/download-artifact@" + SHA}, {"run": "python build.py"}],
            permission="write", path="privileged.yml")
        findings, edges = scan([producer, consumer])
        hazard = next(f for f in findings if f.rule_id == "TG009")
        self.assertEqual(hazard.severity, "critical")
        self.assertTrue(hazard.trace)
        self.assertIn("artifact_to_execution", {edge.relation for edge in edges})


if __name__ == "__main__":
    unittest.main()
