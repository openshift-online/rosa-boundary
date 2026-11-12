"""Evaluate shared HCP topology offline, without the private module."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "hcp-terraform/rosa-boundary/main.tf"


class ReplicationTopologyTest(unittest.TestCase):
    def evaluate(self, handoff=None):
        source = SOURCE.read_text()
        locals_hcl = source[source.index("locals {"):source.index('module "rosa_boundary"')]
        if handoff is not None:
            locals_hcl = locals_hcl.replace("content = null", f"content = {json.dumps(handoff)}")
        with tempfile.TemporaryDirectory(prefix="boundary-topology-") as directory:
            Path(directory, "main.tf").write_text(locals_hcl)
            result = subprocess.run(
                ["terraform", "console"], cwd=directory,
                input='jsonencode(local.replication_topology)\n',
                text=True, capture_output=True, check=True,
            )
        return json.loads(json.loads(result.stdout.strip()))

    def test_existing_ecr_topology_and_inactive_s3_are_preserved(self):
        for topology in self.evaluate().values():
            self.assertEqual(topology["primary_region"], "us-east-1")
            self.assertEqual(topology["destinations"], {"us-west-2": {"content": None}})

    def test_ready_handoff_keeps_the_same_destination_key(self):
        handoff = {
            "bucket_arn": "arn:aws:s3:::test-content-replica",
            "kms_key_arn": "arn:aws:kms:us-west-2:123456789012:key/test-fixture",
            "content_prefixes": {"ops-sop": "ops-sop/"},
        }
        for topology in self.evaluate(handoff).values():
            self.assertEqual(topology["destinations"], {"us-west-2": {"content": handoff}})

    def test_every_workspace_gets_the_same_generic_input(self):
        source = SOURCE.read_text()
        for stage, primary in (("stage", "regional"), ("prod", "regional-us-east-1")):
            for suffix in ("account", primary, "regional-us-west-2"):
                block = source.split(f"    rosa-boundary-{stage}-{suffix} = {{", 1)[1].split("\n    }\n", 1)[0]
                self.assertIn('key      = "replication"', block)
                self.assertIn(f"value    = jsonencode(local.replication_topology.{stage})", block)
        self.assertNotIn('key      = "lambda_ecr_replication_regions"', source)
        self.assertNotIn('key      = "content_replication_destinations"', source)

    def test_staging_publisher_handoff_is_source_only_and_complete(self):
        source = SOURCE.read_text()
        workspace = source.split("    rosa-boundary-stage-regional = {", 1)[1].split("\n    }\n", 1)[0]
        variable = workspace.split('key = "content_publisher_role_arns"', 1)[1].split("\n        },", 1)[0]
        self.assertIn('category = "terraform"', variable)
        self.assertIn("hcl      = true", variable)
        expression = variable.split("value = ", 1)[1].split("\n          category", 1)[0]
        with tempfile.TemporaryDirectory(prefix="boundary-publishers-") as directory:
            Path(directory, "main.tf").write_text(f"locals {{ publishers = {expression} }}\n")
            result = subprocess.run(
                ["terraform", "console"], cwd=directory,
                input="local.publishers\n",
                text=True, capture_output=True, check=True,
            )
        self.assertEqual(json.loads(json.loads(result.stdout.strip())), {
            key: f"arn:aws:iam::150100906299:role/rosa-boundary-stage-publisher-{key}"
            for key in ("ops-sop", "managed-notifications", "rosa-claude-plugins")
        })
        # No account-owned grant, replica publishing access or production rollout.
        self.assertEqual(source.count('"content_publisher_role_arns"'), 1)

    def test_existing_account_variable_resources_are_moved_not_deleted(self):
        moves = (SOURCE.parent / "moved.tf").read_text()
        for stage in ("stage", "prod"):
            prefix = f'module.rosa_boundary.tfe_variable.this["rosa-boundary-{stage}-account:terraform:'
            self.assertIn(f'from = {prefix}lambda_ecr_replication_regions"]', moves)
            self.assertIn(f'to   = {prefix}replication"]', moves)
        self.assertEqual(moves.count("moved {"), 2)

    def test_both_roots_accept_the_same_type(self):
        types = []
        for root in ("account", "regional"):
            source = (ROOT / "deploy" / root / "variables.tf").read_text()
            variable = source.split('variable "replication" {', 1)[1]
            types.append("".join(variable.split("type", 1)[1].split("default", 1)[0].split()))
        self.assertEqual(*types)


if __name__ == "__main__":
    unittest.main()
