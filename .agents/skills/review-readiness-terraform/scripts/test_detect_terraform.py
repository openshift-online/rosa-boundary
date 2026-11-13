"""Unit and isolated Git integration tests for the cheap review gate."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

FILE = Path(__file__).with_name("detect_terraform.py")
spec = importlib.util.spec_from_file_location("detect_terraform", FILE)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class ClassifierTests(unittest.TestCase):
    def test_no_terraform_stops_on_application_code_and_docs(self):
        result = gate.classify({"internal/foo.go": "", "deploy/account/README.md": "", ".tekton/rosa-boundary-pull-request.yaml": "+image: quay"})
        self.assertFalse(result["terraform"])
        self.assertEqual(result["matches"], [])

    def test_all_roots_and_inputs(self):
        paths = ["deploy/account/main.tf", "deploy/network/terraform.tfvars.example",
                 "deploy/regional/.terraform.lock.hcl", "hcp-terraform/aws-creds/rosa-boundary-prod/cloud.tf",
                 "hcp-terraform/rosa-boundary/main.tf", "hcp-terraform/rosa-trusted-actions/main.tf",
                 "components/trusted-actions/terraform/global/variables.tf",
                 "components/trusted-actions/terraform/regional/templates/userdata.sh.tpl",
                 "tests/localstack/terraform/override.tf", "elsewhere/new.tf.json"]
        self.assertEqual(len(gate.classify(dict.fromkeys(paths, ""))["matches"]), len(paths))

    def test_indirect_automation_changed_lines(self):
        self.assertFalse(gate.classify({"Makefile": "+go test ./..."})["terraform"])
        self.assertTrue(gate.classify({"Makefile": "-terraform validate\n+terraform test"})["terraform"])
        self.assertTrue(gate.classify({".github/workflows/terraform-plan.yml": ""})["terraform"])
        self.assertTrue(gate.classify({".tekton/job.yaml": None})["terraform"])
        self.assertTrue(gate.classify({"tests/localstack/integration/test_terraform_contract.py": ""})["terraform"])

    def test_renames_deletions_and_malformed_patch(self):
        parsed = gate.parse_patch('diff --git a/deploy/account/old.tf b/deploy/account/new.tf\n'
                                  'rename from deploy/account/old.tf\nrename to deploy/account/new.tf\n'
                                  '@@ -1 +1 @@\n-resource "a"\n+resource "b"\n')
        self.assertIn("deploy/account/old.tf", parsed)
        self.assertIn("deploy/account/new.tf", parsed)
        self.assertTrue(gate.classify(parsed)["terraform"])
        with self.assertRaises(ValueError):
            gate.parse_patch("arbitrary text")

    def test_pr_uses_only_changed_files_api(self):
        args = SimpleNamespace(pr=499, repo=gate.REPO, patch=None, paths_file=None,
                               working_tree=False, branch=None, commit=None, range=None)
        with patch.object(gate, "run", return_value=json.dumps({"filename": "internal/foo.go", "patch": "@@"}) + "\n") as mock:
            self.assertFalse(gate.classify(gate.inputs(args))["terraform"])
            self.assertIn("/pulls/499/files", mock.call_args.args[2])

    def test_unsafe_path_rejected(self):
        with self.assertRaises(ValueError):
            gate.classify({"../deploy/account/main.tf": ""})


class GitInputsTests(unittest.TestCase):
    def test_worktree_includes_staged_unstaged_and_untracked(self):
        with tempfile.TemporaryDirectory() as directory:
            old_cwd = os.getcwd()
            try:
                os.chdir(directory)
                subprocess.run(["git", "init", "-q"], check=True)
                subprocess.run(["git", "config", "user.email", "test@example.com"], check=True)
                subprocess.run(["git", "config", "user.name", "Tester"], check=True)
                Path("README.md").write_text("baseline\n")
                subprocess.run(["git", "add", "README.md"], check=True)
                subprocess.run(["git", "commit", "-qm", "baseline"], check=True)
                Path("README.md").write_text("changed\n")
                Path("deploy/account").mkdir(parents=True)
                Path("deploy/account/variables.tf").write_text('variable "x" {}\n')
                args = SimpleNamespace(pr=None, patch=None, paths_file=None, working_tree=True,
                                       branch=None, commit=None, range=None)
                self.assertTrue(gate.classify(gate.inputs(args))["terraform"])
                subprocess.run(["git", "add", "deploy/account/variables.tf"], check=True)
                self.assertTrue(gate.classify(gate.inputs(args))["terraform"])
                subprocess.run(["git", "commit", "-qm", "add variable"], check=True)
                args.working_tree = False
                args.commit = "HEAD"
                self.assertTrue(gate.classify(gate.inputs(args))["terraform"])
                args.commit = None
                args.range = "HEAD^..HEAD"
                self.assertTrue(gate.classify(gate.inputs(args))["terraform"])
                args.range = None
                args.branch = "HEAD"
                args.base = "HEAD^"
                self.assertTrue(gate.classify(gate.inputs(args))["terraform"])
            finally:
                os.chdir(old_cwd)


if __name__ == "__main__":
    unittest.main()
