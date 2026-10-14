"""Offline preflight decisions with stubbed AWS metadata."""

import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
import preflight  # noqa: E402


PROFILE = {"account_id": "123456789012", "region": "us-east-1", "stage": "dev", "project": "rosa-boundary"}
DIGEST = "sha256:" + "a" * 64


def aws_result(*args):
    if args[0] == "sts":
        return {"Account": "123456789012"}
    if args[1] == "describe-clusters":
        return {"clusters": [{"status": "ACTIVE"}]}
    if args[1] == "describe-task-definition":
        return {"taskDefinition": {"status": "ACTIVE", "taskDefinitionArn":
                "arn:aws:ecs:us-east-1:123456789012:task-definition/rosa-boundary-dev:9",
                "containerDefinitions": [{"name": "rosa-boundary", "image": IMAGE}]}}
    if args[0] == "lambda":
        return {"State": "Active", "LastUpdateStatus": "Successful", "PackageType": "Zip",
                "CodeSha256": "a" * 44}
    raise AssertionError(args)


IMAGE = "123456789012.dkr.ecr.us-east-1.amazonaws.com/rosa-boundary:latest"


class PreflightTest(unittest.TestCase):
    @patch.object(preflight, "aws", side_effect=aws_result)
    def test_mutable_tag_not_verified_even_with_healthy_cluster(self, _):
        result = preflight.check_deployment(PROFILE, image_digest=DIGEST, architecture="X86_64")
        self.assertFalse(result["matched"])
        self.assertIn("not pinned", result["checks"]["task_image_digest"])

    @patch.object(preflight, "aws", side_effect=aws_result)
    def test_digest_pinned_can_match(self, _):
        global IMAGE
        previous = IMAGE
        try:
            IMAGE = previous.split(":latest")[0] + "@" + DIGEST
            result = preflight.check_deployment(PROFILE, image_digest=DIGEST, architecture="X86_64")
            self.assertTrue(result["matched"])
        finally:
            IMAGE = previous

    @patch.object(preflight, "aws", return_value={"Account": "000000000000"})
    def test_wrong_account_short_circuits(self, aws):
        result = preflight.check_deployment(PROFILE, image_digest=DIGEST)
        self.assertFalse(result["matched"])
        self.assertEqual(aws.call_count, 1)

    @patch.object(preflight, "aws", side_effect=aws_result)
    def test_lambda_zip_hash_check(self, _):
        good = preflight.check_deployment(PROFILE, lambda_sha="a" * 44)
        self.assertTrue(good["matched"])
        bad = preflight.check_deployment(PROFILE, lambda_sha="b" * 44)
        self.assertFalse(bad["matched"])


if __name__ == "__main__":
    unittest.main()
