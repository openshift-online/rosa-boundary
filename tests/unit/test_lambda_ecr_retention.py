"""A push must never age a deployed Lambda digest or its metadata out of ECR."""
import re
from pathlib import Path

import pytest

DEPLOY = Path(__file__).resolve().parents[2] / 'deploy'


@pytest.mark.parametrize('root,side', [('account', 'source'), ('regional', 'destination')])
def test_lambda_repository_has_no_expiration_policy(root, side):
    for path in (DEPLOY / root).glob('*.tf'):
        for block in re.findall(r'(?m)^resource "aws_ecr_lifecycle_policy" .*?^}',
                                path.read_text(), re.DOTALL):
            assert f'aws_ecr_repository.create_investigation_lambda_{side}' not in block
            assert '/create-investigation-lambda"' not in block
