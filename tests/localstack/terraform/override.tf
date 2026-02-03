# Terraform provider overrides for LocalStack testing

provider "aws" {
  endpoints {
    s3                     = "http://localhost:4566"
    iam                    = "http://localhost:4566"
    lambda                 = "http://localhost:4566"
    logs                   = "http://localhost:4566"
    kms                    = "http://localhost:4566"
    sts                    = "http://localhost:4566"
    ec2                    = "http://localhost:4566"
    ecs                    = "http://localhost:4566"
    elasticfilesystem      = "http://localhost:4566"
    ssm                    = "http://localhost:4566"
  }

  access_key                  = "test"
  secret_key                  = "test"
  region                      = "us-east-2"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true

  # LocalStack doesn't validate these
  s3_use_path_style = true
}
