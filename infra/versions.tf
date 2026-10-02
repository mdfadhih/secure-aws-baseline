terraform {
  required_version = ">= 1.11.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }

  # Partial configuration: the bucket is passed at init time so no account IDs live in Git.
  #   terraform init -backend-config="bucket=<TF_STATE_BUCKET>" -backend-config="region=<REGION>"
  # use_lockfile = native S3 locking (Terraform 1.10+), so no DynamoDB table is needed.
  backend "s3" {
    key          = "secure-aws-baseline/infra.tfstate"
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project   = "secure-aws-baseline"
      ManagedBy = "terraform"
      Component = "infra"
    }
  }
}

data "aws_caller_identity" "current" {}
