# A new, dedicated bucket for Beacon telemetry and the write-only IAM user the forwarder uses.
#
#   terraform init
#   terraform apply -var region=us-west-2 -var bucket_name=<globally-unique-name>
#   aws iam create-access-key --user-name "$(terraform output -raw writer_user_name)"
#
# Outside this repository, point source at a release:
#   source = "github.com/asymptote-labs/agent-beacon//terraform/aws-s3?ref=<release tag>"

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

variable "region" {
  description = "AWS region for the bucket."
  type        = string
}

variable "bucket_name" {
  description = "Globally unique name for the new bucket."
  type        = string
}

variable "prefix" {
  description = "Root prefix for Beacon objects."
  type        = string
  default     = "beacon-prod"
}

provider "aws" {
  region = var.region
}

module "beacon_s3" {
  source = "../.."

  bucket_name = var.bucket_name
  prefix      = var.prefix
}

output "bucket_name" {
  value = module.beacon_s3.bucket_name
}

output "region" {
  value = module.beacon_s3.region
}

output "prefix" {
  value = module.beacon_s3.prefix
}

output "writer_user_name" {
  value = module.beacon_s3.writer_user_name
}
