# A Beacon bucket that Asymptote can read: the aws-s3 module creates the bucket and the writer,
# and this module adds Asymptote's read-only user and the new-object queues.
#
#   terraform init
#   terraform apply -var region=us-west-2 -var bucket_name=<globally-unique-name>
#   aws iam create-access-key --user-name "$(terraform output -raw writer_user_name)"
#   aws iam create-access-key --user-name "$(terraform output -raw asymptote_reader_user_name)"
#
# Outside this repository, point both sources at a release:
#   source = "github.com/asymptote-labs/agent-beacon//terraform/aws-s3?ref=<release tag>"
#   source = "github.com/asymptote-labs/agent-beacon//terraform/aws-s3-asymptote-reader?ref=<release tag>"

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
  description = "AWS region for the bucket and the queues."
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
  source = "../../../aws-s3"

  bucket_name = var.bucket_name
  prefix      = var.prefix
}

module "asymptote_reader" {
  source = "../.."

  bucket = module.beacon_s3.bucket
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

output "asymptote_reader_user_name" {
  value = module.asymptote_reader.user_name
}

output "asymptote_source_url" {
  value = module.asymptote_reader.source_url
}

output "asymptote_queue_urls" {
  value = module.asymptote_reader.queue_urls
}
