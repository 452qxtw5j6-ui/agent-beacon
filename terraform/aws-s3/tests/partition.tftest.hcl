# The module builds ARNs and URLs from the partition, so it also works in AWS China and GovCloud.

mock_provider "aws" {
  mock_data "aws_partition" {
    defaults = {
      partition  = "aws-cn"
      dns_suffix = "amazonaws.com.cn"
    }
  }

  mock_resource "aws_s3_bucket" {
    defaults = {
      bucket = "acme-beacon-telemetry"
      region = "cn-north-1"
    }
  }
}

variables {
  bucket_name = "acme-beacon-telemetry"
  prefix      = "beacon-prod"
}

run "urls_and_arns_follow_the_partition" {
  command = apply

  assert {
    condition     = output.bucket_arn == "arn:aws-cn:s3:::acme-beacon-telemetry"
    error_message = "The bucket ARN uses the partition."
  }

  assert {
    condition     = jsondecode(aws_iam_user_policy.writer.policy).Statement[0].Resource == "arn:aws-cn:s3:::acme-beacon-telemetry/beacon-prod/*"
    error_message = "The writer policy uses the partition."
  }
}
