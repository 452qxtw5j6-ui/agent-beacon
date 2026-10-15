# The module builds URLs from the partition, so it also works in AWS China and GovCloud.

mock_provider "aws" {
  mock_data "aws_partition" {
    defaults = {
      partition  = "aws-cn"
      dns_suffix = "amazonaws.com.cn"
    }
  }

  mock_resource "aws_sqs_queue" {
    defaults = {
      arn = "arn:aws-cn:sqs:cn-north-1:111122223333:mock"
    }
  }
}

variables {
  bucket = {
    name   = "acme-beacon-telemetry"
    arn    = "arn:aws-cn:s3:::acme-beacon-telemetry"
    region = "cn-north-1"
    prefix = "beacon-prod"
  }
}

run "source_url_follows_the_partition" {
  command = apply

  assert {
    condition     = output.source_url == "https://acme-beacon-telemetry.s3.cn-north-1.amazonaws.com.cn/beacon-prod"
    error_message = "The source URL uses the partition's DNS suffix."
  }
}
