# S3 can only notify queues in the bucket's own region.

mock_provider "aws" {
  mock_resource "aws_sqs_queue" {
    defaults = {
      arn = "arn:aws:sqs:eu-west-1:111122223333:mock"
    }
  }
}

variables {
  bucket = {
    name   = "acme-beacon-telemetry"
    arn    = "arn:aws:s3:::acme-beacon-telemetry"
    region = "us-west-2"
    prefix = "beacon-prod"
  }
}

run "refuses_queues_in_another_region" {
  command = apply

  expect_failures = [aws_s3_bucket_notification.this]
}
