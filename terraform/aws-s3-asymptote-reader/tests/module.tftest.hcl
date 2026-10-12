# Hermetic: the AWS provider is mocked, so these runs need no account or credentials.

mock_provider "aws" {
  mock_data "aws_partition" {
    defaults = {
      partition  = "aws"
      dns_suffix = "amazonaws.com"
    }
  }

  mock_data "aws_caller_identity" {
    defaults = {
      account_id = "111122223333"
    }
  }

  mock_resource "aws_sqs_queue" {
    defaults = {
      arn = "arn:aws:sqs:us-west-2:111122223333:mock"
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

run "reader_reads_only_the_prefix_and_its_queues" {
  command = apply

  assert {
    condition = jsondecode(aws_iam_user_policy.reader.policy).Statement == [
      {
        Sid      = "ListBeaconBucket"
        Effect   = "Allow"
        Action   = ["s3:ListBucket", "s3:GetBucketLocation"]
        Resource = "arn:aws:s3:::acme-beacon-telemetry"
      },
      {
        Sid      = "ReadBeaconObjects"
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = "arn:aws:s3:::acme-beacon-telemetry/beacon-prod/*"
      },
      {
        Sid      = "ConsumeBeaconNotifications"
        Effect   = "Allow"
        Action   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
        Resource = [aws_sqs_queue.reader["inventory"].arn, aws_sqs_queue.reader["runtime"].arn]
      },
      {
        Sid      = "FindBeaconQueues"
        Effect   = "Allow"
        Action   = "sqs:ListQueues"
        Resource = "*"
      },
    ]
    error_message = "The reader may list the bucket, read only the Beacon prefix, and consume its two queues."
  }

  assert {
    condition     = aws_iam_user.reader.name == "asymptote-s3-reader" && aws_iam_user_policy.reader.name == "BeaconTelemetryReadOnly"
    error_message = "The reader has the documented names."
  }

  assert {
    condition     = length(aws_iam_access_key.reader) == 0
    error_message = "The access key, whose secret would land in state, must be opt-in."
  }
}

run "each_stream_gets_a_queue" {
  command = apply

  assert {
    condition = (
      aws_sqs_queue.reader["runtime"].name == "asymptote-s3-reader-runtime"
      && aws_sqs_queue.reader["inventory"].name == "asymptote-s3-reader-inventory"
      && aws_sqs_queue.dead_letter["runtime"].name == "asymptote-s3-reader-runtime-dlq"
      && aws_sqs_queue.dead_letter["inventory"].name == "asymptote-s3-reader-inventory-dlq"
    )
    error_message = "Each stream gets a queue and a dead-letter queue named after the reader."
  }

  assert {
    condition = alltrue([
      for stream in ["runtime", "inventory"] :
      aws_sqs_queue.reader[stream].sqs_managed_sse_enabled
      && aws_sqs_queue.reader[stream].message_retention_seconds == 1209600
      && aws_sqs_queue.reader[stream].visibility_timeout_seconds == 300
      && jsondecode(aws_sqs_queue.reader[stream].redrive_policy) == {
        deadLetterTargetArn = aws_sqs_queue.dead_letter[stream].arn
        maxReceiveCount     = 10
      }
    ])
    error_message = "Queues are encrypted, keep messages 14 days, and move a message to the dead-letter queue after ten failed deliveries."
  }

  assert {
    condition = alltrue([
      for stream in ["runtime", "inventory"] :
      jsondecode(aws_sqs_queue_policy.reader[stream].policy).Statement == [
        {
          Sid       = "AllowBucketNotifications"
          Effect    = "Allow"
          Principal = { Service = "s3.amazonaws.com" }
          Action    = "sqs:SendMessage"
          Resource  = aws_sqs_queue.reader[stream].arn
          Condition = {
            ArnEquals    = { "aws:SourceArn" = "arn:aws:s3:::acme-beacon-telemetry" }
            StringEquals = { "aws:SourceAccount" = "111122223333" }
          }
        },
      ]
    ])
    error_message = "Only this bucket, in this account, may send to the queues."
  }

  assert {
    condition = aws_s3_bucket_notification.this.bucket == "acme-beacon-telemetry" && {
      for queue in aws_s3_bucket_notification.this.queue : queue.filter_prefix => {
        arn    = queue.queue_arn
        events = queue.events
      }
      } == {
      "beacon-prod/runtime/"   = { arn = aws_sqs_queue.reader["runtime"].arn, events = toset(["s3:ObjectCreated:*"]) }
      "beacon-prod/inventory/" = { arn = aws_sqs_queue.reader["inventory"].arn, events = toset(["s3:ObjectCreated:*"]) }
    }
    error_message = "Every new object below each stream's prefix is announced on that stream's queue."
  }

  assert {
    condition = output.queue_urls == {
      runtime   = aws_sqs_queue.reader["runtime"].url
      inventory = aws_sqs_queue.reader["inventory"].url
    }
    error_message = "queue_urls gives the provisioning script's --queue-url values."
  }

  assert {
    condition     = output.source_url == "https://acme-beacon-telemetry.s3.us-west-2.amazonaws.com/beacon-prod"
    error_message = "The source URL is the bucket's regional endpoint plus the prefix."
  }
}

run "dotted_bucket_names_get_a_path_style_url" {
  command = apply

  variables {
    bucket = {
      name   = "acme.beacon.telemetry"
      arn    = "arn:aws:s3:::acme.beacon.telemetry"
      region = "us-west-2"
      prefix = "beacon-prod"
    }
  }

  assert {
    condition     = output.source_url == "https://s3.us-west-2.amazonaws.com/acme.beacon.telemetry/beacon-prod"
    error_message = "A dotted bucket name fails TLS on a virtual-hosted URL, so the URL must be path style."
  }
}

run "kms_bucket_needs_decrypt" {
  command = apply

  variables {
    bucket = {
      name        = "acme-beacon-telemetry"
      arn         = "arn:aws:s3:::acme-beacon-telemetry"
      region      = "us-west-2"
      prefix      = "beacon-prod"
      kms_key_arn = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
    }
  }

  assert {
    condition = contains(jsondecode(aws_iam_user_policy.reader.policy).Statement, {
      Sid      = "DecryptBeaconObjects"
      Effect   = "Allow"
      Action   = "kms:Decrypt"
      Resource = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
    })
    error_message = "The reader needs kms:Decrypt to read an SSE-KMS bucket."
  }
}

run "queue_names_drop_characters_sqs_refuses" {
  command = plan

  variables {
    user_name = "asymptote.reader@acme"
  }

  assert {
    condition     = aws_sqs_queue.reader["runtime"].name == "asymptote-reader-acme-runtime"
    error_message = "IAM user names allow . and @, which SQS names do not."
  }
}

run "access_key_when_asked" {
  command = plan

  variables {
    create_access_key = true
  }

  assert {
    condition     = length(aws_iam_access_key.reader) == 1
    error_message = "create_access_key creates one key."
  }
}
