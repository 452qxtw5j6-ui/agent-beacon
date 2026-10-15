# Hermetic: the AWS provider is mocked, so these runs need no account or credentials.

mock_provider "aws" {
  mock_data "aws_partition" {
    defaults = {
      partition  = "aws"
      dns_suffix = "amazonaws.com"
    }
  }

  mock_resource "aws_s3_bucket" {
    defaults = {
      bucket = "acme-beacon-telemetry"
      region = "us-west-2"
    }
  }
}

variables {
  bucket_name = "acme-beacon-telemetry"
  prefix      = "beacon-prod"
}

run "writer_can_only_put_below_the_prefix" {
  command = plan

  assert {
    condition = jsondecode(aws_iam_user_policy.writer.policy).Statement == [
      {
        Sid      = "WriteBeaconObjects"
        Effect   = "Allow"
        Action   = "s3:PutObject"
        Resource = "arn:aws:s3:::acme-beacon-telemetry/beacon-prod/*"
      },
      {
        Sid      = "ForwarderHealthCheck"
        Effect   = "Allow"
        Action   = "s3:ListBucket"
        Resource = "arn:aws:s3:::acme-beacon-telemetry"
      },
    ]
    error_message = "The writer policy must grant only s3:PutObject below the prefix and the health-check s3:ListBucket."
  }

  assert {
    condition     = aws_iam_user_policy.writer.name == "BeaconEndpointWriteOnly" && aws_iam_user.writer.name == "beacon-endpoint-writer"
    error_message = "The writer keeps the names the manual guides use."
  }
}

run "no_access_keys_by_default" {
  command = plan

  assert {
    condition     = length(aws_iam_access_key.writer) == 0
    error_message = "The access key, whose secret would land in state, must be opt-in."
  }
}

run "new_bucket_is_hardened" {
  command = plan

  assert {
    condition = (
      aws_s3_bucket_public_access_block.this.block_public_acls
      && aws_s3_bucket_public_access_block.this.block_public_policy
      && aws_s3_bucket_public_access_block.this.ignore_public_acls
      && aws_s3_bucket_public_access_block.this.restrict_public_buckets
    )
    error_message = "A new bucket must block all public access."
  }

  assert {
    condition     = one(aws_s3_bucket_ownership_controls.this.rule).object_ownership == "BucketOwnerEnforced"
    error_message = "A new bucket must disable ACLs."
  }

  assert {
    condition     = one(one(aws_s3_bucket_server_side_encryption_configuration.this.rule).apply_server_side_encryption_by_default).sse_algorithm == "AES256"
    error_message = "Without a KMS key the bucket defaults to SSE-S3."
  }

  assert {
    condition     = one(aws_s3_bucket_versioning.this[0].versioning_configuration).status == "Enabled"
    error_message = "Versioning is on by default."
  }

  assert {
    condition     = aws_s3_bucket.this.force_destroy == false
    error_message = "A bucket holding telemetry must not be force-destroyed by default."
  }

  assert {
    condition = jsondecode(aws_s3_bucket_policy.this.policy).Statement == [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = ["arn:aws:s3:::acme-beacon-telemetry", "arn:aws:s3:::acme-beacon-telemetry/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
    ]
    error_message = "A new bucket must refuse requests that are not over TLS."
  }

  assert {
    condition     = one(aws_s3_bucket_lifecycle_configuration.this.rule[0].filter).prefix == "beacon-prod/"
    error_message = "The lifecycle rule applies only to the Beacon prefix."
  }

  assert {
    condition     = length(aws_s3_bucket_lifecycle_configuration.this.rule[0].expiration) == 0
    error_message = "Objects are kept forever unless expiration_days is set."
  }

  assert {
    condition     = one(aws_s3_bucket_lifecycle_configuration.this.rule[0].noncurrent_version_expiration).noncurrent_days == 30
    error_message = "Noncurrent versions expire after 30 days by default."
  }
}

run "forwarder_settings_match_the_helper" {
  command = apply

  assert {
    condition = output.forwarder_settings == {
      BEACON_S3_BUCKET        = "acme-beacon-telemetry"
      AWS_REGION              = "us-west-2"
      BEACON_S3_PREFIX        = "beacon-prod"
      BEACON_S3_STORAGE_CLASS = "STANDARD"
    }
    error_message = "forwarder_settings must carry exactly the variables install-forwarder.sh reads."
  }

  assert {
    condition = (
      output.bucket.name == "acme-beacon-telemetry"
      && output.bucket.arn == "arn:aws:s3:::acme-beacon-telemetry"
      && output.bucket.region == "us-west-2"
      && output.bucket.prefix == "beacon-prod"
      && output.bucket.kms_key_arn == null
    )
    error_message = "The bucket output carries what the reader module needs."
  }
}

run "kms_key_encrypts_and_is_granted" {
  command = plan

  variables {
    kms_key_arn = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
  }

  assert {
    condition = (
      one(one(aws_s3_bucket_server_side_encryption_configuration.this.rule).apply_server_side_encryption_by_default).sse_algorithm == "aws:kms"
      && one(one(aws_s3_bucket_server_side_encryption_configuration.this.rule).apply_server_side_encryption_by_default).kms_master_key_id == var.kms_key_arn
      && one(aws_s3_bucket_server_side_encryption_configuration.this.rule).bucket_key_enabled
    )
    error_message = "A KMS key becomes the bucket default, with an S3 Bucket Key."
  }

  assert {
    condition = contains(jsondecode(aws_iam_user_policy.writer.policy).Statement, {
      Sid      = "EncryptBeaconObjects"
      Effect   = "Allow"
      Action   = "kms:GenerateDataKey"
      Resource = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
    })
    error_message = "The writer needs kms:GenerateDataKey to upload to an SSE-KMS bucket."
  }
}

run "healthcheck_permission_can_be_dropped" {
  command = plan

  variables {
    allow_writer_healthcheck = false
  }

  assert {
    condition     = [for s in jsondecode(aws_iam_user_policy.writer.policy).Statement : s.Action] == ["s3:PutObject"]
    error_message = "Without the health check the writer holds s3:PutObject alone."
  }
}

run "writer_access_key_when_asked" {
  command = plan

  variables {
    create_writer_access_key = true
  }

  assert {
    condition     = length(aws_iam_access_key.writer) == 1
    error_message = "create_writer_access_key creates one key."
  }
}

run "expiration_when_asked" {
  command = plan

  variables {
    expiration_days    = 365
    versioning_enabled = false
  }

  assert {
    condition     = one(aws_s3_bucket_lifecycle_configuration.this.rule[0].expiration).days == 365
    error_message = "expiration_days expires current objects."
  }

  assert {
    condition     = length(aws_s3_bucket_versioning.this) == 0 && length(aws_s3_bucket_lifecycle_configuration.this.rule[0].noncurrent_version_expiration) == 0
    error_message = "Without versioning there is no versioning resource and no noncurrent rule."
  }
}

run "nested_prefix_is_allowed" {
  command = plan

  variables {
    prefix = "security/beacon"
  }

  assert {
    condition     = jsondecode(aws_iam_user_policy.writer.policy).Statement[0].Resource == "arn:aws:s3:::acme-beacon-telemetry/security/beacon/*"
    error_message = "A nested root prefix is scoped as written."
  }
}

run "rejects_stream_suffix_prefix" {
  command = plan

  variables {
    prefix = "beacon-prod/runtime"
  }

  expect_failures = [var.prefix]
}

run "rejects_slashes_around_prefix" {
  command = plan

  variables {
    prefix = "/beacon-prod/"
  }

  expect_failures = [var.prefix]
}

run "rejects_wildcard_prefix" {
  command = plan

  variables {
    prefix = "beacon*"
  }

  expect_failures = [var.prefix]
}

run "rejects_kms_alias" {
  command = plan

  variables {
    kms_key_arn = "arn:aws:kms:us-west-2:111122223333:alias/beacon"
  }

  expect_failures = [var.kms_key_arn]
}

run "rejects_fractional_expiration" {
  command = plan

  variables {
    expiration_days = 1.5
  }

  expect_failures = [var.expiration_days]
}
