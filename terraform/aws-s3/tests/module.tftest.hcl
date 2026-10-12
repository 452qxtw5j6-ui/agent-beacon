# Hermetic: the AWS provider is mocked, so these runs need no account or credentials.

mock_provider "aws" {
  mock_data "aws_partition" {
    defaults = {
      partition = "aws"
    }
  }

  mock_data "aws_s3_bucket" {
    defaults = {
      bucket = "acme-security-logs"
      region = "eu-west-1"
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
    condition     = length(aws_iam_access_key.writer) == 0 && length(aws_iam_access_key.beacon_reader) == 0
    error_message = "Access keys, whose secrets would land in state, must be opt-in."
  }

  assert {
    condition     = length(aws_iam_user.beacon_reader) == 0
    error_message = "The Beacon reader must be opt-in."
  }
}

run "new_bucket_is_hardened" {
  command = plan

  assert {
    condition = (
      aws_s3_bucket_public_access_block.this[0].block_public_acls
      && aws_s3_bucket_public_access_block.this[0].block_public_policy
      && aws_s3_bucket_public_access_block.this[0].ignore_public_acls
      && aws_s3_bucket_public_access_block.this[0].restrict_public_buckets
    )
    error_message = "A new bucket must block all public access."
  }

  assert {
    condition     = one(aws_s3_bucket_ownership_controls.this[0].rule).object_ownership == "BucketOwnerEnforced"
    error_message = "A new bucket must disable ACLs."
  }

  assert {
    condition     = one(one(aws_s3_bucket_server_side_encryption_configuration.this[0].rule).apply_server_side_encryption_by_default).sse_algorithm == "AES256"
    error_message = "Without a KMS key the bucket defaults to SSE-S3."
  }

  assert {
    condition     = one(aws_s3_bucket_versioning.this[0].versioning_configuration).status == "Enabled"
    error_message = "Versioning is on by default."
  }

  assert {
    condition     = aws_s3_bucket.this[0].force_destroy == false
    error_message = "A bucket holding telemetry must not be force-destroyed by default."
  }

  assert {
    condition = jsondecode(aws_s3_bucket_policy.this[0].policy).Statement == [
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
    condition     = one(aws_s3_bucket_lifecycle_configuration.this[0].rule[0].filter).prefix == "beacon-prod/"
    error_message = "The lifecycle rule applies only to the Beacon prefix."
  }

  assert {
    condition     = length(aws_s3_bucket_lifecycle_configuration.this[0].rule[0].expiration) == 0
    error_message = "Objects are kept forever unless expiration_days is set."
  }

  assert {
    condition     = one(aws_s3_bucket_lifecycle_configuration.this[0].rule[0].noncurrent_version_expiration).noncurrent_days == 30
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
    condition     = output.beacon_reader_source_url == "https://acme-beacon-telemetry.s3.us-west-2.amazonaws.com/beacon-prod"
    error_message = "The data connector URL is the bucket's regional endpoint plus the prefix."
  }
}

run "kms_key_encrypts_and_is_granted" {
  command = plan

  variables {
    kms_key_arn          = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
    create_beacon_reader = true
  }

  assert {
    condition = (
      one(one(aws_s3_bucket_server_side_encryption_configuration.this[0].rule).apply_server_side_encryption_by_default).sse_algorithm == "aws:kms"
      && one(one(aws_s3_bucket_server_side_encryption_configuration.this[0].rule).apply_server_side_encryption_by_default).kms_master_key_id == var.kms_key_arn
      && one(aws_s3_bucket_server_side_encryption_configuration.this[0].rule).bucket_key_enabled
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

  assert {
    condition = contains(jsondecode(aws_iam_user_policy.beacon_reader[0].policy).Statement, {
      Sid      = "DecryptBeaconObjects"
      Effect   = "Allow"
      Action   = "kms:Decrypt"
      Resource = "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
    })
    error_message = "The Beacon reader needs kms:Decrypt to read an SSE-KMS bucket."
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

run "beacon_reader_reads_only_the_prefix" {
  command = plan

  variables {
    create_beacon_reader = true
  }

  assert {
    condition = jsondecode(aws_iam_user_policy.beacon_reader[0].policy).Statement == [
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
    ]
    error_message = "The Beacon reader may list the bucket and read only the Beacon prefix."
  }

  assert {
    condition     = aws_iam_user.beacon_reader[0].name == "beacon-s3-reader" && length(aws_iam_access_key.beacon_reader) == 0
    error_message = "The reader is created without a key unless create_access_keys is set."
  }
}

run "access_keys_when_asked" {
  command = plan

  variables {
    create_beacon_reader = true
    create_access_keys   = true
  }

  assert {
    condition     = length(aws_iam_access_key.writer) == 1 && length(aws_iam_access_key.beacon_reader) == 1
    error_message = "create_access_keys creates one key per user."
  }
}

run "existing_bucket_is_left_alone" {
  command = apply

  variables {
    create_bucket = false
    bucket_name   = "acme-security-logs"
  }

  assert {
    condition = (
      length(aws_s3_bucket.this) == 0
      && length(aws_s3_bucket_policy.this) == 0
      && length(aws_s3_bucket_public_access_block.this) == 0
      && length(aws_s3_bucket_server_side_encryption_configuration.this) == 0
      && length(aws_s3_bucket_versioning.this) == 0
      && length(aws_s3_bucket_lifecycle_configuration.this) == 0
      && length(aws_s3_bucket_ownership_controls.this) == 0
    )
    error_message = "With create_bucket = false the module must not manage any bucket setting."
  }

  assert {
    condition     = output.forwarder_settings.AWS_REGION == "eu-west-1" && output.forwarder_settings.BEACON_S3_BUCKET == "acme-security-logs"
    error_message = "An existing bucket's name and region come from the bucket itself."
  }

  assert {
    condition     = jsondecode(aws_iam_user_policy.writer.policy).Statement[0].Resource == "arn:aws:s3:::acme-security-logs/beacon-prod/*"
    error_message = "The writer is scoped to the existing bucket's Beacon prefix."
  }

  assert {
    condition     = data.aws_s3_bucket.existing[0].region == "eu-west-1"
    error_message = "Without existing_bucket_region the bucket is looked up in the provider's region."
  }
}

run "existing_bucket_in_another_region" {
  command = plan

  variables {
    create_bucket          = false
    bucket_name            = "acme-security-logs"
    existing_bucket_region = "ap-southeast-2"
  }

  assert {
    condition     = data.aws_s3_bucket.existing[0].region == "ap-southeast-2"
    error_message = "existing_bucket_region is where the bucket is looked up, so the lookup works across regions."
  }
}

run "rejects_existing_bucket_region_for_a_new_bucket" {
  command = plan

  variables {
    existing_bucket_region = "ap-southeast-2"
  }

  expect_failures = [aws_s3_bucket.this]
}

run "expiration_when_asked" {
  command = plan

  variables {
    expiration_days    = 365
    versioning_enabled = false
  }

  assert {
    condition     = one(aws_s3_bucket_lifecycle_configuration.this[0].rule[0].expiration).days == 365
    error_message = "expiration_days expires current objects."
  }

  assert {
    condition     = length(aws_s3_bucket_versioning.this) == 0 && length(aws_s3_bucket_lifecycle_configuration.this[0].rule[0].noncurrent_version_expiration) == 0
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
