data "aws_partition" "current" {}

# Only read for an existing bucket: it confirms the bucket exists and reports its region. The lookup
# runs in the provider's region unless existing_bucket_region names another.
data "aws_s3_bucket" "existing" {
  count = var.create_bucket ? 0 : 1

  bucket = var.bucket_name
  region = var.existing_bucket_region
}

locals {
  bucket_arn = "arn:${data.aws_partition.current.partition}:s3:::${var.bucket_name}"

  # Beacon writes <prefix>/runtime/date=YYYY-MM-DD/... and <prefix>/inventory/date=YYYY-MM-DD/...
  beacon_objects_arn = "${local.bucket_arn}/${var.prefix}/*"

  bucket_region = var.create_bucket ? aws_s3_bucket.this[0].region : data.aws_s3_bucket.existing[0].region

  # S3's certificate for virtual-hosted URLs covers one label, so a dotted bucket name needs path style.
  s3_host = "s3.${local.bucket_region}.${data.aws_partition.current.dns_suffix}"
  beacon_reader_source_url = (
    strcontains(var.bucket_name, ".")
    ? "https://${local.s3_host}/${var.bucket_name}/${var.prefix}"
    : "https://${var.bucket_name}.${local.s3_host}/${var.prefix}"
  )
}

resource "aws_s3_bucket" "this" {
  count = var.create_bucket ? 1 : 0

  bucket        = var.bucket_name
  force_destroy = var.force_destroy
  tags          = var.tags

  lifecycle {
    precondition {
      condition     = var.existing_bucket_region == null
      error_message = "existing_bucket_region applies only with create_bucket = false. A new bucket is created in the provider's region."
    }
  }
}

resource "aws_s3_bucket_public_access_block" "this" {
  count = var.create_bucket ? 1 : 0

  bucket                  = aws_s3_bucket.this[0].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ACLs off: every object belongs to the bucket owner. The forwarder sends no ACL.
resource "aws_s3_bucket_ownership_controls" "this" {
  count = var.create_bucket ? 1 : 0

  bucket = aws_s3_bucket.this[0].id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# The forwarder sends no encryption headers, so the bucket default decides how objects are encrypted.
resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  count = var.create_bucket ? 1 : 0

  bucket = aws_s3_bucket.this[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.kms_key_arn == null ? "AES256" : "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = var.kms_key_arn != null
  }
}

resource "aws_s3_bucket_versioning" "this" {
  count = var.create_bucket && var.versioning_enabled ? 1 : 0

  bucket = aws_s3_bucket.this[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "this" {
  count = var.create_bucket ? 1 : 0

  bucket = aws_s3_bucket.this[0].id

  rule {
    id     = "beacon-telemetry"
    status = "Enabled"

    filter {
      prefix = "${var.prefix}/"
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }

    dynamic "expiration" {
      for_each = var.expiration_days == null ? [] : [var.expiration_days]
      content {
        days = expiration.value
      }
    }

    dynamic "noncurrent_version_expiration" {
      for_each = var.versioning_enabled ? [var.noncurrent_version_expiration_days] : []
      content {
        noncurrent_days = noncurrent_version_expiration.value
      }
    }
  }

  depends_on = [aws_s3_bucket_versioning.this]
}

resource "aws_s3_bucket_policy" "this" {
  count = var.create_bucket ? 1 : 0

  bucket = aws_s3_bucket.this[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [local.bucket_arn, "${local.bucket_arn}/*"]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
    ]
  })

  # S3 rejects a bucket policy written while the public access block is still being applied.
  depends_on = [aws_s3_bucket_public_access_block.this]
}
