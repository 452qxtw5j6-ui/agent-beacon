# Read-only access for Asymptote to a Beacon bucket created by the aws-s3 module.
#
# Asymptote's ClickPipes read the bucket in "any order" mode: S3 announces every new object on an
# SQS queue, and the pipe loads what the queue names. Without the queues a pipe lists objects in
# key order and skips any that sort before ones it has already loaded, which happens whenever Macs
# upload out of step.

data "aws_partition" "current" {}

data "aws_caller_identity" "current" {}

locals {
  streams = toset(["runtime", "inventory"])

  objects_arn = "${var.bucket.arn}/${var.bucket.prefix}/*"

  # SQS names allow letters, digits, hyphens and underscores; IAM user names allow a few more.
  queue_base = replace(var.user_name, "/[^A-Za-z0-9_-]/", "-")

  # S3's certificate for virtual-hosted URLs covers one label, so a dotted bucket name needs path style.
  s3_host = "s3.${var.bucket.region}.${data.aws_partition.current.dns_suffix}"
  source_url = (
    strcontains(var.bucket.name, ".")
    ? "https://${local.s3_host}/${var.bucket.name}/${var.bucket.prefix}"
    : "https://${var.bucket.name}.${local.s3_host}/${var.bucket.prefix}"
  )

  statements = concat(
    [
      {
        Sid      = "ListBeaconBucket"
        Effect   = "Allow"
        Action   = ["s3:ListBucket", "s3:GetBucketLocation"]
        Resource = var.bucket.arn
      },
      {
        Sid      = "ReadBeaconObjects"
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = local.objects_arn
      },
      # The four actions ClickPipes needs to consume the new-object queues.
      {
        Sid      = "ConsumeBeaconNotifications"
        Effect   = "Allow"
        Action   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
        Resource = [for queue in aws_sqs_queue.reader : queue.arn]
      },
      {
        Sid      = "FindBeaconQueues"
        Effect   = "Allow"
        Action   = "sqs:ListQueues"
        Resource = "*"
      },
    ],
    var.bucket.kms_key_arn == null ? [] : [
      {
        Sid      = "DecryptBeaconObjects"
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = var.bucket.kms_key_arn
      },
    ],
  )
}

resource "aws_iam_user" "reader" {
  name                 = var.user_name
  path                 = var.iam_path
  permissions_boundary = var.permissions_boundary_arn
  tags                 = var.tags
}

resource "aws_iam_user_policy" "reader" {
  name = "BeaconTelemetryReadOnly"
  user = aws_iam_user.reader.name
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = local.statements
  })
}

resource "aws_iam_access_key" "reader" {
  count = var.create_access_key ? 1 : 0

  user = aws_iam_user.reader.name
}

# A message that fails ten deliveries moves here instead of being dropped, so it can be redriven.
resource "aws_sqs_queue" "dead_letter" {
  for_each = local.streams

  name                      = "${local.queue_base}-${each.key}-dlq"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
  tags                      = var.tags
}

resource "aws_sqs_queue" "reader" {
  for_each = local.streams

  name                       = "${local.queue_base}-${each.key}"
  message_retention_seconds  = 1209600
  visibility_timeout_seconds = 300
  sqs_managed_sse_enabled    = true
  tags                       = var.tags

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.dead_letter[each.key].arn
    maxReceiveCount     = 10
  })
}

resource "aws_sqs_queue_policy" "reader" {
  for_each = local.streams

  queue_url = aws_sqs_queue.reader[each.key].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowBucketNotifications"
        Effect    = "Allow"
        Principal = { Service = "s3.amazonaws.com" }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.reader[each.key].arn
        Condition = {
          ArnEquals    = { "aws:SourceArn" = var.bucket.arn }
          StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        }
      },
    ]
  })
}

# S3 keeps one notification configuration per bucket. The aws-s3 module never sets one, so this
# module owns it.
resource "aws_s3_bucket_notification" "this" {
  bucket = var.bucket.name

  dynamic "queue" {
    for_each = local.streams
    content {
      id            = "beacon-${queue.key}"
      queue_arn     = aws_sqs_queue.reader[queue.key].arn
      events        = ["s3:ObjectCreated:*"]
      filter_prefix = "${var.bucket.prefix}/${queue.key}/"
    }
  }

  lifecycle {
    precondition {
      condition     = split(":", aws_sqs_queue.reader["runtime"].arn)[3] == var.bucket.region
      error_message = "S3 can only notify queues in the bucket's own region. Use a provider in ${var.bucket.region} for this module."
    }
  }

  # S3 checks that it may send to each queue when the configuration is written.
  depends_on = [aws_sqs_queue_policy.reader]
}
