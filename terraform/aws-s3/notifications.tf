# Beacon Cloud's ClickPipes read the bucket in "any order" mode: S3 announces every new object on
# an SQS queue, and the pipe loads what the queue names. Without the queues a pipe lists objects in
# key order and skips any that sort before ones it has already loaded, which happens whenever Macs
# upload out of step.

locals {
  reader_streams = var.create_beacon_reader ? toset(["runtime", "inventory"]) : toset([])

  # SQS names allow letters, digits, hyphens and underscores; IAM user names allow a few more.
  reader_queue_base = replace(var.beacon_reader_user_name, "/[^A-Za-z0-9_-]/", "-")
}

# A message that fails ten deliveries moves here instead of being dropped, so it can be redriven.
resource "aws_sqs_queue" "beacon_reader_dead_letter" {
  for_each = local.reader_streams

  name                      = "${local.reader_queue_base}-${each.key}-dlq"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
  tags                      = var.tags
}

resource "aws_sqs_queue" "beacon_reader" {
  for_each = local.reader_streams

  name                       = "${local.reader_queue_base}-${each.key}"
  message_retention_seconds  = 1209600
  visibility_timeout_seconds = 300
  sqs_managed_sse_enabled    = true
  tags                       = var.tags

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.beacon_reader_dead_letter[each.key].arn
    maxReceiveCount     = 10
  })
}

resource "aws_sqs_queue_policy" "beacon_reader" {
  for_each = local.reader_streams

  queue_url = aws_sqs_queue.beacon_reader[each.key].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowBucketNotifications"
        Effect    = "Allow"
        Principal = { Service = "s3.amazonaws.com" }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.beacon_reader[each.key].arn
        Condition = {
          ArnEquals    = { "aws:SourceArn" = local.bucket_arn }
          StringEquals = { "aws:SourceAccount" = data.aws_caller_identity.current.account_id }
        }
      },
    ]
  })
}

# S3 keeps one notification configuration per bucket. The module owns this bucket, so it owns that too.
resource "aws_s3_bucket_notification" "this" {
  count = var.create_beacon_reader ? 1 : 0

  bucket = aws_s3_bucket.this.id

  dynamic "queue" {
    for_each = local.reader_streams
    content {
      id            = "beacon-${queue.key}"
      queue_arn     = aws_sqs_queue.beacon_reader[queue.key].arn
      events        = ["s3:ObjectCreated:*"]
      filter_prefix = "${var.prefix}/${queue.key}/"
    }
  }

  # S3 checks that it may send to each queue when the configuration is written.
  depends_on = [aws_sqs_queue_policy.beacon_reader]
}
