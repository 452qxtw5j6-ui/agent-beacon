locals {
  writer_statements = concat(
    [
      {
        Sid      = "WriteBeaconObjects"
        Effect   = "Allow"
        Action   = "s3:PutObject"
        Resource = local.beacon_objects_arn
      },
    ],
    var.allow_writer_healthcheck ? [
      {
        Sid      = "ForwarderHealthCheck"
        Effect   = "Allow"
        Action   = "s3:ListBucket"
        Resource = local.bucket_arn
      },
    ] : [],
    var.kms_key_arn == null ? [] : [
      {
        Sid      = "EncryptBeaconObjects"
        Effect   = "Allow"
        Action   = "kms:GenerateDataKey"
        Resource = var.kms_key_arn
      },
    ],
  )

  reader_statements = concat(
    [
      {
        Sid      = "ListBeaconBucket"
        Effect   = "Allow"
        Action   = ["s3:ListBucket", "s3:GetBucketLocation"]
        Resource = local.bucket_arn
      },
      {
        Sid      = "ReadBeaconObjects"
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = local.beacon_objects_arn
      },
      # The four actions ClickPipes needs to consume the new-object queues.
      {
        Sid      = "ConsumeBeaconNotifications"
        Effect   = "Allow"
        Action   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
        Resource = [for queue in aws_sqs_queue.beacon_reader : queue.arn]
      },
      {
        Sid      = "FindBeaconQueues"
        Effect   = "Allow"
        Action   = "sqs:ListQueues"
        Resource = "*"
      },
    ],
    var.kms_key_arn == null ? [] : [
      {
        Sid      = "DecryptBeaconObjects"
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = var.kms_key_arn
      },
    ],
  )
}

# The identity every Mac's forwarder uses. It can create objects below the Beacon prefix, and it
# cannot read or delete them.
resource "aws_iam_user" "writer" {
  name                 = var.writer_user_name
  path                 = var.iam_path
  permissions_boundary = var.permissions_boundary_arn
  tags                 = var.tags
}

resource "aws_iam_user_policy" "writer" {
  name = "BeaconEndpointWriteOnly"
  user = aws_iam_user.writer.name
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = local.writer_statements
  })
}

resource "aws_iam_access_key" "writer" {
  count = var.create_access_keys ? 1 : 0

  user = aws_iam_user.writer.name
}

# Beacon Cloud's S3 data connector reads with an access key; it cannot assume a role in your account.
resource "aws_iam_user" "beacon_reader" {
  count = var.create_beacon_reader ? 1 : 0

  name                 = var.beacon_reader_user_name
  path                 = var.iam_path
  permissions_boundary = var.permissions_boundary_arn
  tags                 = var.tags
}

resource "aws_iam_user_policy" "beacon_reader" {
  count = var.create_beacon_reader ? 1 : 0

  name = "BeaconTelemetryReadOnly"
  user = aws_iam_user.beacon_reader[0].name
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = local.reader_statements
  })
}

resource "aws_iam_access_key" "beacon_reader" {
  count = var.create_beacon_reader && var.create_access_keys ? 1 : 0

  user = aws_iam_user.beacon_reader[0].name
}
