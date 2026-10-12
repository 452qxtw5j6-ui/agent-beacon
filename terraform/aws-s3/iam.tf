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
  count = var.create_writer_access_key ? 1 : 0

  user = aws_iam_user.writer.name
}
