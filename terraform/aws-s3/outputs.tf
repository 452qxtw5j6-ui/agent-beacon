output "bucket_name" {
  description = "Bucket Beacon writes to."
  value       = aws_s3_bucket.this.bucket
}

output "bucket_arn" {
  description = "ARN of the bucket."
  value       = local.bucket_arn
}

output "region" {
  description = "Region of the bucket (AWS_REGION for the forwarder)."
  value       = aws_s3_bucket.this.region
}

output "prefix" {
  description = "Root prefix Beacon writes below (BEACON_S3_PREFIX)."
  value       = var.prefix
}

output "bucket" {
  description = "The bucket as one object, for the aws-s3-asymptote-reader module: bucket = module.beacon_s3.bucket."
  value = {
    name        = aws_s3_bucket.this.bucket
    arn         = local.bucket_arn
    region      = aws_s3_bucket.this.region
    prefix      = var.prefix
    kms_key_arn = var.kms_key_arn
  }
}

output "storage_class" {
  description = "Storage class the forwarder writes objects with (BEACON_S3_STORAGE_CLASS)."
  value       = var.storage_class
}

output "forwarder_settings" {
  description = "The non-secret settings Beacon's S3 forwarder helper reads, keyed by environment variable name."
  value = {
    BEACON_S3_BUCKET        = aws_s3_bucket.this.bucket
    AWS_REGION              = aws_s3_bucket.this.region
    BEACON_S3_PREFIX        = var.prefix
    BEACON_S3_STORAGE_CLASS = var.storage_class
  }
}

output "writer_user_name" {
  description = "IAM user the forwarder authenticates as. Create its access key with: aws iam create-access-key --user-name <this value>"
  value       = aws_iam_user.writer.name
}

output "writer_user_arn" {
  description = "ARN of the writer IAM user."
  value       = aws_iam_user.writer.arn
}

output "writer_access_key_id" {
  description = "Writer access key ID, when create_writer_access_key = true."
  value       = try(aws_iam_access_key.writer[0].id, null)
}

output "writer_secret_access_key" {
  description = "Writer secret access key, when create_writer_access_key = true. Read it with terraform output -raw writer_secret_access_key."
  value       = try(aws_iam_access_key.writer[0].secret, null)
  sensitive   = true
}
