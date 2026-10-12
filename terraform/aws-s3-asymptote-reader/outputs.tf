output "user_name" {
  description = "Read-only IAM user Asymptote reads the bucket with. Create its access key with: aws iam create-access-key --user-name <this value>"
  value       = aws_iam_user.reader.name
}

output "user_arn" {
  description = "ARN of the reader IAM user."
  value       = aws_iam_user.reader.arn
}

output "access_key_id" {
  description = "Reader access key ID, when create_access_key = true."
  value       = try(aws_iam_access_key.reader[0].id, null)
}

output "secret_access_key" {
  description = "Reader secret access key, when create_access_key = true."
  value       = try(aws_iam_access_key.reader[0].secret, null)
  sensitive   = true
}

output "source_url" {
  description = "The bucket location to send Asymptote."
  value       = local.source_url
}

output "queue_urls" {
  description = "The new-object queues to send Asymptote, by stream."
  value       = { for stream, queue in aws_sqs_queue.reader : stream => queue.url }
}
