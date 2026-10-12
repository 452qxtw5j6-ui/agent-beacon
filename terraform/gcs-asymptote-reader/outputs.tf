output "subscriptions" {
  description = "The new-object subscriptions to send Asymptote, by stream."
  value       = { for stream, sub in google_pubsub_subscription.reader : stream => sub.id }
}

output "topic" {
  description = "The Pub/Sub topic the bucket publishes new objects to."
  value       = google_pubsub_topic.objects.id
}
