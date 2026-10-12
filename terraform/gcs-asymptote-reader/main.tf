# Read access for Asymptote to a Beacon bucket created by the gcs module.
#
# Asymptote's ClickPipes read the bucket in "any order" mode: Cloud Storage announces every new
# object on Pub/Sub, and the pipe loads what its subscription names. Without them a pipe lists
# objects in name order and skips any that sort before ones it has already loaded, which happens
# whenever Macs upload out of step. The subscriptions match the ones Asymptote's managed ingest uses.

locals {
  streams = toset(["runtime", "inventory"])
}

resource "google_project_service" "pubsub" {
  count = var.enable_apis ? 1 : 0

  project            = var.bucket.project
  service            = "pubsub.googleapis.com"
  disable_on_destroy = false
}

# Asymptote reads with its own service account, so no key is involved.
resource "google_storage_bucket_iam_member" "reader" {
  bucket = var.bucket.name
  role   = "roles/storage.objectViewer"
  member = var.reader_member
}

# Cloud Storage publishes notifications as its own service agent.
data "google_storage_project_service_account" "this" {
  project = var.bucket.project
}

resource "google_pubsub_topic" "objects" {
  project = var.bucket.project
  name    = "asymptote-${var.bucket.name}-objects"
  labels  = var.labels

  depends_on = [google_project_service.pubsub]
}

resource "google_pubsub_topic_iam_member" "storage_agent" {
  project = var.bucket.project
  topic   = google_pubsub_topic.objects.name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${data.google_storage_project_service_account.this.email_address}"
}

resource "google_storage_notification" "objects" {
  bucket             = var.bucket.name
  topic              = google_pubsub_topic.objects.id
  payload_format     = "JSON_API_V1"
  event_types        = ["OBJECT_FINALIZE"]
  object_name_prefix = "${var.bucket.prefix}/"

  # Cloud Storage checks that it may publish to the topic when the notification is created.
  depends_on = [google_pubsub_topic_iam_member.storage_agent]
}

resource "google_pubsub_subscription" "reader" {
  for_each = local.streams

  project                    = var.bucket.project
  name                       = "asymptote-${var.bucket.name}-${each.key}"
  topic                      = google_pubsub_topic.objects.id
  filter                     = "attributes.eventType = \"OBJECT_FINALIZE\" AND hasPrefix(attributes.objectId, \"${var.bucket.prefix}/${each.key}/\")"
  ack_deadline_seconds       = 60
  message_retention_duration = "604800s"
  labels                     = var.labels

  # An empty TTL never expires the subscription. The default expires it after 31 quiet days,
  # which would silently stop ingestion from a fleet that was offline for a month.
  expiration_policy {
    ttl = ""
  }
}

resource "google_pubsub_subscription_iam_member" "reader" {
  for_each = {
    for pair in setproduct(local.streams, ["roles/pubsub.subscriber", "roles/pubsub.viewer"]) :
    "${pair[0]}:${pair[1]}" => { stream = pair[0], role = pair[1] }
  }

  project      = var.bucket.project
  subscription = google_pubsub_subscription.reader[each.value.stream].name
  role         = each.value.role
  member       = var.reader_member
}
