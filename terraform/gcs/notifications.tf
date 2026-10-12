# Beacon Cloud's ClickPipes read the bucket in "any order" mode: Cloud Storage announces every new
# object on Pub/Sub, and the pipe loads what its subscription names. Without them a pipe lists
# objects in name order and skips any that sort before ones it has already loaded, which happens
# whenever Macs upload out of step. The subscriptions match the ones Beacon's managed ingest uses.

locals {
  reader_streams = var.grant_beacon_read_access ? toset(["runtime", "inventory"]) : toset([])
}

resource "google_pubsub_topic" "beacon_reader" {
  count = var.grant_beacon_read_access ? 1 : 0

  project = var.project
  name    = "beacon-${var.bucket_name}-objects"
  labels  = var.labels

  depends_on = [google_project_service.this]
}

resource "google_pubsub_topic_iam_member" "storage_agent" {
  count = var.grant_beacon_read_access ? 1 : 0

  project = var.project
  topic   = google_pubsub_topic.beacon_reader[0].name
  role    = "roles/pubsub.publisher"
  member  = "serviceAccount:${data.google_storage_project_service_account.this[0].email_address}"
}

resource "google_storage_notification" "beacon_reader" {
  count = var.grant_beacon_read_access ? 1 : 0

  bucket             = google_storage_bucket.this.name
  topic              = google_pubsub_topic.beacon_reader[0].id
  payload_format     = "JSON_API_V1"
  event_types        = ["OBJECT_FINALIZE"]
  object_name_prefix = "${var.prefix}/"

  # Cloud Storage checks that it may publish to the topic when the notification is created.
  depends_on = [google_pubsub_topic_iam_member.storage_agent]
}

resource "google_pubsub_subscription" "beacon_reader" {
  for_each = local.reader_streams

  project                    = var.project
  name                       = "beacon-${var.bucket_name}-${each.key}"
  topic                      = google_pubsub_topic.beacon_reader[0].id
  filter                     = "attributes.eventType = \"OBJECT_FINALIZE\" AND hasPrefix(attributes.objectId, \"${var.prefix}/${each.key}/\")"
  ack_deadline_seconds       = 60
  message_retention_duration = "604800s"
  labels                     = var.labels

  # An empty TTL never expires the subscription. The default expires it after 31 quiet days,
  # which would silently stop ingestion from a fleet that was offline for a month.
  expiration_policy {
    ttl = ""
  }
}

resource "google_pubsub_subscription_iam_member" "beacon_reader" {
  for_each = {
    for pair in setproduct(local.reader_streams, ["roles/pubsub.subscriber", "roles/pubsub.viewer"]) :
    "${pair[0]}:${pair[1]}" => { stream = pair[0], role = pair[1] }
  }

  project      = var.project
  subscription = google_pubsub_subscription.beacon_reader[each.value.stream].name
  role         = each.value.role
  member       = var.beacon_reader_member
}
