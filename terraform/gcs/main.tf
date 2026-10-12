locals {
  apis = var.enable_apis ? toset(["storage.googleapis.com", "iam.googleapis.com"]) : toset([])

  bucket_name = var.create_bucket ? google_storage_bucket.this[0].name : var.bucket_name

  # Beacon writes <prefix>/runtime/date=YYYY-MM-DD/... and <prefix>/inventory/date=YYYY-MM-DD/...
  # The condition is built from the variable, not the bucket resource, so it is known at plan time.
  writer_condition = "resource.name.startsWith(\"projects/_/buckets/${var.bucket_name}/objects/${var.prefix}/\")"
}

resource "google_project_service" "this" {
  for_each = local.apis

  project            = var.project
  service            = each.value
  disable_on_destroy = false
}

data "google_storage_project_service_account" "this" {
  count = var.create_bucket && var.kms_key_name != null && var.grant_kms_to_storage_agent ? 1 : 0

  project = var.project

  depends_on = [google_project_service.this]
}

# Cloud Storage encrypts with a customer-managed key as its own service agent, not as the writer.
resource "google_kms_crypto_key_iam_member" "storage_agent" {
  count = length(data.google_storage_project_service_account.this)

  crypto_key_id = var.kms_key_name
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${data.google_storage_project_service_account.this[0].email_address}"
}

resource "google_storage_bucket" "this" {
  count = var.create_bucket ? 1 : 0

  project                     = var.project
  name                        = var.bucket_name
  location                    = var.location
  storage_class               = var.storage_class
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = var.force_destroy
  labels                      = var.labels

  versioning {
    enabled = var.versioning_enabled
  }

  dynamic "encryption" {
    for_each = var.kms_key_name == null ? [] : [var.kms_key_name]
    content {
      default_kms_key_name = encryption.value
    }
  }

  dynamic "lifecycle_rule" {
    for_each = var.expiration_days == null ? [] : [var.expiration_days]
    content {
      action {
        type = "Delete"
      }
      condition {
        age            = lifecycle_rule.value
        matches_prefix = ["${var.prefix}/"]
      }
    }
  }

  dynamic "lifecycle_rule" {
    for_each = var.versioning_enabled ? [var.noncurrent_version_expiration_days] : []
    content {
      action {
        type = "Delete"
      }
      condition {
        days_since_noncurrent_time = lifecycle_rule.value
        matches_prefix             = ["${var.prefix}/"]
      }
    }
  }

  lifecycle {
    precondition {
      condition     = var.location != null
      error_message = "location is required when create_bucket = true."
    }
  }

  depends_on = [google_project_service.this, google_kms_crypto_key_iam_member.storage_agent]
}

# The identity every Mac's forwarder uses. roles/storage.objectCreator can create objects but not
# list, read, replace or delete them.
resource "google_service_account" "writer" {
  project      = var.project
  account_id   = var.writer_account_id
  display_name = "Beacon endpoint GCS writer"
  description  = "Uploads Beacon endpoint telemetry to gs://${var.bucket_name}/${var.prefix}/"

  depends_on = [google_project_service.this]
}

resource "google_storage_bucket_iam_member" "writer" {
  bucket = local.bucket_name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${google_service_account.writer.email}"

  dynamic "condition" {
    for_each = var.scope_writer_to_prefix ? [local.writer_condition] : []
    content {
      title       = "beacon-prefix-only"
      description = "Create objects only below the Beacon prefix."
      expression  = condition.value
    }
  }
}

resource "google_service_account_key" "writer" {
  count = var.create_writer_key ? 1 : 0

  service_account_id = google_service_account.writer.name
}

resource "google_service_account" "reader" {
  count = var.create_reader ? 1 : 0

  project      = var.project
  account_id   = var.reader_account_id
  display_name = "Beacon endpoint GCS reader"
  description  = "Reads Beacon endpoint telemetry in gs://${var.bucket_name}"

  depends_on = [google_project_service.this]
}

resource "google_storage_bucket_iam_member" "reader" {
  count = var.create_reader ? 1 : 0

  bucket = local.bucket_name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.reader[0].email}"
}

resource "google_storage_bucket_iam_member" "beacon_reader" {
  count = var.grant_beacon_read_access ? 1 : 0

  bucket = local.bucket_name
  role   = "roles/storage.objectViewer"
  member = var.beacon_reader_member
}
