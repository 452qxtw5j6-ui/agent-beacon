output "bucket_name" {
  description = "Bucket Beacon writes to."
  value       = google_storage_bucket.this.name
}

output "bucket_url" {
  description = "gs:// URL of the Beacon prefix."
  value       = "gs://${google_storage_bucket.this.name}/${var.prefix}/"
}

output "prefix" {
  description = "Root prefix Beacon writes below (BEACON_GCS_PREFIX)."
  value       = var.prefix
}

output "bucket" {
  description = "The bucket as one object, for the gcs-asymptote-reader module: bucket = module.beacon_gcs.bucket."
  value = {
    name    = google_storage_bucket.this.name
    project = var.project
    prefix  = var.prefix
  }
}

output "storage_class" {
  description = "Storage class the forwarder writes objects with (BEACON_GCS_STORAGE_CLASS)."
  value       = var.storage_class
}

output "forwarder_settings" {
  description = "The non-secret settings Beacon's GCS forwarder helper reads, keyed by environment variable name. The helper also needs GOOGLE_APPLICATION_CREDENTIALS, the path of the writer's key file on the Mac."
  value = {
    BEACON_GCS_BUCKET        = google_storage_bucket.this.name
    BEACON_GCS_PREFIX        = var.prefix
    BEACON_GCS_STORAGE_CLASS = var.storage_class
  }
}

output "writer_email" {
  description = "Service account the forwarder authenticates as. Create its key with: gcloud iam service-accounts keys create beacon-gcs-writer.json --iam-account <this value>"
  value       = google_service_account.writer.email
}

output "writer_private_key" {
  description = "Base64-encoded JSON key for the writer, when create_writer_key = true. Decode it with: terraform output -raw writer_private_key | base64 --decode"
  value       = try(google_service_account_key.writer[0].private_key, null)
  sensitive   = true
}

output "reader_email" {
  description = "Read-only service account, when create_reader = true."
  value       = try(google_service_account.reader[0].email, null)
}
