# Hermetic: the Google provider is mocked, so these runs need no project or credentials.

mock_provider "google" {
  mock_resource "google_service_account" {
    defaults = {
      email = "beacon-endpoint-writer@acme-security.iam.gserviceaccount.com"
      name  = "projects/acme-security/serviceAccounts/beacon-endpoint-writer@acme-security.iam.gserviceaccount.com"
    }
  }

  mock_resource "google_storage_bucket" {
    defaults = {
      name = "acme-beacon-telemetry"
    }
  }

  mock_data "google_storage_project_service_account" {
    defaults = {
      email_address = "service-123456789@gs-project-accounts.iam.gserviceaccount.com"
    }
  }
}

variables {
  project     = "acme-security"
  bucket_name = "acme-beacon-telemetry"
  location    = "us-west1"
  prefix      = "beacon-prod"
}

run "writer_can_only_create_below_the_prefix" {
  command = plan

  assert {
    condition     = google_storage_bucket_iam_member.writer.role == "roles/storage.objectCreator"
    error_message = "The writer may only create objects."
  }

  assert {
    condition     = one(google_storage_bucket_iam_member.writer.condition).expression == "resource.name.startsWith(\"projects/_/buckets/acme-beacon-telemetry/objects/beacon-prod/\")"
    error_message = "The writer is limited to the Beacon prefix."
  }

  assert {
    condition     = google_service_account.writer.account_id == "beacon-endpoint-writer"
    error_message = "The writer keeps the name the manual guides use."
  }
}

run "no_key_or_reader_by_default" {
  command = plan

  assert {
    condition = (
      length(google_service_account_key.writer) == 0
      && length(google_service_account.reader) == 0
      && length(google_storage_bucket_iam_member.reader) == 0
    )
    error_message = "The key and the reader must be opt-in."
  }
}

run "new_bucket_is_hardened" {
  command = plan

  assert {
    condition = (
      google_storage_bucket.this.uniform_bucket_level_access
      && google_storage_bucket.this.public_access_prevention == "enforced"
      && google_storage_bucket.this.force_destroy == false
      && one(google_storage_bucket.this.versioning).enabled
      && google_storage_bucket.this.location == "us-west1"
      && google_storage_bucket.this.storage_class == "STANDARD"
    )
    error_message = "A new bucket uses uniform access, enforced public access prevention and versioning."
  }

  assert {
    condition     = length(google_storage_bucket.this.encryption) == 0
    error_message = "Without a KMS key the bucket uses Google-managed encryption."
  }

  assert {
    condition = (
      length(google_storage_bucket.this.lifecycle_rule) == 1
      && one(google_storage_bucket.this.lifecycle_rule[0].condition).days_since_noncurrent_time == 30
      && one(google_storage_bucket.this.lifecycle_rule[0].condition).matches_prefix == tolist(["beacon-prod/"])
    )
    error_message = "By default only noncurrent versions below the prefix expire, after 30 days."
  }

  assert {
    condition     = google_project_service.this["storage.googleapis.com"].disable_on_destroy == false
    error_message = "The module enables the APIs it needs and never disables them."
  }
}

run "forwarder_settings_match_the_helper" {
  command = apply

  assert {
    condition = output.forwarder_settings == {
      BEACON_GCS_BUCKET        = "acme-beacon-telemetry"
      BEACON_GCS_PREFIX        = "beacon-prod"
      BEACON_GCS_STORAGE_CLASS = "STANDARD"
    }
    error_message = "forwarder_settings must carry exactly the variables install-forwarder.sh reads."
  }

  assert {
    condition     = output.bucket.name == "acme-beacon-telemetry" && output.bucket.project == "acme-security" && output.bucket.prefix == "beacon-prod"
    error_message = "The bucket output carries what the reader module needs."
  }

  assert {
    condition     = output.writer_email == "beacon-endpoint-writer@acme-security.iam.gserviceaccount.com"
    error_message = "writer_email is the service account's email."
  }
}

run "kms_key_encrypts_and_is_granted_to_the_storage_agent" {
  command = plan

  variables {
    kms_key_name = "projects/acme-security/locations/us-west1/keyRings/beacon/cryptoKeys/telemetry"
  }

  assert {
    condition     = one(google_storage_bucket.this.encryption).default_kms_key_name == var.kms_key_name
    error_message = "The key becomes the bucket's default encryption."
  }

  assert {
    condition = (
      google_kms_crypto_key_iam_member.storage_agent[0].crypto_key_id == var.kms_key_name
      && google_kms_crypto_key_iam_member.storage_agent[0].role == "roles/cloudkms.cryptoKeyEncrypterDecrypter"
      && google_kms_crypto_key_iam_member.storage_agent[0].member == "serviceAccount:service-123456789@gs-project-accounts.iam.gserviceaccount.com"
    )
    error_message = "Cloud Storage's service agent must be able to use the key."
  }
}

run "expiration_when_asked" {
  command = plan

  variables {
    expiration_days    = 365
    versioning_enabled = false
  }

  assert {
    condition = (
      length(google_storage_bucket.this.lifecycle_rule) == 1
      && one(google_storage_bucket.this.lifecycle_rule[0].condition).age == 365
      && one(google_storage_bucket.this.lifecycle_rule[0].condition).matches_prefix == tolist(["beacon-prod/"])
    )
    error_message = "expiration_days deletes objects below the prefix, and no noncurrent rule exists without versioning."
  }
}

run "key_when_asked" {
  command = plan

  variables {
    create_writer_key = true
  }

  assert {
    condition     = length(google_service_account_key.writer) == 1
    error_message = "create_writer_key creates one key."
  }
}

run "rejects_stream_suffix_prefix" {
  command = plan

  variables {
    prefix = "beacon-prod/inventory"
  }

  expect_failures = [var.prefix]
}

run "rejects_short_kms_name" {
  command = plan

  variables {
    kms_key_name = "telemetry"
  }

  expect_failures = [var.kms_key_name]
}

run "reader_when_asked" {
  command = plan

  variables {
    create_reader = true
  }

  assert {
    condition     = google_storage_bucket_iam_member.reader[0].role == "roles/storage.objectViewer" && google_service_account.reader[0].account_id == "beacon-endpoint-reader"
    error_message = "create_reader adds the read-only service account the manual guides use."
  }
}
