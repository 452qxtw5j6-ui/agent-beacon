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

  mock_resource "google_pubsub_topic" {
    defaults = {
      id = "projects/acme-security/topics/beacon-acme-beacon-telemetry-objects"
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

run "no_key_reader_or_beacon_access_by_default" {
  command = plan

  assert {
    condition = (
      length(google_service_account_key.writer) == 0
      && length(google_service_account.reader) == 0
      && length(google_storage_bucket_iam_member.reader) == 0
      && length(google_storage_bucket_iam_member.beacon_reader) == 0
    )
    error_message = "Keys, the reader and Beacon read access must all be opt-in."
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
    condition     = output.writer_email == "beacon-endpoint-writer@acme-security.iam.gserviceaccount.com"
    error_message = "writer_email is the service account's email."
  }
}

run "beacon_read_access_when_asked" {
  command = plan

  variables {
    grant_beacon_read_access = true
    create_reader            = true
  }

  assert {
    condition = (
      google_storage_bucket_iam_member.beacon_reader[0].role == "roles/storage.objectViewer"
      && google_storage_bucket_iam_member.beacon_reader[0].member == "serviceAccount:beacon-clickpipes-reader@asymptote-labs.iam.gserviceaccount.com"
      && length(google_storage_bucket_iam_member.beacon_reader[0].condition) == 0
    )
    error_message = "Beacon's reader gets objectViewer on the bucket."
  }

  assert {
    condition     = google_storage_bucket_iam_member.reader[0].role == "roles/storage.objectViewer" && google_service_account.reader[0].account_id == "beacon-endpoint-reader"
    error_message = "create_reader adds the read-only service account the manual guides use."
  }
}

run "beacon_read_access_brings_new_object_subscriptions" {
  command = apply

  variables {
    grant_beacon_read_access = true
  }

  assert {
    condition = (
      google_pubsub_topic.beacon_reader[0].name == "beacon-acme-beacon-telemetry-objects"
      && google_pubsub_topic_iam_member.storage_agent[0].role == "roles/pubsub.publisher"
      && google_pubsub_topic_iam_member.storage_agent[0].member == "serviceAccount:service-123456789@gs-project-accounts.iam.gserviceaccount.com"
    )
    error_message = "Cloud Storage's service agent publishes new-object notifications to a topic for this bucket."
  }

  assert {
    condition = (
      google_storage_notification.beacon_reader[0].event_types == toset(["OBJECT_FINALIZE"])
      && google_storage_notification.beacon_reader[0].object_name_prefix == "beacon-prod/"
      && google_storage_notification.beacon_reader[0].payload_format == "JSON_API_V1"
    )
    error_message = "Every new object below the prefix is announced."
  }

  assert {
    condition = alltrue([
      for stream in ["runtime", "inventory"] :
      google_pubsub_subscription.beacon_reader[stream].name == "beacon-acme-beacon-telemetry-${stream}"
      && google_pubsub_subscription.beacon_reader[stream].filter == "attributes.eventType = \"OBJECT_FINALIZE\" AND hasPrefix(attributes.objectId, \"beacon-prod/${stream}/\")"
      && google_pubsub_subscription.beacon_reader[stream].ack_deadline_seconds == 60
      && google_pubsub_subscription.beacon_reader[stream].message_retention_duration == "604800s"
      && one(google_pubsub_subscription.beacon_reader[stream].expiration_policy).ttl == ""
    ])
    error_message = "Each stream has a never-expiring subscription filtered to its prefix, with the managed path's settings."
  }

  assert {
    condition = toset([
      for binding in google_pubsub_subscription_iam_member.beacon_reader : "${binding.subscription}|${binding.role}|${binding.member}"
      ]) == toset(flatten([
        for stream in ["runtime", "inventory"] : [
          for role in ["roles/pubsub.subscriber", "roles/pubsub.viewer"] :
          "${google_pubsub_subscription.beacon_reader[stream].name}|${role}|serviceAccount:beacon-clickpipes-reader@asymptote-labs.iam.gserviceaccount.com"
        ]
    ]))
    error_message = "Beacon's reader may consume and view both subscriptions, and nothing else gets access."
  }

  assert {
    condition = output.beacon_reader_subscriptions == {
      runtime   = google_pubsub_subscription.beacon_reader["runtime"].id
      inventory = google_pubsub_subscription.beacon_reader["inventory"].id
    }
    error_message = "beacon_reader_subscriptions gives the provisioning script's --queue-url values."
  }

  assert {
    condition     = contains(keys(google_project_service.this), "pubsub.googleapis.com")
    error_message = "Pub/Sub is enabled when Beacon reads the bucket."
  }
}

run "no_pubsub_without_beacon_read_access" {
  command = apply

  assert {
    condition = (
      length(google_pubsub_topic.beacon_reader) == 0
      && length(google_storage_notification.beacon_reader) == 0
      && length(google_pubsub_subscription.beacon_reader) == 0
      && output.beacon_reader_subscriptions == null
      && !contains(keys(google_project_service.this), "pubsub.googleapis.com")
    )
    error_message = "The topic, notification and subscriptions exist only with Beacon read access."
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
