# Hermetic: the Google provider is mocked, so these runs need no project or credentials.

mock_provider "google" {
  mock_resource "google_pubsub_topic" {
    defaults = {
      id = "projects/acme-security/topics/asymptote-acme-beacon-telemetry-objects"
    }
  }

  mock_data "google_storage_project_service_account" {
    defaults = {
      email_address = "service-123456789@gs-project-accounts.iam.gserviceaccount.com"
    }
  }
}

variables {
  bucket = {
    name    = "acme-beacon-telemetry"
    project = "acme-security"
    prefix  = "beacon-prod"
  }
}

run "asymptote_can_read_the_bucket" {
  command = plan

  assert {
    condition = (
      google_storage_bucket_iam_member.reader.bucket == "acme-beacon-telemetry"
      && google_storage_bucket_iam_member.reader.role == "roles/storage.objectViewer"
      && google_storage_bucket_iam_member.reader.member == "serviceAccount:beacon-clickpipes-reader@asymptote-labs.iam.gserviceaccount.com"
    )
    error_message = "Asymptote's reader gets objectViewer on the bucket."
  }
}

run "new_objects_are_announced_per_stream" {
  command = apply

  assert {
    condition = (
      google_pubsub_topic.objects.name == "asymptote-acme-beacon-telemetry-objects"
      && google_pubsub_topic_iam_member.storage_agent.role == "roles/pubsub.publisher"
      && google_pubsub_topic_iam_member.storage_agent.member == "serviceAccount:service-123456789@gs-project-accounts.iam.gserviceaccount.com"
    )
    error_message = "Cloud Storage's service agent publishes new-object notifications to a topic for this bucket."
  }

  assert {
    condition = (
      google_storage_notification.objects.bucket == "acme-beacon-telemetry"
      && google_storage_notification.objects.event_types == toset(["OBJECT_FINALIZE"])
      && google_storage_notification.objects.object_name_prefix == "beacon-prod/"
      && google_storage_notification.objects.payload_format == "JSON_API_V1"
    )
    error_message = "Every new object below the prefix is announced."
  }

  assert {
    condition = alltrue([
      for stream in ["runtime", "inventory"] :
      google_pubsub_subscription.reader[stream].name == "asymptote-acme-beacon-telemetry-${stream}"
      && google_pubsub_subscription.reader[stream].filter == "attributes.eventType = \"OBJECT_FINALIZE\" AND hasPrefix(attributes.objectId, \"beacon-prod/${stream}/\")"
      && google_pubsub_subscription.reader[stream].ack_deadline_seconds == 60
      && google_pubsub_subscription.reader[stream].message_retention_duration == "604800s"
      && one(google_pubsub_subscription.reader[stream].expiration_policy).ttl == ""
    ])
    error_message = "Each stream has a never-expiring subscription filtered to its prefix, with the managed path's settings."
  }

  assert {
    condition = toset([
      for binding in google_pubsub_subscription_iam_member.reader : "${binding.subscription}|${binding.role}|${binding.member}"
      ]) == toset(flatten([
        for stream in ["runtime", "inventory"] : [
          for role in ["roles/pubsub.subscriber", "roles/pubsub.viewer"] :
          "${google_pubsub_subscription.reader[stream].name}|${role}|serviceAccount:beacon-clickpipes-reader@asymptote-labs.iam.gserviceaccount.com"
        ]
    ]))
    error_message = "Asymptote's reader may consume and view both subscriptions, and nothing else gets access."
  }

  assert {
    condition = output.subscriptions == {
      runtime   = google_pubsub_subscription.reader["runtime"].id
      inventory = google_pubsub_subscription.reader["inventory"].id
    }
    error_message = "subscriptions gives the provisioning script's --queue-url values."
  }

  assert {
    condition     = google_project_service.pubsub[0].service == "pubsub.googleapis.com" && google_project_service.pubsub[0].disable_on_destroy == false
    error_message = "The module enables Pub/Sub and never disables it."
  }
}

run "apis_left_alone_when_asked" {
  command = plan

  variables {
    enable_apis = false
  }

  assert {
    condition     = length(google_project_service.pubsub) == 0
    error_message = "enable_apis = false leaves the project's APIs alone."
  }
}
