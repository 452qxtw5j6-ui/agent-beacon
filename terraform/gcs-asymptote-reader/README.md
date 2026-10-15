# Asymptote reader for a Beacon Cloud Storage bucket

Gives Asymptote read access to a Beacon bucket created by the [`gcs`](../gcs) module, for
customers who keep Beacon telemetry in their own bucket and use Asymptote's dashboard:

- `roles/storage.objectViewer` on the bucket for Asymptote's reader,
  `beacon-clickpipes-reader@asymptote-labs.iam.gserviceaccount.com`. No key is involved;
- a Pub/Sub topic the bucket notifies of every new object below the Beacon prefix, with one
  subscription per stream (`runtime`, `inventory`) that Asymptote's reader may consume, so
  Asymptote loads objects in any order.

```hcl
module "beacon_gcs" {
  source = "github.com/asymptote-labs/agent-beacon//terraform/gcs?ref=<release tag>"

  project     = "acme-security"
  location    = "us-west1"
  bucket_name = "acme-beacon-telemetry"
  prefix      = "beacon-prod"
}

module "asymptote_reader" {
  source = "github.com/asymptote-labs/agent-beacon//terraform/gcs-asymptote-reader?ref=<release tag>"

  bucket = module.beacon_gcs.bucket
}
```

Send Asymptote the bucket name, the prefix and the `subscriptions` output.

The full walkthrough is on the Asymptote docs:
[Asymptote with your own Cloud Storage bucket](https://docs.asymptotelabs.ai/deployment/self-hosted-gcs).
