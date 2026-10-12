# Beacon Google Cloud Storage module

Creates the Google Cloud side of Beacon's GCS forwarding:

- a new, dedicated Cloud Storage bucket with uniform bucket-level access, public access
  prevention enforced, versioning, optional CMEK (`kms_key_name`), and lifecycle rules
  scoped to the Beacon prefix;
- `beacon-endpoint-writer`, a service account with `roles/storage.objectCreator` on
  the bucket, limited by an IAM condition to objects below the prefix;
- optionally a read-only `beacon-endpoint-reader` (`create_reader = true`) for
  checking uploads.

```hcl
provider "google" {
  project = "acme-security"
}

module "beacon_gcs" {
  source = "github.com/asymptote-labs/agent-beacon//terraform/gcs?ref=<release tag>"

  project     = "acme-security"
  location    = "us-west1"
  bucket_name = "acme-beacon-telemetry"
  prefix      = "beacon-prod"
}

output "forwarder_settings" {
  value = module.beacon_gcs.forwarder_settings
}
```

After `terraform apply`, create the writer's key outside Terraform, so the private key
never enters state:

```bash
gcloud iam service-accounts keys create beacon-gcs-writer.json \
  --iam-account beacon-endpoint-writer@acme-security.iam.gserviceaccount.com
```

`forwarder_settings` holds the non-secret values the packaged forwarder helper reads
(`BEACON_GCS_BUCKET`, `BEACON_GCS_PREFIX`, `BEACON_GCS_STORAGE_CLASS`). The helper
also needs `GOOGLE_APPLICATION_CREDENTIALS`, the path of the key file on the Mac.

Every input is described in [`variables.tf`](variables.tf), and every output in
[`outputs.tf`](outputs.tf). The full walkthrough is
[Google Cloud Storage with Terraform](https://docs.beacon.sh/log-forwarding/gcs-terraform).
