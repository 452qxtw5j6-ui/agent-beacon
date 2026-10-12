# Terraform for Beacon object storage forwarding

These modules create the cloud side of Beacon's object storage forwarding: the bucket
your Macs upload to, and the narrowly scoped identity their forwarder uses. You run
them in your own cloud account. Beacon itself never runs Terraform and never needs
your cloud credentials.

| Module | Creates | Guide |
| --- | --- | --- |
| [`aws-s3`](aws-s3) | An S3 bucket, a write-only IAM user, and optionally a read-only user for Beacon Cloud | [AWS S3 with Terraform](https://docs.beacon.sh/log-forwarding/aws-s3-terraform) |
| [`gcs`](gcs) | A Cloud Storage bucket, a create-only service account, and optionally read access for Beacon Cloud | [Google Cloud Storage with Terraform](https://docs.beacon.sh/log-forwarding/gcs-terraform) |

Use a module from your own configuration and pin it to a Beacon release:

```hcl
module "beacon_s3" {
  source = "github.com/asymptote-labs/agent-beacon//terraform/aws-s3?ref=<release tag>"

  bucket_name = "acme-beacon-telemetry"
  prefix      = "beacon-prod"
}
```

Neither module creates keys unless you ask it to (`create_access_keys`,
`create_writer_key`), so by default no secret is written to Terraform state. The
guides show how to create the key with the AWS CLI or gcloud instead.

## Development

The tests mock the cloud providers, so they need no account:

```bash
cd terraform/aws-s3   # or terraform/gcs
terraform init -backend=false
terraform test
```

CI runs `terraform fmt -check`, `validate` and `test` for both modules, and
`validate` for each example.
