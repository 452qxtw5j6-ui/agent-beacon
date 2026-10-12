# Terraform for Beacon object storage forwarding

These modules create the cloud side of Beacon's object storage forwarding: the bucket
your Macs upload to, and the narrowly scoped identity their forwarder uses. You run
them in your own cloud account. Beacon itself never runs Terraform and never needs
your cloud credentials.

| Module | Creates | Guide |
| --- | --- | --- |
| [`aws-s3`](aws-s3) | A new S3 bucket and a write-only IAM user | [AWS S3 with Terraform](https://docs.beacon.sh/log-forwarding/aws-s3-terraform) |
| [`gcs`](gcs) | A new Cloud Storage bucket and a create-only service account | [Google Cloud Storage with Terraform](https://docs.beacon.sh/log-forwarding/gcs-terraform) |
| [`aws-s3-asymptote-reader`](aws-s3-asymptote-reader) | Read-only access for Asymptote to an `aws-s3` bucket, with new-object SQS queues | [Asymptote with your own S3 bucket](https://docs.asymptotelabs.ai/deployment/self-hosted-s3) |
| [`gcs-asymptote-reader`](gcs-asymptote-reader) | Read access for Asymptote to a `gcs` bucket, with new-object Pub/Sub subscriptions | [Asymptote with your own Cloud Storage bucket](https://docs.asymptotelabs.ai/deployment/self-hosted-gcs) |

The reader modules take the base module's `bucket` output, so the bucket is always one the
base module created.

Use a module from your own configuration and pin it to a Beacon release:

```hcl
module "beacon_s3" {
  source = "github.com/asymptote-labs/agent-beacon//terraform/aws-s3?ref=<release tag>"

  bucket_name = "acme-beacon-telemetry"
  prefix      = "beacon-prod"
}
```

No module creates keys unless you ask it to (`create_writer_access_key`,
`create_writer_key`, `create_access_key`), so by default no secret is written to
Terraform state. The guides show how to create the keys with the AWS CLI or gcloud
instead.

## Development

The tests mock the cloud providers, so they need no account:

```bash
cd terraform/aws-s3   # or any other module directory
terraform init -backend=false
terraform test
```

CI runs `terraform fmt -check`, `validate` and `test` for every module, and
`validate` for each example.
