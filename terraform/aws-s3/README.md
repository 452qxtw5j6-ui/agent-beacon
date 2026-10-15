# Beacon AWS S3 module

Creates the AWS side of Beacon's S3 forwarding:

- a new, dedicated S3 bucket with public access blocked, ACLs disabled, TLS required,
  default encryption (SSE-S3, or SSE-KMS with `kms_key_arn`), versioning, and a
  lifecycle rule scoped to the Beacon prefix;
- `beacon-endpoint-writer`, an IAM user that can only `s3:PutObject` below the prefix
  (plus `s3:ListBucket` for the forwarder's startup health check);
- optionally the writer's access key (`create_writer_access_key = true`), though the
  docs create it with the AWS CLI so its secret stays out of Terraform state.

```hcl
provider "aws" {
  region = "us-west-2"
}

module "beacon_s3" {
  source = "github.com/asymptote-labs/agent-beacon//terraform/aws-s3?ref=<release tag>"

  bucket_name = "acme-beacon-telemetry"
  prefix      = "beacon-prod"
}

output "forwarder_settings" {
  value = module.beacon_s3.forwarder_settings
}
```

After `terraform apply`, create the writer's access key outside Terraform, so its
secret never enters state:

```bash
aws iam create-access-key --user-name beacon-endpoint-writer
```

`forwarder_settings` holds the non-secret values the packaged forwarder helper reads
(`BEACON_S3_BUCKET`, `AWS_REGION`, `BEACON_S3_PREFIX`, `BEACON_S3_STORAGE_CLASS`).

The module needs Terraform 1.5 or later and the AWS provider 5.0 or later. The bucket
is created in the provider's region. The module always creates its own bucket; it does
not manage existing ones.

Before `terraform destroy`, delete the access keys you created with the AWS CLI. IAM
refuses to delete a user that still has keys, which keeps a rename or replace from
cutting off every Mac at once.

Every input is described in [`variables.tf`](variables.tf), and every output in
[`outputs.tf`](outputs.tf). The full walkthrough, including Fleet, Jamf and
single-Mac handoff, is [AWS S3 with Terraform](https://docs.beacon.sh/log-forwarding/aws-s3-terraform).
