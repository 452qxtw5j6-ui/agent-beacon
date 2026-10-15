# Asymptote reader for a Beacon S3 bucket

Gives Asymptote read-only access to a Beacon bucket created by the [`aws-s3`](../aws-s3)
module, for customers who keep Beacon telemetry in their own bucket and use Asymptote's
dashboard:

- `asymptote-s3-reader`, an IAM user that can list the bucket, read objects below the
  Beacon prefix, and consume the two queues below;
- an SQS queue per stream (`runtime`, `inventory`), each with a dead-letter queue, that S3
  notifies of every new object, so Asymptote loads objects in any order;
- the bucket's notification configuration, which this module owns.

```hcl
module "beacon_s3" {
  source = "github.com/asymptote-labs/agent-beacon//terraform/aws-s3?ref=<release tag>"

  bucket_name = "acme-beacon-telemetry"
  prefix      = "beacon-prod"
}

module "asymptote_reader" {
  source = "github.com/asymptote-labs/agent-beacon//terraform/aws-s3-asymptote-reader?ref=<release tag>"

  bucket = module.beacon_s3.bucket
}
```

Use a provider in the bucket's region: S3 can only notify queues in its own region. Create
the reader's access key with the AWS CLI, so its secret never enters Terraform state, and
send Asymptote the key with the `source_url` and `queue_urls` outputs.

The full walkthrough is on the Asymptote docs:
[Asymptote with your own S3 bucket](https://docs.asymptotelabs.ai/deployment/self-hosted-s3).
