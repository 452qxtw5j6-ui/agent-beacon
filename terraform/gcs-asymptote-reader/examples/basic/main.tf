# A Beacon bucket that Asymptote can read: the gcs module creates the bucket and the writer, and
# this module adds Asymptote's read access and the new-object subscriptions.
#
#   terraform init
#   terraform apply -var project=<project-id> -var location=us-west1 -var bucket_name=<globally-unique-name>
#   gcloud iam service-accounts keys create beacon-gcs-writer.json --iam-account "$(terraform output -raw writer_email)"
#
# Outside this repository, point both sources at a release:
#   source = "github.com/asymptote-labs/agent-beacon//terraform/gcs?ref=<release tag>"
#   source = "github.com/asymptote-labs/agent-beacon//terraform/gcs-asymptote-reader?ref=<release tag>"

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
  }
}

variable "project" {
  description = "Google Cloud project for the bucket, service account and subscriptions."
  type        = string
}

variable "location" {
  description = "Bucket location, such as us-west1."
  type        = string
}

variable "bucket_name" {
  description = "Globally unique name for the new bucket."
  type        = string
}

variable "prefix" {
  description = "Root prefix for Beacon objects."
  type        = string
  default     = "beacon-prod"
}

provider "google" {
  project = var.project
}

module "beacon_gcs" {
  source = "../../../gcs"

  project     = var.project
  location    = var.location
  bucket_name = var.bucket_name
  prefix      = var.prefix
}

module "asymptote_reader" {
  source = "../.."

  bucket = module.beacon_gcs.bucket
}

output "bucket_name" {
  value = module.beacon_gcs.bucket_name
}

output "prefix" {
  value = module.beacon_gcs.prefix
}

output "writer_email" {
  value = module.beacon_gcs.writer_email
}

output "asymptote_subscriptions" {
  value = module.asymptote_reader.subscriptions
}
