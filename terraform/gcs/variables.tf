variable "project" {
  description = "Google Cloud project that holds the bucket and the service accounts."
  type        = string
}

variable "bucket_name" {
  description = "Name of the Cloud Storage bucket Beacon writes to. With create_bucket = true it must be globally unique."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$", var.bucket_name))
    error_message = "bucket_name must be a valid bucket name: 3 to 63 lowercase letters, digits, dots, hyphens and underscores."
  }
}

variable "create_bucket" {
  description = "Create and harden the bucket. Set to false to use a bucket you already manage: the module then only creates the service account and its bucket IAM bindings."
  type        = bool
  default     = true
}

variable "location" {
  description = "Bucket location, such as us-west1 or US. Required when create_bucket = true."
  type        = string
  default     = null
}

variable "prefix" {
  description = "Root prefix for Beacon objects, such as beacon-prod. Beacon adds runtime/ and inventory/ below it."
  type        = string
  default     = "beacon"

  validation {
    condition = (
      can(regex("^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$", var.prefix))
      && !can(regex("(^|/)(runtime|inventory)$", var.prefix))
    )
    error_message = "prefix must be a root prefix such as beacon-prod: letters, digits, dots, hyphens, underscores and inner slashes, without a leading or trailing slash, and not ending in runtime or inventory, which Beacon adds itself."
  }
}

variable "storage_class" {
  description = "Storage class the forwarder writes objects with (BEACON_GCS_STORAGE_CLASS), and the default class of a bucket the module creates."
  type        = string
  default     = "STANDARD"

  validation {
    condition     = contains(["STANDARD", "NEARLINE", "COLDLINE", "ARCHIVE"], var.storage_class)
    error_message = "storage_class must be one of STANDARD, NEARLINE, COLDLINE or ARCHIVE."
  }
}

variable "kms_key_name" {
  description = "Cloud KMS key (projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>) to use as the default encryption of a bucket the module creates. Leave null for Google-managed encryption."
  type        = string
  default     = null

  validation {
    condition     = var.kms_key_name == null || can(regex("^projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+$", var.kms_key_name))
    error_message = "kms_key_name must be a full key name: projects/<project>/locations/<location>/keyRings/<ring>/cryptoKeys/<key>."
  }
}

variable "grant_kms_to_storage_agent" {
  description = "With kms_key_name set, grant the project's Cloud Storage service agent permission to use the key, which Cloud Storage needs to encrypt objects with it. Set to false if you manage the key's IAM elsewhere."
  type        = bool
  default     = true
}

variable "versioning_enabled" {
  description = "Turn on object versioning, so objects deleted or replaced by an administrator can be recovered. Applies only when the module creates the bucket."
  type        = bool
  default     = true
}

variable "expiration_days" {
  description = "Delete Beacon objects this many days after upload. Leave null to keep them until you delete them. Applies only when the module creates the bucket."
  type        = number
  default     = null

  validation {
    condition     = var.expiration_days == null || try(var.expiration_days >= 1 && floor(var.expiration_days) == var.expiration_days, false)
    error_message = "expiration_days must be a whole number of days, at least 1."
  }
}

variable "noncurrent_version_expiration_days" {
  description = "With versioning on, delete replaced or deleted object versions this many days after they stop being current. Applies only when the module creates the bucket."
  type        = number
  default     = 30

  validation {
    condition     = var.noncurrent_version_expiration_days >= 1 && floor(var.noncurrent_version_expiration_days) == var.noncurrent_version_expiration_days
    error_message = "noncurrent_version_expiration_days must be a whole number of days, at least 1."
  }
}

variable "force_destroy" {
  description = "Let terraform destroy delete the bucket even when it still holds objects. Leave false in production."
  type        = bool
  default     = false
}

variable "enable_apis" {
  description = "Enable the Cloud Storage and IAM APIs on the project. They are left enabled when the module is destroyed."
  type        = bool
  default     = true
}

variable "writer_account_id" {
  description = "Account ID of the service account every Mac's forwarder authenticates as."
  type        = string
  default     = "beacon-endpoint-writer"
}

variable "scope_writer_to_prefix" {
  description = "Limit the writer to creating objects below the Beacon prefix with an IAM condition. Conditions need uniform bucket-level access, which a bucket the module creates always has; set to false only for an existing bucket that still uses fine-grained ACLs."
  type        = bool
  default     = true
}

variable "create_writer_key" {
  description = "Also create a JSON key for the writer. The private key is then stored in Terraform state, so leave this false unless your state is encrypted and access-controlled, and create the key with gcloud instead."
  type        = bool
  default     = false
}

variable "create_reader" {
  description = "Create a read-only service account (roles/storage.objectViewer on the bucket) for checking uploads and for your own downstream consumers. The writer cannot list or read objects."
  type        = bool
  default     = false
}

variable "reader_account_id" {
  description = "Account ID of the read-only service account created when create_reader = true."
  type        = string
  default     = "beacon-endpoint-reader"
}

variable "grant_beacon_read_access" {
  description = "Grant Beacon Cloud read access to the bucket (roles/storage.objectViewer for beacon_reader_member), so Beacon can ingest the telemetry you store there. No key is involved."
  type        = bool
  default     = false
}

variable "beacon_reader_member" {
  description = "Beacon Cloud's reader identity. Change it only if Beacon gives you a different one."
  type        = string
  default     = "serviceAccount:beacon-clickpipes-reader@asymptote-labs.iam.gserviceaccount.com"
}

variable "labels" {
  description = "Labels to apply to a bucket the module creates."
  type        = map(string)
  default     = {}
}
