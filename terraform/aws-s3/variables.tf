variable "bucket_name" {
  description = "Name of the S3 bucket Beacon writes to. With create_bucket = true it must be globally unique."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.bucket_name))
    error_message = "bucket_name must be a valid S3 bucket name: 3 to 63 lowercase letters, digits, dots and hyphens."
  }
}

variable "create_bucket" {
  description = "Create and harden the bucket. Set to false to use a bucket you already manage: the module then only creates the IAM users and changes nothing on the bucket."
  type        = bool
  default     = true
}

variable "existing_bucket_region" {
  description = "Region of an existing bucket (create_bucket = false) when it is not the provider's region. Terraform cannot find a bucket in another region without it. A bucket the module creates is always in the provider's region, so leave this null then."
  type        = string
  default     = null

  validation {
    condition     = var.existing_bucket_region == null || can(regex("^[a-z]{2}(-[a-z]+)+-[0-9]+$", var.existing_bucket_region))
    error_message = "existing_bucket_region must be an AWS region name such as us-west-2."
  }
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
  description = "S3 storage class the forwarder writes objects with (BEACON_S3_STORAGE_CLASS). It is passed to the forwarder through the forwarder_settings output; the bucket itself has no storage class."
  type        = string
  default     = "STANDARD"

  validation {
    condition = contains([
      "STANDARD",
      "INTELLIGENT_TIERING",
      "STANDARD_IA",
      "ONEZONE_IA",
      "GLACIER_IR",
      "GLACIER",
      "DEEP_ARCHIVE",
    ], var.storage_class)
    error_message = "storage_class must be one of STANDARD, INTELLIGENT_TIERING, STANDARD_IA, ONEZONE_IA, GLACIER_IR, GLACIER or DEEP_ARCHIVE."
  }
}

variable "kms_key_arn" {
  description = "ARN of a customer managed KMS key. With create_bucket = true it becomes the bucket's default encryption (SSE-KMS with an S3 Bucket Key); with an existing bucket, set it to the key that bucket already uses. Either way the writer gets kms:GenerateDataKey and the Beacon reader gets kms:Decrypt on it. Leave null for SSE-S3."
  type        = string
  default     = null

  validation {
    condition     = var.kms_key_arn == null || can(regex("^arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/.+$", var.kms_key_arn))
    error_message = "kms_key_arn must be a KMS key ARN (arn:aws:kms:<region>:<account>:key/<id>), not an alias."
  }
}

variable "versioning_enabled" {
  description = "Turn on bucket versioning, so objects deleted or overwritten by an administrator can be recovered. Applies only when the module creates the bucket."
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

variable "writer_user_name" {
  description = "Name of the IAM user every Mac's forwarder authenticates as."
  type        = string
  default     = "beacon-endpoint-writer"
}

variable "allow_writer_healthcheck" {
  description = "Grant the writer s3:ListBucket on the bucket. The forwarder's startup health check calls HeadBucket, which needs it; without it uploads still work, but the forwarder logs a health-check error each time it starts. s3:ListBucket also lets the writer list object names in the bucket, though never read them."
  type        = bool
  default     = true
}

variable "create_beacon_reader" {
  description = "Create a read-only IAM user for Beacon Cloud's S3 data connector, which reads your bucket with an access key. It can read only the Beacon prefix."
  type        = bool
  default     = false
}

variable "beacon_reader_user_name" {
  description = "Name of the read-only IAM user created when create_beacon_reader = true."
  type        = string
  default     = "beacon-s3-reader"
}

variable "create_access_keys" {
  description = "Also create an access key for the writer (and for the Beacon reader, when created). The secret keys are then stored in Terraform state, so leave this false unless your state is encrypted and access-controlled, and create the keys with the AWS CLI instead."
  type        = bool
  default     = false
}

variable "iam_path" {
  description = "Path for the IAM users."
  type        = string
  default     = "/"

  validation {
    condition     = can(regex("^/([A-Za-z0-9+=,.@_-]+/)*$", var.iam_path))
    error_message = "iam_path must begin and end with a slash, such as / or /beacon/."
  }
}

variable "permissions_boundary_arn" {
  description = "ARN of a permissions boundary policy to attach to the IAM users, if your organization requires one."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags to apply to every resource the module creates."
  type        = map(string)
  default     = {}
}
