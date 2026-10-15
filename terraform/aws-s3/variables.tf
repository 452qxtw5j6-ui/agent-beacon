variable "bucket_name" {
  description = "Name of the dedicated S3 bucket the module creates for Beacon telemetry. Bucket names are global across AWS, so it must be unused."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.bucket_name))
    error_message = "bucket_name must be a valid S3 bucket name: 3 to 63 lowercase letters, digits, dots and hyphens."
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
  description = "ARN of a customer managed KMS key to make the bucket's default encryption (SSE-KMS with an S3 Bucket Key). The writer gets kms:GenerateDataKey on it. Leave null for SSE-S3."
  type        = string
  default     = null

  validation {
    condition     = var.kms_key_arn == null || can(regex("^arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/.+$", var.kms_key_arn))
    error_message = "kms_key_arn must be a KMS key ARN (arn:aws:kms:<region>:<account>:key/<id>), not an alias."
  }
}

variable "versioning_enabled" {
  description = "Turn on bucket versioning, so objects deleted or overwritten by an administrator can be recovered."
  type        = bool
  default     = true
}

variable "expiration_days" {
  description = "Delete Beacon objects this many days after upload. Leave null to keep them until you delete them."
  type        = number
  default     = null

  validation {
    condition     = var.expiration_days == null || try(var.expiration_days >= 1 && floor(var.expiration_days) == var.expiration_days, false)
    error_message = "expiration_days must be a whole number of days, at least 1."
  }
}

variable "noncurrent_version_expiration_days" {
  description = "With versioning on, delete replaced or deleted object versions this many days after they stop being current."
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

variable "create_writer_access_key" {
  description = "Also create the writer's access key. The secret key is then stored in Terraform state, so leave this false unless your state is encrypted and access-controlled, and create the key with the AWS CLI instead."
  type        = bool
  default     = false
}

variable "iam_path" {
  description = "Path for the writer IAM user."
  type        = string
  default     = "/"

  validation {
    condition     = can(regex("^/([A-Za-z0-9+=,.@_-]+/)*$", var.iam_path))
    error_message = "iam_path must begin and end with a slash, such as / or /beacon/."
  }
}

variable "permissions_boundary_arn" {
  description = "ARN of a permissions boundary policy to attach to the writer IAM user, if your organization requires one."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags to apply to every resource the module creates."
  type        = map(string)
  default     = {}
}
