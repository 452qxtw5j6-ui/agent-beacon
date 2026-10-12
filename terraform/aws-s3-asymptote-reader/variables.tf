variable "bucket" {
  description = "The Beacon bucket to read, as the aws-s3 module's bucket output: bucket = module.beacon_s3.bucket."
  type = object({
    name        = string
    arn         = string
    region      = string
    prefix      = string
    kms_key_arn = optional(string)
  })
}

variable "user_name" {
  description = "Name of the read-only IAM user Asymptote reads the bucket with. Its queues are named after it: <name>-runtime and <name>-inventory, each with a -dlq."
  type        = string
  default     = "asymptote-s3-reader"
}

variable "create_access_key" {
  description = "Also create the reader's access key. The secret key is then stored in Terraform state, so leave this false unless your state is encrypted and access-controlled, and create the key with the AWS CLI instead."
  type        = bool
  default     = false
}

variable "iam_path" {
  description = "Path for the IAM user."
  type        = string
  default     = "/"

  validation {
    condition     = can(regex("^/([A-Za-z0-9+=,.@_-]+/)*$", var.iam_path))
    error_message = "iam_path must begin and end with a slash, such as / or /beacon/."
  }
}

variable "permissions_boundary_arn" {
  description = "ARN of a permissions boundary policy to attach to the IAM user, if your organization requires one."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags to apply to every resource the module creates."
  type        = map(string)
  default     = {}
}
