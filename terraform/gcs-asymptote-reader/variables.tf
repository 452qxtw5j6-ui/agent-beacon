variable "bucket" {
  description = "The Beacon bucket to read, as the gcs module's bucket output: bucket = module.beacon_gcs.bucket."
  type = object({
    name    = string
    project = string
    prefix  = string
  })
}

variable "reader_member" {
  description = "Asymptote's reader identity. Change it only if Asymptote gives you a different one."
  type        = string
  default     = "serviceAccount:beacon-clickpipes-reader@asymptote-labs.iam.gserviceaccount.com"
}

variable "enable_apis" {
  description = "Enable the Pub/Sub API on the project. It is left enabled when the module is destroyed."
  type        = bool
  default     = true
}

variable "labels" {
  description = "Labels to apply to the Pub/Sub topic and subscriptions."
  type        = map(string)
  default     = {}
}
