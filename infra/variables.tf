variable "region" {
  description = "Home region for the trail, key and GuardDuty detector. Must match the region used in bootstrap."
  type        = string
  default     = "ap-southeast-2"
}

variable "name_prefix" {
  description = "Prefix for resource names. Must match baseline_name_prefix in bootstrap, because the apply role can only manage IAM roles with this prefix."
  type        = string
  default     = "baseline"
}

variable "log_retention_days" {
  description = "Days to keep CloudTrail log objects before they expire."
  type        = number
  default     = 365
}

variable "force_destroy_log_bucket" {
  description = "Allow terraform destroy to empty and delete the log bucket. Fine for a lab; set false in a real environment so logs cannot be wiped by a destroy."
  type        = bool
  default     = true
}

variable "enable_account_s3_public_block" {
  description = "Turn on S3 Block Public Access for the WHOLE account. Recommended in a dedicated lab account; leave false if other projects in this account rely on public buckets."
  type        = bool
  default     = false
}

variable "enable_guardduty" {
  description = "Create a GuardDuty detector. Set false if GuardDuty is already enabled in this region (only one detector per region is allowed)."
  type        = bool
  default     = true
}

variable "enable_access_analyzer" {
  description = "Create an account-level IAM Access Analyzer. Set false if one already exists in this region."
  type        = bool
  default     = true
}
