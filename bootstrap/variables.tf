variable "region" {
  description = "AWS region for the lab. Sydney by default; Melbourne (ap-southeast-4) must be enabled in your account first."
  type        = string
  default     = "ap-southeast-2"
}

variable "github_repo" {
  description = "GitHub repository allowed to assume the pipeline roles, as owner/name (case-sensitive), e.g. mdfadhih/secure-aws-baseline."
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$", var.github_repo))
    error_message = "github_repo must look like owner/name."
  }
}

variable "github_owner_id" {
  description = "Numeric ID of the GitHub owner. Needed when your repository's OIDC subject uses the OWNER@ID/NAME@ID form. See the README for how to read it from a workflow run."
  type        = string
  default     = ""

  validation {
    condition     = can(regex("^[0-9]*$", var.github_owner_id))
    error_message = "github_owner_id must be digits only."
  }
}

variable "github_repo_id" {
  description = "Numeric ID of the GitHub repository (pair with github_owner_id)."
  type        = string
  default     = ""

  validation {
    condition     = can(regex("^[0-9]*$", var.github_repo_id))
    error_message = "github_repo_id must be digits only."
  }
}

variable "github_environment" {
  description = "GitHub Environment that must approve applies. The apply role can only be assumed by jobs running in this environment."
  type        = string
  default     = "production"
}

variable "baseline_name_prefix" {
  description = "Prefix for resources created by the pipeline. The apply role may only manage IAM roles with this prefix, so it cannot edit itself."
  type        = string
  default     = "baseline"
}

variable "state_key" {
  description = "Object key of the infra Terraform state inside the state bucket."
  type        = string
  default     = "secure-aws-baseline/infra.tfstate"
}

variable "create_oidc_provider" {
  description = "Create the GitHub OIDC provider. Set to false if your account already has one (an account can hold only one per URL)."
  type        = bool
  default     = true
}

variable "force_destroy_state_bucket" {
  description = "Allow terraform destroy to delete the state bucket even when it holds objects. Fine for a lab; set false for anything real."
  type        = bool
  default     = true
}
