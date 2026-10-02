output "state_bucket" {
  description = "Name of the remote state bucket. Save as the GitHub variable TF_STATE_BUCKET."
  value       = aws_s3_bucket.state.id
}

output "plan_role_arn" {
  description = "Save as the GitHub variable AWS_PLAN_ROLE_ARN."
  value       = aws_iam_role.plan.arn
}

output "apply_role_arn" {
  description = "Save as the GitHub variable AWS_APPLY_ROLE_ARN."
  value       = aws_iam_role.apply.arn
}

output "region" {
  description = "Save as the GitHub variable AWS_REGION."
  value       = var.region
}

output "next_steps" {
  description = "What to do with these outputs."
  value       = <<-EOT
    In GitHub: Settings > Secrets and variables > Actions > Variables, add:
      TF_STATE_BUCKET      = ${aws_s3_bucket.state.id}
      AWS_PLAN_ROLE_ARN    = ${aws_iam_role.plan.arn}
      AWS_APPLY_ROLE_ARN   = ${aws_iam_role.apply.arn}
      AWS_REGION           = ${var.region}
    Then create the Environment "${var.github_environment}" with required reviewers (yourself).
  EOT
}
