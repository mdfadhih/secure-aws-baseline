output "log_bucket" {
  description = "Bucket that holds the CloudTrail logs."
  value       = aws_s3_bucket.logs.id
}

output "trail_arn" {
  description = "ARN of the multi-region CloudTrail trail."
  value       = aws_cloudtrail.main.arn
}

output "kms_key_arn" {
  description = "KMS key that encrypts the logs."
  value       = aws_kms_key.logs.arn
}

output "log_reader_role_arn" {
  description = "Least-privilege role that can read the logs (MFA required)."
  value       = aws_iam_role.log_reader.arn
}

output "guardduty_detector_id" {
  description = "GuardDuty detector ID, if created."
  value       = one(aws_guardduty_detector.main[*].id)
}

output "access_analyzer_arn" {
  description = "IAM Access Analyzer ARN, if created."
  value       = one(aws_accessanalyzer_analyzer.account[*].arn)
}
