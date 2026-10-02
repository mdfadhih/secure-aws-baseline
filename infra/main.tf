# Secure AWS baseline: audit logging, threat detection, external-access analysis and one
# least-privilege role. Deployed by the GitHub Actions pipeline, never from a laptop.

locals {
  account_id = data.aws_caller_identity.current.account_id
  trail_name = "${var.name_prefix}-trail"
  # Built from names (not read from the resource) so the key and bucket policies can reference
  # the trail without creating a dependency cycle.
  trail_arn  = "arn:aws:cloudtrail:${var.region}:${local.account_id}:trail/${local.trail_name}"
  log_bucket = "${var.name_prefix}-cloudtrail-logs-${local.account_id}"
}

# ---------------------------------------------------------------------------
# KMS key that encrypts CloudTrail logs
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "logs_key" {
  #checkov:skip=CKV_AWS_109:A KMS key policy must let the account root delegate to IAM, otherwise the key can become unmanageable. "*" in a key policy means "this key", not all resources.
  #checkov:skip=CKV_AWS_111:Same reason as CKV_AWS_109: standard key-policy pattern. CloudTrail's own grant is constrained by aws:SourceArn and the encryption context.
  #checkov:skip=CKV_AWS_356:Same reason as CKV_AWS_109: Resource "*" in a key policy refers to the key itself.
  statement {
    sid       = "EnableAccountAdministration"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
  }

  statement {
    sid       = "AllowCloudTrailToEncryptLogs"
    actions   = ["kms:GenerateDataKey*"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }

    condition {
      test     = "StringLike"
      variable = "kms:EncryptionContext:aws:cloudtrail:arn"
      values   = ["arn:aws:cloudtrail:*:${local.account_id}:trail/*"]
    }
  }

  statement {
    sid       = "AllowCloudTrailToDescribeKey"
    actions   = ["kms:DescribeKey"]
    resources = ["*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}

resource "aws_kms_key" "logs" {
  description             = "Encrypts CloudTrail logs for the ${var.name_prefix} baseline"
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.logs_key.json
}

resource "aws_kms_alias" "logs" {
  name          = "alias/${var.name_prefix}-cloudtrail-logs"
  target_key_id = aws_kms_key.logs.key_id
}

# ---------------------------------------------------------------------------
# Log bucket: private, versioned, KMS-encrypted, TLS-only, expires old logs
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "logs" {
  #checkov:skip=CKV_AWS_18:Access logging would need a second bucket that itself needs logging. Stretch goal: send access logs to a separate account.
  #checkov:skip=CKV_AWS_144:Cross-region replication is out of scope and adds cost for a single-account lab.
  #checkov:skip=CKV2_AWS_62:Event notifications are not needed for an audit-log bucket in this lab.
  bucket        = local.log_bucket
  force_destroy = var.force_destroy_log_bucket
}

resource "aws_s3_bucket_ownership_controls" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    bucket_key_enabled = true

    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.logs.arn
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "expire-old-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = var.log_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 90
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.logs]
}

data "aws_iam_policy_document" "logs_bucket" {
  statement {
    sid       = "AllowCloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.logs.arn]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "AllowCloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.logs.arn}/AWSLogs/${local.account_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.logs.arn, "${aws_s3_bucket.logs.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id
  policy = data.aws_iam_policy_document.logs_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.logs]
}

# ---------------------------------------------------------------------------
# CloudTrail: all regions, global services, tamper-evident (log file validation)
# ---------------------------------------------------------------------------

resource "aws_cloudtrail" "main" {
  #checkov:skip=CKV2_AWS_10:CloudWatch Logs integration (for metric filters and alarms) is the planned stretch goal; it needs an extra role and log group.
  #checkov:skip=CKV_AWS_252:SNS notification on log delivery is optional; alerting is the planned stretch goal.
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.logs.id
  kms_key_id                    = aws_kms_key.logs.arn
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true

  depends_on = [aws_s3_bucket_policy.logs]
}

# ---------------------------------------------------------------------------
# Detection: GuardDuty threat detection and IAM Access Analyzer
# ---------------------------------------------------------------------------

resource "aws_guardduty_detector" "main" {
  #checkov:skip=CKV2_AWS_3:Organization-wide and multi-region enablement need AWS Organizations; this lab covers one account and one region.
  count = var.enable_guardduty ? 1 : 0

  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

resource "aws_accessanalyzer_analyzer" "account" {
  count = var.enable_access_analyzer ? 1 : 0

  analyzer_name = "${var.name_prefix}-account-analyzer"
  type          = "ACCOUNT"
}

resource "aws_s3_account_public_access_block" "account" {
  count = var.enable_account_s3_public_block ? 1 : 0

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ---------------------------------------------------------------------------
# One least-privilege role: read CloudTrail logs and nothing else, MFA required
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "log_reader_trust" {
  statement {
    sid     = "AllowAccountPrincipalsWithMfa"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }

    condition {
      test     = "Bool"
      variable = "aws:MultiFactorAuthPresent"
      values   = ["true"]
    }
  }
}

data "aws_iam_policy_document" "log_reader" {
  statement {
    sid       = "ListLogBucket"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.logs.arn]
  }

  statement {
    sid       = "ReadCloudTrailLogs"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.logs.arn}/AWSLogs/${local.account_id}/*"]
  }

  statement {
    sid       = "DecryptLogsOnly"
    actions   = ["kms:Decrypt"]
    resources = [aws_kms_key.logs.arn]
  }
}

resource "aws_iam_role" "log_reader" {
  name                 = "${var.name_prefix}-log-reader"
  description          = "Read-only access to CloudTrail logs. Requires MFA."
  assume_role_policy   = data.aws_iam_policy_document.log_reader_trust.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy" "log_reader" {
  name   = "read-cloudtrail-logs"
  role   = aws_iam_role.log_reader.id
  policy = data.aws_iam_policy_document.log_reader.json
}
