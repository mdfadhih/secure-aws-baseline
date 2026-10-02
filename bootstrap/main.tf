# Bootstrap: run ONCE from your laptop with admin credentials in a dedicated AWS account.
# It creates what the pipeline needs before it can run: a remote-state bucket, the GitHub OIDC
# identity provider, and two IAM roles (read-only plan, scoped apply). State for this folder
# stays local on purpose (chicken-and-egg: the state bucket does not exist yet).

locals {
  account_id      = data.aws_caller_identity.current.account_id
  state_bucket    = "tfstate-${local.account_id}-${var.region}"
  lock_key        = "${var.state_key}.tflock"
  baseline_bucket = "${var.baseline_name_prefix}-cloudtrail-logs-${local.account_id}"
  oidc_host       = "token.actions.githubusercontent.com"
  oidc_arn        = var.create_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : data.aws_iam_openid_connect_provider.existing[0].arn
}

# ---------------------------------------------------------------------------
# Remote state bucket: private, versioned, encrypted, TLS-only
# ---------------------------------------------------------------------------

resource "aws_s3_bucket" "state" {
  #checkov:skip=CKV_AWS_18:Access logging needs a second bucket; state access is already recorded by CloudTrail data events if enabled.
  #checkov:skip=CKV_AWS_144:Cross-region replication is out of scope and adds cost for a single-account lab.
  #checkov:skip=CKV_AWS_145:State bucket uses SSE-S3 (AES256) so the pipeline roles need no KMS permissions; a CMK is a documented upgrade.
  #checkov:skip=CKV2_AWS_62:Event notifications are not needed for a state bucket.
  bucket        = local.state_bucket
  force_destroy = var.force_destroy_state_bucket
}

resource "aws_s3_bucket_ownership_controls" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_public_access_block" "state" {
  bucket                  = aws_s3_bucket.state.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "state" {
  bucket = aws_s3_bucket.state.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "state" {
  bucket = aws_s3_bucket.state.id

  rule {
    id     = "expire-old-state-versions"
    status = "Enabled"

    filter {}

    noncurrent_version_expiration {
      noncurrent_days = 90
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.state]
}

data "aws_iam_policy_document" "state_bucket" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.state.arn, "${aws_s3_bucket.state.arn}/*"]

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

resource "aws_s3_bucket_policy" "state" {
  bucket = aws_s3_bucket.state.id
  policy = data.aws_iam_policy_document.state_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.state]
}

# ---------------------------------------------------------------------------
# GitHub OIDC: no long-lived AWS keys stored in GitHub
# ---------------------------------------------------------------------------

resource "aws_iam_openid_connect_provider" "github" {
  count = var.create_oidc_provider ? 1 : 0

  url            = "https://${local.oidc_host}"
  client_id_list = ["sts.amazonaws.com"]
}

data "aws_iam_openid_connect_provider" "existing" {
  count = var.create_oidc_provider ? 0 : 1

  url = "https://${local.oidc_host}"
}

# ---------------------------------------------------------------------------
# Plan role: read-only. Assumable from pull requests and from main.
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "plan_trust" {
  statement {
    sid     = "GitHubOidcPlan"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.oidc_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:sub"
      values = [
        "repo:${var.github_repo}:pull_request",
        "repo:${var.github_repo}:ref:refs/heads/main",
      ]
    }
  }
}

resource "aws_iam_role" "plan" {
  name                 = "gha-tf-plan"
  description          = "GitHub Actions: read-only role used to run terraform plan"
  assume_role_policy   = data.aws_iam_policy_document.plan_trust.json
  max_session_duration = 3600
}

# Broad but read-only. Known trade-off: it can read objects in any bucket in this lab account.
# A tighter option is SecurityAudit plus targeted reads; see README "Security decisions".
resource "aws_iam_role_policy_attachment" "plan_read_only" {
  role       = aws_iam_role.plan.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

data "aws_iam_policy_document" "plan_state" {
  statement {
    sid       = "ListStateBucket"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.state.arn]
  }

  statement {
    sid       = "ReadState"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.state.arn}/${var.state_key}"]
  }

  statement {
    sid       = "UseLockFile"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = ["${aws_s3_bucket.state.arn}/${local.lock_key}"]
  }
}

resource "aws_iam_role_policy" "plan_state" {
  name   = "state-read-and-lock"
  role   = aws_iam_role.plan.id
  policy = data.aws_iam_policy_document.plan_state.json
}

# ---------------------------------------------------------------------------
# Apply role: assumable ONLY by jobs running in the protected GitHub Environment.
# Permissions are limited to the services and resource names the baseline uses.
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "apply_trust" {
  statement {
    sid     = "GitHubOidcApply"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [local.oidc_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:sub"
      values   = ["repo:${var.github_repo}:environment:${var.github_environment}"]
    }
  }
}

resource "aws_iam_role" "apply" {
  name                 = "gha-tf-apply"
  description          = "GitHub Actions: scoped role used to apply the baseline after manual approval"
  assume_role_policy   = data.aws_iam_policy_document.apply_trust.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "apply" {
  #checkov:skip=CKV_AWS_109:Role and policy writes are limited to IAM roles named baseline-*; the pipeline's own roles (gha-tf-*) are outside that scope. Checkov cannot evaluate the name prefix. A permissions boundary is the documented next step.
  #checkov:skip=CKV_AWS_111:Write access is scoped by service and, where an ARN can be named, by resource. CloudTrail, GuardDuty, Access Analyzer and KMS creation have no resource ARN to name before the resource exists.
  #checkov:skip=CKV_AWS_356:Same reason as CKV_AWS_111: "*" is used only for create-type actions whose ARNs do not exist yet. Applies are gated by OIDC trust to one GitHub Environment with manual approval.
  statement {
    sid       = "ListStateBucket"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.state.arn]
  }

  statement {
    sid       = "ReadWriteState"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
    resources = ["${aws_s3_bucket.state.arn}/${var.state_key}", "${aws_s3_bucket.state.arn}/${local.lock_key}"]
  }

  statement {
    sid       = "ManageCloudTrailLogBucket"
    actions   = ["s3:*"]
    resources = ["arn:aws:s3:::${local.baseline_bucket}", "arn:aws:s3:::${local.baseline_bucket}/*"]
  }

  statement {
    sid       = "ManageAccountPublicAccessBlock"
    actions   = ["s3:GetAccountPublicAccessBlock", "s3:PutAccountPublicAccessBlock"]
    resources = ["*"]
  }

  # KMS keys do not exist yet, so their ARNs cannot be named here. Actions are an explicit list instead.
  statement {
    sid = "ManageKmsKeyForLogs"
    actions = [
      "kms:CreateKey",
      "kms:CreateAlias",
      "kms:UpdateAlias",
      "kms:DeleteAlias",
      "kms:ListAliases",
      "kms:DescribeKey",
      "kms:GetKeyPolicy",
      "kms:PutKeyPolicy",
      "kms:GetKeyRotationStatus",
      "kms:EnableKeyRotation",
      "kms:ListResourceTags",
      "kms:TagResource",
      "kms:UntagResource",
      "kms:ScheduleKeyDeletion",
    ]
    resources = ["*"]
  }

  statement {
    sid       = "ManageSecurityServices"
    actions   = ["cloudtrail:*", "guardduty:*", "access-analyzer:*"]
    resources = ["*"]
  }

  # Only roles with the baseline prefix. The pipeline roles are named gha-tf-*, so the apply role
  # cannot edit itself or the plan role (no privilege escalation path).
  statement {
    sid = "ManageBaselineRoles"
    actions = [
      "iam:CreateRole",
      "iam:DeleteRole",
      "iam:GetRole",
      "iam:UpdateRole",
      "iam:UpdateAssumeRolePolicy",
      "iam:PutRolePolicy",
      "iam:DeleteRolePolicy",
      "iam:GetRolePolicy",
      "iam:ListRolePolicies",
      "iam:ListAttachedRolePolicies",
      "iam:ListInstanceProfilesForRole",
      "iam:ListRoleTags",
      "iam:TagRole",
      "iam:UntagRole",
    ]
    resources = ["arn:aws:iam::${local.account_id}:role/${var.baseline_name_prefix}-*"]
  }

  statement {
    sid       = "CreateServiceLinkedRoles"
    actions   = ["iam:CreateServiceLinkedRole"]
    resources = ["*"]

    condition {
      test     = "StringEquals"
      variable = "iam:AWSServiceName"
      values   = ["guardduty.amazonaws.com", "access-analyzer.amazonaws.com"]
    }
  }

  statement {
    sid       = "GuardDutyServiceLinkedRolePolicy"
    actions   = ["iam:PutRolePolicy"]
    resources = ["arn:aws:iam::*:role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty"]
  }
}

resource "aws_iam_role_policy" "apply" {
  name   = "baseline-apply"
  role   = aws_iam_role.apply.id
  policy = data.aws_iam_policy_document.apply.json
}
