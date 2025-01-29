data "aws_iam_policy_document" "alb_logs_policy" {
#   version = "2012-10-17"

#   statement {
#     effect    = "Allow"
#     actions   = ["s3:PutObject", "s3:PutObjectAcl"]
#     resources = ["arn:aws:s3:::${var.bucket_name}/alb-logs/*"]

#     condition {
#       test     = "StringEquals"
#       variable = "aws:SourceAccount"
#       values   = [data.aws_caller_identity.current.account_id]
#     }

#     condition {
#       test     = "ArnLike"
#       variable = "aws:SourceArn"
#       values   = ["arn:aws:elasticloadbalancing:${var.region}:${data.aws_caller_identity.current.account_id}:loadbalancer/*"]
#     }

#     principal {
#       service = "delivery.logs.amazonaws.com"
#     }
#   }

#   statement {
#     effect    = "Allow"
#     actions   = ["s3:GetBucketAcl"]
#     resources = ["arn:aws:s3:::${var.bucket_name}"]

#     principal {
#       service = "delivery.logs.amazonaws.com"
#     }
#   }

statement {
    sid = "AWSLogDeliveryWrite"

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    effect = "Allow"

    actions = [
      "s3:PutObject",
    ]

    resources = [
      "arn:aws:s3:::${var.bucket_name}/*",
    ]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid = "AWSLogDeliveryAclCheck"

    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }

    actions = [
      "s3:GetBucketAcl",
      "s3:ListBucket",
    ]

    resources = [
      arn:aws:s3:::${var.bucket_name},
    ]

  }
}

