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
  sid = "ELBWriteAccess"

  effect = "Allow"

  principals {
    type        = "AWS"
    identifiers = ["arn:aws:iam::127311923021:root"]
  }

  actions = [
    "s3:PutObject",
  ]

  resources = [
    "arn:aws:s3:::${var.bucket_name}/*",
  ]
}
}

