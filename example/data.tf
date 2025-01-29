data "aws_iam_policy_document" "alb_logs_policy" {
  statement {
    sid    = "ELBWriteAccess"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::127311923021:root"]  # NOTE: This is the ELB account ID for US East (N. Virginia), not your AWS account ID.
    }

    actions = [
      "s3:PutObject",
    ]

    resources = [
      "arn:aws:s3:::${var.bucket_name}/*",
    ]
  }
}


