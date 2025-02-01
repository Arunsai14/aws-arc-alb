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

data "aws_vpc" "default" {
  filter {
    name   = "tag:Name"
    values = var.vpc_name != null ? [var.vpc_name] : ["${var.namespace}-${var.environment}-vpc"]
  }
}

# network
data "aws_subnets" "private" {
  filter {
    name = "tag:Name"

    ## try the created subnets from the upstream network module, or override with custom names
    values = length(var.subnet_names) > 0 ? var.subnet_names : [
      "${var.namespace}-${var.environment}-private-subnet-private-${var.region}a",
      "${var.namespace}-${var.environment}-private-subnet-private-${var.region}b"
    ]
  }

  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

