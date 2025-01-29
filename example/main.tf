################################################################################
## defaults
################################################################################
terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}


provider "aws" {
  region = var.region
}

module "tags" {
  source  = "sourcefuse/arc-tags/aws"
  version = "1.2.6"

  environment = terraform.workspace
  project     = "terraform-aws-arc-alb"

  extra_tags = {
    Example = "True"
  }
}

module "alb" {
  source               = "../"
  region               = var.region
  load_balancer_config            = local.load_balancer_config
  target_group_config            = var.target_group_config
  target_group_attachment_config = var.target_group_attachment_config
  alb_listener            = var.alb_listener
  default_action          = var.default_action
  listener_rules          = var.listener_rules
  security_group_data     = var.security_group_data
  security_group_name     = var.security_group_name
  vpc_id                  = var.vpc_id
  tags                   = module.tags.tags
}

module "s3" {
  source      = "sourcefuse/arc-s3/aws"
  version     = "0.0.4"
  name             = var.bucket_name
  acl              = "log-delivery-write"
  force_destroy   = true
  object_ownership = "ObjectWriter"
  bucket_policy_doc = data.aws_iam_policy_document.alb_logs_policy.json
  tags             = module.tags.tags
}

data "aws_caller_identity" "current" {}