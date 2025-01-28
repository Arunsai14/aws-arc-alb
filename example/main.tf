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
  load_balancer_config            = var.load_balancer_config
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

