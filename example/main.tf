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
  load_balancer_config            = var.load_balancer_config
  target_group_config            = var.target_group_config
  alb_listener            = var.alb_listener
  security_group_data  = var.security_group_data
  security_group_name  = var.security_group_name
  subnets              = var.subnets
  enable_deletion_protection = var.load_balancer_config.enable_deletion_protection
  tags                = module.tags.tags
}

