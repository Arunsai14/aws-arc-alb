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
  alb_name             = var.alb_name
  internal             = var.internal
  type                 = var.load_balancer_config.type
  security_group_data  = var.security_group_data
  security_group_name  = var.security_group_name
  subnets              = var.subnets
  enable_deletion_protection = var.load_balancer_config.enable_deletion_protection
  listener_port        = var.alb_listener.port
  listener_protocol    = var.alb_listener.protocol
  target_group_name    = var.target_group_config.name
  target_group_port    = var.target_group_config.port
  target_group_protocol = var.target_group_config.protocol
  vpc_id               = var.vpc_id
  host_header_values   = var.host_header_values
  target_instance_id   = var.target_instance_id
  target_instance_port = var.target_instance_port
  alb_listener      = var.alb_listener
  load_balancer_config = var.load_balancer_config
  listener_rules    = var.listener_rules
  tags                = module.tags.tags
}

