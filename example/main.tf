################################################################################
## defaults
################################################################################
terraform {
  required_version = "~> 1.3, < 2.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = var.region
}

module "alb" {
  source               = "../.."
  alb_name             = var.alb_name
  internal             = var.internal
  load_balancer_type   = var.load_balancer_type
  security_groups      = var.security_groups
  subnets              = var.subnets
  enable_deletion_protection = var.enable_deletion_protection
  tags                 = var.tags
  listener_port        = var.listener_port
  listener_protocol    = var.listener_protocol
  target_group_name    = var.target_group_name
  target_group_port    = var.target_group_port
  target_group_protocol = var.target_group_protocol
  vpc_id               = var.vpc_id
  host_header_values   = var.host_header_values
  target_instance_id   = var.target_instance_id
  target_instance_port = var.target_instance_port


}