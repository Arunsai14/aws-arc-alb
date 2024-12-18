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


module "arc_security_group" {
  source  = "sourcefuse/arc-security-group/aws"
  version = "0.0.1"

  count = length(var.security_groups) == 0 ? 1 : 0
  name          = "${var.namespace}-${var.environment}-${var.name}-sg"
  vpc_id        = var.vpc_id
  ingress_rules = var.security_group_data.ingress_rules
  egress_rules  = var.security_group_data.egress_rules

  tags = var.tags
}

resource "aws_lb" "this" {
  name                     = var.name
  name_prefix              = var.name_prefix
  load_balancer_type       = var.load_balancer_type
  internal                 = var.internal
  security_groups          = var.security_groups != null ? var.security_groups : [module.arc_security_group.id]
  ip_address_type          = var.ip_address_type
  enable_deletion_protection = var.enable_deletion_protection
  enable_cross_zone_load_balancing = var.enable_cross_zone_load_balancing
  enable_http2             = var.enable_http2
  enable_waf_fail_open     = var.enable_waf_fail_open
  enable_xff_client_port   = var.enable_xff_client_port
  enable_zonal_shift       = var.enable_zonal_shift
  desync_mitigation_mode   = var.desync_mitigation_mode
  drop_invalid_header_fields = var.drop_invalid_header_fields
  enforce_security_group_inbound_rules_on_private_link_traffic = var.enforce_security_group_inbound_rules_on_private_link_traffic
  idle_timeout             = var.idle_timeout
  preserve_host_header     = var.preserve_host_header
  xff_header_processing_mode = var.xff_header_processing_mode
  customer_owned_ipv4_pool = var.customer_owned_ipv4_pool
  dns_record_client_routing_policy = var.dns_record_client_routing_policy
  client_keep_alive        = var.client_keep_alive
  enable_tls_version_and_cipher_suite_headers = var.enable_tls_version_and_cipher_suite_headers

  dynamic "subnet_mapping" {
    for_each = var.subnet_mapping
    content {
      subnet_id            = subnet_mapping.value.subnet_id
      allocation_id        = lookup(subnet_mapping.value, "allocation_id", null)
      ipv6_address         = lookup(subnet_mapping.value, "ipv6_address", null)
      private_ipv4_address = lookup(subnet_mapping.value, "private_ipv4_address", null)
    }
  }

  dynamic "access_logs" {
    for_each = var.access_logs.enabled ? [var.access_logs] : []
    content {
      bucket  = access_logs.value.bucket
      prefix  = access_logs.value.prefix
      enabled = access_logs.value.enabled
    }
  }

  dynamic "connection_logs" {
    for_each = var.connection_logs != null ? [var.connection_logs] : []
    content {
      bucket  = connection_logs.value.bucket
      prefix  = connection_logs.value.prefix
      enabled = connection_logs.value.enabled
    }
  }

  tags = module.tags.tags
}