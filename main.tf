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
  security_groups          = [for sg in module.arc_security_group : sg.id]
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

###################################################################
## Target Group
###################################################################

resource "aws_lb_target_group" "this" {
  for_each = { for tg in var.alb_target_group : tg.name => tg }

  name                              = each.value.name
  port                              = each.value.port
  protocol                          = each.value.protocol
  protocol_version                  = each.value.protocol_version
  vpc_id                            = each.value.vpc_id
  target_type                       = each.value.target_type
  ip_address_type                   = each.value.ip_address_type
  load_balancing_algorithm_type     = each.value.load_balancing_algorithm_type
  load_balancing_cross_zone_enabled = each.value.load_balancing_cross_zone_enabled
  deregistration_delay              = each.value.deregistration_delay
  slow_start                        = each.value.slow_start

  health_check {
    enabled             = each.value.health_check.enabled
    protocol            = each.value.health_check.protocol
    path                = each.value.health_check.path
    port                = each.value.health_check.port
    timeout             = each.value.health_check.timeout
    healthy_threshold   = each.value.health_check.healthy_threshold
    unhealthy_threshold = each.value.health_check.unhealthy_threshold
    interval            = each.value.health_check.interval
    matcher             = each.value.health_check.matcher
  }

  dynamic "stickiness" {
    for_each = each.value.stickiness != null ? [each.value.stickiness] : []
    content {
      cookie_duration = stickiness.value.cookie_duration
      type            = stickiness.value.type
    }
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = each.value.tags
}

###################################################################
## Listener
###################################################################

resource "aws_lb_listener" "this" {
  load_balancer_arn = aws_lb.this.arn
  port              = var.port           
  protocol          = var.protocol       
  alpn_policy       = var.alpn_policy     

  # Optional: Default action with dynamic actions
  dynamic "default_action" {
  for_each = var.default_action
  content {
    type = default_action.value.type

    # OIDC Authentication action - Only if authenticate_oidc is provided
    dynamic "authenticate_oidc" {
      for_each = lookup(default_action.value, "authenticate_oidc", null) != null ? [default_action.value.authenticate_oidc] : []
      content {
        authorization_endpoint = authenticate_oidc.value.authorization_endpoint
        authentication_request_extra_params = authenticate_cognito.value.authentication_request_extra_params
        client_id              = authenticate_oidc.value.client_id
        client_secret          = authenticate_oidc.value.client_secret
        issuer                 = authenticate_oidc.value.issuer
        token_endpoint         = authenticate_oidc.value.token_endpoint
        user_info_endpoint     = authenticate_oidc.value.user_info_endpoint
        on_unauthenticated_request       = authenticate_cognito.value.on_unauthenticated_request
        scope                            = authenticate_cognito.value.scope
        session_cookie_name              = authenticate_cognito.value.session_cookie_name
        session_timeout                  = authenticate_cognito.value.session_timeout
      }
    }

    # Cognito Authentication action - Only if authenticate_cognito is provided
    dynamic "authenticate_cognito" {
      for_each = lookup(default_action.value, "authenticate_cognito", null) != null ? [default_action.value.authenticate_cognito] : []
      content {
        user_pool_arn                    = authenticate_cognito.value.user_pool_arn
        user_pool_client_id              = authenticate_cognito.value.user_pool_client_id
        user_pool_domain                 = authenticate_cognito.value.user_pool_domain
        authentication_request_extra_params = authenticate_cognito.value.authentication_request_extra_params
        on_unauthenticated_request       = authenticate_cognito.value.on_unauthenticated_request
        scope                            = authenticate_cognito.value.scope
        session_cookie_name              = authenticate_cognito.value.session_cookie_name
        session_timeout                  = authenticate_cognito.value.session_timeout
      }
    }

    # Fixed Response action - Only if fixed_response is provided
    dynamic "fixed_response" {
      for_each = lookup(default_action.value, "fixed_response", null) != null ? [default_action.value.fixed_response] : []
      content {
        status_code  = fixed_response.value.status_code
        content_type = fixed_response.value.content_type
        message_body = fixed_response.value.message_body
      }
    }

    # Forward action - Only if forward is provided
    dynamic "forward" {
      for_each = lookup(default_action.value, "forward", null) != null ? [default_action.value.forward] : []
      content {
        target_group {
          arn = aws_lb_target_group.this[var.alb_target_group[0].name].arn
        }

        stickiness {
          duration = forward.value.stickiness.duration
          enabled  = forward.value.stickiness.enabled
        }
      }
    }

    # Redirect action - Only if redirect is provided
    dynamic "redirect" {
      for_each = lookup(default_action.value, "redirect", null) != null ? [default_action.value.redirect] : []
      content {
        host        = redirect.value.host
        path        = redirect.value.path
        query       = redirect.value.query
        protocol    = redirect.value.protocol
        port        = redirect.value.port
        status_code = redirect.value.status_code
      }
    }

   # Dynamic mutual_authentication block
  dynamic "mutual_authentication" {
    for_each = lookup(default_action.value, "mutual_authentication", null) != null ? [default_action.value.mutual_authentication] : []
    content {
      advertise_trust_store_ca_names = mutual_authentication.value.advertise_trust_store_ca_names
      ignore_client_certificate_expiry = mutual_authentication.value.ignore_client_certificate_expiry
      mode                           = mutual_authentication.value.mode
      trust_store_arn                = mutual_authentication.value.trust_store_arn
    }
  }
  }
}

  # Optional: SSL certificate ARN
  certificate_arn = var.certificate_arn   # Only if using HTTPS

  # Optional: SSL policy for TLS listeners
  ssl_policy = var.ssl_policy             # Only if using HTTPS

  # Optional: TCP idle timeout for TCP protocols
  tcp_idle_timeout_seconds = var.tcp_idle_timeout_seconds # Only for TCP

  # Optional: Tags for the listener
  tags = module.tags.tags 
}



###################################################################
## Listener Rules
###################################################################
resource "aws_lb_listener_rule" "this" {
  for_each = var.create_listener_rule ? { for rule in var.listener_rules : rule.priority => rule } : {}

  listener_arn = aws_lb_listener.this.arn
  priority     = each.value.priority

  dynamic "condition" {
    for_each = each.value.conditions
    content {
      dynamic "host_header" {
        for_each = each.value.field == "host-header" ? [each.value] : []
        content {
          values = each.value.values
        }
      }

      dynamic "path_pattern" {
        for_each = each.value.field == "path-pattern" ? [each.value] : []
        content {
          values = each.value.values
        }
      }
    }
  }

  dynamic "action" {
    for_each = each.value.actions
    content {
      type             = action.value.type
      target_group_arn = lookup(action.value, "target_group_arn", aws_lb_target_group.this.arn)
      order            = lookup(action.value, "order", null)
      redirect {
        protocol    = lookup(action.value.redirect, "protocol", null)
        port        = lookup(action.value.redirect, "port", null)
        host        = lookup(action.value.redirect, "host", null)
        path        = lookup(action.value.redirect, "path", null)
        query       = lookup(action.value.redirect, "query", null)
        status_code = lookup(action.value.redirect, "status_code", null)
      }
      fixed_response {
        content_type = lookup(action.value.fixed_response, "content_type", null)
        message_body = lookup(action.value.fixed_response, "message_body", null)
        status_code  = lookup(action.value.fixed_response, "status_code", null)
      }
    }
  }

  depends_on = [aws_lb_listener.this]
}
