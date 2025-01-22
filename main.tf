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
#                 Target Group
###################################################################
resource "aws_lb_target_group" "this" {
  name                       = var.target_group_config.name
  name_prefix               = var.target_group_config.name_prefix
  port                       = var.target_group_config.port
  protocol                   = var.target_group_config.protocol
  vpc_id                     = var.target_group_config.vpc_id
  ip_address_type        = var.target_group_config.ip_address_type
  load_balancing_anomaly_mitigation = var.target_group_config.load_balancing_anomaly_mitigation
  load_balancing_cross_zone_enabled = var.target_group_config.load_balancing_cross_zone_enabled
  preserve_client_ip       = var.target_group_config.preserve_client_ip
  protocol_version         = var.target_group_config.protocol_version
  load_balancing_algorithm_type = var.target_group_config.load_balancing_algorithm
  target_type                = var.target_group_config.target_type
  proxy_protocol_v2        = var.target_group_config.proxy_protocol_v2
  slow_start               = var.target_group_config.slow_start
  tags                       = var.target_group_config.tags

  # Health Check
  dynamic "health_check" {
    for_each = var.target_group_config.health_check != null ? [var.target_group_config.health_check] : []
    content {
      enabled             = health_check.value.enabled
      interval            = health_check.value.interval
      path                = health_check.value.path
      port                = health_check.value.port
      protocol            = health_check.value.protocol
      timeout             = health_check.value.timeout
      unhealthy_threshold = health_check.value.unhealthy_threshold
      healthy_threshold   = health_check.value.healthy_threshold
      matcher             = health_check.value.matcher
    }
  }

  # Stickiness
  dynamic "stickiness" {
    for_each = var.target_group_config.stickiness != null ? [var.target_group_config.stickiness] : []
    content {
      type            = stickiness.value.type
      cookie_duration = stickiness.value.cookie_duration
      cookie_name    = stickiness.value.cookie_name
      enabled         = stickiness.value.enabled
    }
  }

  # DNS Failover
  dynamic "dns_failover" {
    for_each = var.target_group_config.dns_failover != null ? [var.target_group_config.dns_failover] : []
    content {
      enabled         = dns_failover.value.enabled
      minimum_healthy_targets_count     = dns_failover.value.minimum_healthy_targets_count
      minimum_healthy_targets_percentage = dns_failover.value.minimum_healthy_targets_percentage
    }
  }

  # Target Group Health
  dynamic "target_group_health" {
    for_each = var.target_group_config.target_group_health != null ? [var.target_group_config.target_group_health] : []
    content {
      enabled = target_group_health.value.enabled
      dns_failover = target_group_health.value.dns_failover
      unhealthy_state_routing   = target_group_health.value.unhealthy_state_routing
    }
  }

  # Target Failover
  dynamic "target_failover" {
    for_each = var.target_group_config.target_failover != null ? [var.target_group_config.target_failover] : []
    content {
      on_deregistration   = target_failover.value.on_deregistration
      on_unhealthy = target_failover.value.on_unhealthy
    }
  }

  # Unhealthy State Routing
  dynamic "unhealthy_state_routing" {
    for_each = var.target_group_config.unhealthy_state_routing != null ? [var.target_group_config.unhealthy_state_routing] : []
    content {
      enabled    = unhealthy_state_routing.value.enabled
      minimum_healthy_targets_count    = unhealthy_state_routing.value.minimum_healthy_targets_count
      minimum_healthy_targets_percentage = unhealthy_state_routing.value.minimum_healthy_targets_percentage
    }
  }

  # Target Health State
  dynamic "target_health_state" {
    for_each = var.target_group_config.target_health_state != null ? [var.target_group_config.target_health_state] : []
    content {
      enabled = target_health_state.value.enabled
      enable_unhealthy_connection_termination  = target_health_state.value.enable_unhealthy_connection_termination
      unhealthy_draining_interval = target_health_state.value.unhealthy_draining_interval
    }
  }
}


###################################################################
#                 Listener
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
        authentication_request_extra_params = authenticate_oidc.value.authentication_request_extra_params
        client_id              = authenticate_oidc.value.client_id
        client_secret          = authenticate_oidc.value.client_secret
        issuer                 = authenticate_oidc.value.issuer
        token_endpoint         = authenticate_oidc.value.token_endpoint
        user_info_endpoint     = authenticate_oidc.value.user_info_endpoint
        on_unauthenticated_request       = authenticate_oidc.value.on_unauthenticated_request
        scope                            = authenticate_oidc.value.scope
        session_cookie_name              = authenticate_oidc.value.session_cookie_name
        session_timeout                  = authenticate_oidc.value.session_timeout
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
  # dynamic "mutual_authentication" {
  #   for_each = lookup(default_action.value, "mutual_authentication", null) != null ? [default_action.value.mutual_authentication] : []
  #   content {
  #     advertise_trust_store_ca_names = mutual_authentication.value.advertise_trust_store_ca_names
  #     ignore_client_certificate_expiry = mutual_authentication.value.ignore_client_certificate_expiry
  #     mode                           = mutual_authentication.value.mode
  #     trust_store_arn                = mutual_authentication.value.trust_store_arn
  #   }
  # }
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
#                  Listener  Certificate
###################################################################
resource "aws_lb_listener_certificate" "this" {
  for_each = try({ for k, v in var.listener_certificates : k => v if v.certificate_arn != null }, {})

  listener_arn    = aws_lb_listener.this.arn
  certificate_arn = each.value.certificate_arn
}


###################################################################
#                 Listener Rules
###################################################################
resource "aws_lb_listener_rule" "this" {
  for_each = var.listener_rules

  listener_arn = aws_lb_listener.this.arn
  priority     = each.value.priority

  dynamic "action" {
    for_each = each.value.actions
    content {
      type  = action.value.type
      order = action.value.order

      dynamic "redirect" {
        for_each = action.value.redirect != null ? [action.value.redirect] : []
        content {
          host        = redirect.value.host
          path        = redirect.value.path
          query       = redirect.value.query
          protocol    = redirect.value.protocol
          port        = redirect.value.port
          status_code = redirect.value.status_code
        }
      }

      dynamic "fixed_response" {
        for_each = action.value.fixed_response != null ? [action.value.fixed_response] : []
        content {
          status_code  = fixed_response.value.status_code
          content_type = fixed_response.value.content_type
          message_body = fixed_response.value.message_body
        }
      }

      dynamic "authenticate_cognito" {
        for_each = action.value.authenticate_cognito != null ? [action.value.authenticate_cognito] : []
        content {
          user_pool_arn                   = authenticate_cognito.value.user_pool_arn
          user_pool_client_id             = authenticate_cognito.value.user_pool_client_id
          user_pool_domain                = authenticate_cognito.value.user_pool_domain
          on_unauthenticated_request      = authenticate_cognito.value.on_unauthenticated_request
          authentication_request_extra_params = authenticate_cognito.value.authentication_request_extra_params
          session_cookie_name              = authenticate_cognito.value.session_cookie_name
          session_timeout                  = authenticate_cognito.value.session_timeout
          on_unauthenticated_request       = authenticate_cognito.value.on_unauthenticated_request
        }
      }

      dynamic "authenticate_oidc" {
      for_each = lookup(action.value, "authenticate_oidc", null) != null ? [action.value.authenticate_oidc] : []
      content {
        authorization_endpoint = authenticate_oidc.value.authorization_endpoint
        authentication_request_extra_params = authenticate_oidc.value.authentication_request_extra_params
        client_id              = authenticate_oidc.value.client_id
        client_secret          = authenticate_oidc.value.client_secret
        issuer                 = authenticate_oidc.value.issuer
        token_endpoint         = authenticate_oidc.value.token_endpoint
        user_info_endpoint     = authenticate_oidc.value.user_info_endpoint
        on_unauthenticated_request       = authenticate_oidc.value.on_unauthenticated_request
        scope                            = authenticate_oidc.value.scope
        session_cookie_name              = authenticate_oidc.value.session_cookie_name
        session_timeout                  = authenticate_oidc.value.session_timeout
      }
    }
    }
  }

  dynamic "condition" {
    for_each = each.value.conditions
    content {
      dynamic "host_header" {
        for_each = condition.value.host_header != null ? [condition.value.host_header] : []
        content {
          values = host_header.value.values
        }
      }

      dynamic "path_pattern" {
        for_each = condition.value.path_pattern != null ? [condition.value.path_pattern] : []
        content {
          values = path_pattern.value.values
        }
      }
    }
  }

  # certificate {
  #   for_each = length(var.listener_certificates) > 0 ? var.listener_certificates : []
  #   certificate_arn = each.value.certificate_arn
  # }
}
