terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}


# provider "aws" {
#   region = var.region
# }

module "tags" {
  source  = "sourcefuse/arc-tags/aws"
  version = "1.2.6"

  environment = terraform.workspace
  project     = "terraform-aws-arc-alb"

  extra_tags = {
    Example = "True"
  }
}

###################################################################
#                 Security Group
###################################################################
module "arc_security_group" {
  source  = "sourcefuse/arc-security-group/aws"
  version = "0.0.1"

  count = length(var.security_groups) == 0 ? 1 : 0
  name          = var.security_group_name
  vpc_id        = var.vpc_id
  ingress_rules = var.security_group_data.ingress_rules
  egress_rules  = var.security_group_data.egress_rules

  tags = var.tags
}

###################################################################
#                 Load Balancer
###################################################################
resource "aws_lb" "this" {
  name                     = var.load_balancer_config.name
  name_prefix              = var.load_balancer_config.name_prefix
  load_balancer_type       = var.load_balancer_config.type
  internal                 = var.load_balancer_config.internal
  security_groups          = [for sg in module.arc_security_group : sg.id]
  ip_address_type          = var.load_balancer_config.ip_address_type
  enable_deletion_protection = var.load_balancer_config.enable_deletion_protection
  enable_cross_zone_load_balancing = var.load_balancer_config.enable_cross_zone_load_balancing
  enable_http2             = var.load_balancer_config.enable_http2
  enable_waf_fail_open     = var.load_balancer_config.enable_waf_fail_open
  enable_xff_client_port   = var.load_balancer_config.enable_xff_client_port
  enable_zonal_shift       = var.load_balancer_config.enable_zonal_shift
  desync_mitigation_mode   = var.load_balancer_config.desync_mitigation_mode
  drop_invalid_header_fields = var.load_balancer_config.drop_invalid_header_fields
  enforce_security_group_inbound_rules_on_private_link_traffic = var.load_balancer_config.enforce_security_group_inbound_rules_on_private_link_traffic
  idle_timeout             = var.load_balancer_config.idle_timeout
  preserve_host_header     = var.load_balancer_config.preserve_host_header
  xff_header_processing_mode = var.load_balancer_config.xff_header_processing_mode
  customer_owned_ipv4_pool = var.load_balancer_config.customer_owned_ipv4_pool
  dns_record_client_routing_policy = var.load_balancer_config.dns_record_client_routing_policy
  client_keep_alive        = var.load_balancer_config.client_keep_alive
  enable_tls_version_and_cipher_suite_headers = var.load_balancer_config.enable_tls_version_and_cipher_suite_headers

  dynamic "subnet_mapping" {
    for_each = var.load_balancer_config.subnet_mapping
    content {
      subnet_id            = subnet_mapping.value.subnet_id
      allocation_id        = lookup(subnet_mapping.value, "allocation_id", null)
      ipv6_address         = lookup(subnet_mapping.value, "ipv6_address", null)
      private_ipv4_address = lookup(subnet_mapping.value, "private_ipv4_address", null)
    }
  }

  dynamic "access_logs" {
    for_each = var.load_balancer_config.access_logs != null && var.load_balancer_config.access_logs.enabled ? [var.load_balancer_config.access_logs] : []
    content {
      bucket  = access_logs.value.bucket
      prefix  = access_logs.value.prefix
      enabled = access_logs.value.enabled
    }
  }

  dynamic "connection_logs" {
    for_each = var.load_balancer_config.connection_logs != null ? [var.load_balancer_config.connection_logs] : []
    content {
      bucket  = connection_logs.value.bucket
      prefix  = connection_logs.value.prefix
      enabled = connection_logs.value.enabled
    }
  }

  tags = var.tags
}



###################################################################
#                 Target Group
###################################################################
resource "aws_lb_target_group" "this" {
for_each = var.target_group_config != null ? { "config" = var.target_group_config } : {}
  name                        = var.target_group_config.name
  name_prefix                 = var.target_group_config.name_prefix
  port                        = var.target_group_config.port
  protocol                    = var.target_group_config.protocol
  vpc_id                      = var.vpc_id
  ip_address_type             = var.target_group_config.ip_address_type
  load_balancing_anomaly_mitigation = var.target_group_config.load_balancing_anomaly_mitigation
  load_balancing_cross_zone_enabled = var.target_group_config.load_balancing_cross_zone_enabled
  preserve_client_ip          = var.target_group_config.preserve_client_ip
  protocol_version            = var.target_group_config.protocol_version
  load_balancing_algorithm_type = var.target_group_config.load_balancing_algorithm_type
  target_type                 = var.target_group_config.target_type
  proxy_protocol_v2           = var.target_group_config.proxy_protocol_v2
  slow_start                  = var.target_group_config.slow_start
  tags = var.tags

  # Health Check
  dynamic "health_check" {
    for_each = each.value.health_check != null ? [each.value.health_check] : []
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
      cookie_name     = stickiness.value.cookie_name
      enabled         = stickiness.value.enabled
    }
  }

  # Target Group Health (DNS Failover & Unhealthy State Routing)
  dynamic "target_group_health" {
    for_each = var.target_group_config.target_group_health != null ? [var.target_group_config.target_group_health] : []
    content {
      # DNS Failover
      dynamic "dns_failover" {
        for_each = var.target_group_config.target_group_health.dns_failover != null ? [var.target_group_config.target_group_health.dns_failover] : []
        content {
          minimum_healthy_targets_count      = dns_failover.value.minimum_healthy_targets_count
          minimum_healthy_targets_percentage = dns_failover.value.minimum_healthy_targets_percentage
        }
      }

      # Unhealthy State Routing
      dynamic "unhealthy_state_routing" {
        for_each = var.target_group_config.target_group_health.unhealthy_state_routing != null ? [var.target_group_config.target_group_health.unhealthy_state_routing] : []
        content {
          minimum_healthy_targets_count      = unhealthy_state_routing.value.minimum_healthy_targets_count
          minimum_healthy_targets_percentage = unhealthy_state_routing.value.minimum_healthy_targets_percentage
        }
      }
    }
  }

  # Target Failover
  dynamic "target_failover" {
    for_each = var.target_group_config.target_failover != null ? [var.target_group_config.target_failover] : []
    content {
      on_deregistration = target_failover.value.on_deregistration
      on_unhealthy      = target_failover.value.on_unhealthy
    }
  }

  # Target Health State
  dynamic "target_health_state" {
    for_each = var.target_group_config.target_health_state != null ? [var.target_group_config.target_health_state] : []
    content {
      enable_unhealthy_connection_termination = target_health_state.value.enable_unhealthy_connection_termination
      unhealthy_draining_interval             = target_health_state.value.unhealthy_draining_interval
    }
  }
}

###################################################################
#                Target Group Attachment
###################################################################

resource "aws_lb_target_group_attachment" "this" {
  for_each = var.target_group_attachment_config != null ? { for idx, attachment in var.target_group_attachment_config : idx => attachment } : {}

  target_group_arn = aws_lb_target_group.this["config"].arn
  target_id        = each.value.target_id
  port             = each.value.port

  # For IP targets, optionally set availability_zone
  availability_zone = lookup(each.value, "availability_zone", null)

}

###################################################################
#                Load Balancer Trust Store
###################################################################

resource "aws_lb_trust_store" "this" {
  for_each = var.lb_trust_store_config != null ? { for idx, trust_store in var.lb_trust_store_config : idx => trust_store } : {}

  name                     = each.value.name
  name_prefix              = each.value.name_prefix
  ca_certificates_bundle_s3_bucket = each.value.ca_certificates_bundle_s3_bucket
  ca_certificates_bundle_s3_key    = each.value.ca_certificates_bundle_s3_key
  ca_certificates_bundle_s3_object_version = each.value.ca_certificates_bundle_s3_object_version

 tags = var.tags
}


###################################################################
#                 Listener
###################################################################
resource "aws_lb_listener" "this" {
  load_balancer_arn = aws_lb.this.arn
  port              = var.alb_listener.port
  protocol          = var.alb_listener.protocol
  alpn_policy       = var.alb_listener.alpn_policy
  certificate_arn   = var.alb_listener.certificate_arn
  ssl_policy        = var.alb_listener.ssl_policy
  tcp_idle_timeout_seconds = var.alb_listener.tcp_idle_timeout_seconds

  dynamic "default_action" {
    for_each = var.default_action
    content {
      type = default_action.value.type

      # OIDC Authentication action
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

      # Cognito Authentication action
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

      # Fixed Response action
      dynamic "fixed_response" {
        for_each = lookup(default_action.value, "fixed_response", null) != null ? [default_action.value.fixed_response] : []
        content {
          status_code  = fixed_response.value.status_code
          content_type = fixed_response.value.content_type
          message_body = fixed_response.value.message_body
        }
      }

      # Forward action

      #  dynamic "forward" {
      #   for_each = lookup(default_action.value, "forward", null) != null ? [default_action.value.forward] : []
      #   content {
      #     target_group {
      #       arn = lookup(default_action.value.forward, "arn", null) != null ? default_action.value.forward.arn : aws_lb_target_group.this["config"].arn
      #     }
      #  }
      #  }

      # dynamic "forward" {
      #   for_each = lookup(default_action.value, "forward", null) != null ? [default_action.value.forward] : []

      #     dynamic "target_group" {
      #       for_each = lookup(default_action.value.forward, "target_groups", null) != null ? default_action.value.forward.target_groups : []
      #       content {
      #         arn    = aws_lb_target_group.this["config"].arn
      #         weight = target_group.value.weight
      #       }
      #     }

      #     dynamic "stickiness" {
      #       for_each = lookup(default_action.value.forward, "stickiness", null) != null ? [default_action.value.forward.stickiness] : []
      #       content {
      #         duration = stickiness.value.duration
      #         enabled  = stickiness.value.enabled
      #       }
      #     }
      #   }

      # Forward action with multiple target groups
      dynamic "forward" {
        for_each = lookup(default_action.value, "forward", null) != null ? [default_action.value.forward] : []
        content {
          dynamic "target_group" {
            for_each = lookup(forward.value, "target_groups", [])
            content {
              arn    = aws_lb_target_group.this["config"].arn
              weight = lookup(target_group.value, "weight", null)
            }
          }

          dynamic "stickiness" {
            for_each = lookup(forward.value, "stickiness", null) != null ? [forward.value.stickiness] : []
            content {
              duration = stickiness.value.duration
              enabled  = lookup(stickiness.value, "enabled", false)
            }
          }
        }
      }

      # Redirect action
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
    }
  }

  tags = var.tags
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
 tags = var.tags
}
