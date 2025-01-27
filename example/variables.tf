################################################################################
## shared
################################################################################
variable "region" {
  type        = string
  default     = "us-east-1"
  description = "AWS region"
}


variable "security_groups" {
  type    = list(string)
  default = []  
}

variable "security_group_name" {
  type        = string
  description = "The name of the security group"
}

variable "vpc_id" {
  description = "The VPC ID for the resources"
  type        = string
}


# variable "enable_deletion_protection" {
#   description = "Enable deletion protection for the ALB"
#   type        = bool
# }

variable "load_balancer_config" {
  type = object({
    name                              = optional(string, null)
    name_prefix                       = optional(string, null)
    type                              = optional(string, "application")
    internal                          = optional(bool, false)
    ip_address_type                   = optional(string, "ipv4")
    enable_deletion_protection        = optional(bool, true)
    enable_cross_zone_load_balancing  = optional(bool, true)
    enable_http2                      = optional(bool, true)
    enable_waf_fail_open              = optional(bool, false)
    enable_xff_client_port            = optional(bool, true)
    enable_zonal_shift                = optional(bool, true)
    desync_mitigation_mode            = optional(string, "defensive")
    drop_invalid_header_fields        = optional(bool, false)
    enforce_security_group_inbound_rules_on_private_link_traffic = optional(string, "off")
    idle_timeout                      = optional(number, 60)
    preserve_host_header              = optional(bool, true)
    xff_header_processing_mode        = optional(string, "append")
    customer_owned_ipv4_pool          = optional(string, null)
    dns_record_client_routing_policy  = optional(string, "any_availability_zone")
    client_keep_alive                 = optional(number, 60)
    enable_tls_version_and_cipher_suite_headers = optional(bool, true)
    subnet_mapping = optional(list(object({
      subnet_id            = string
      allocation_id        = optional(string, null)
      ipv6_address         = optional(string, null)
      private_ipv4_address = optional(string, null)
    })))
    access_logs = optional(object({
      enabled = optional(bool, false)
      bucket  = string
      prefix  = optional(string, "access-logs")
    }))
    connection_logs = optional(object({
      enabled = optional(bool, false)
      bucket  = string
      prefix  = optional(string, "connection-logs")
    }))
  })
}

variable "security_group_data" {
  type = object({
    security_group_ids_to_attach = optional(list(string), []),
    create                       = optional(bool, true),
    description                  = optional(string, null),
    ingress_rules = optional(list(object({
      description              = optional(string, null)
      cidr_block               = optional(string, null)
      source_security_group_id = optional(string, null)
      from_port                = number
      ip_protocol              = string
      to_port                  = string
      self                     = optional(bool, false)
    })), []),
    egress_rules = optional(list(object({
      description                   = optional(string, null)
      cidr_block                    = optional(string, null)
      destination_security_group_id = optional(string, null)
      from_port                     = number
      ip_protocol                   = string
      to_port                       = string
      prefix_list_id                = optional(string, null)
    })), [])
  })
  default = {
    create = false
  }
}

variable "target_group_config" {
  type = object({
    name                                = optional(string)
    name_prefix                         = optional(string)
    port                                = optional(number)
    protocol                            = optional(string)
    vpc_id                              = optional(string)
    ip_address_type                     = optional(string)
    load_balancing_anomaly_mitigation   = optional(bool)
    load_balancing_cross_zone_enabled   = optional(bool)
    preserve_client_ip                  = optional(bool)
    protocol_version                    = optional(string)
    load_balancing_algorithm_type       = optional(string)
    target_type                         = optional(string)
    proxy_protocol_v2                   = optional(bool)
    slow_start                          = optional(number)

    health_check = optional(object({
      enabled             = bool
      interval            = number
      path                = string
      port                = number
      protocol            = string
      timeout             = number
      unhealthy_threshold = number
      healthy_threshold   = number
      matcher             = string
    }))

    stickiness = optional(object({
      type            = string
      cookie_duration = number
      cookie_name     = optional(string)
      enabled         = bool
    }))
  })
  default = null
}

variable "alb_listener" {
  type = object({
    port                     = optional(number, 80)
    protocol                 = optional(string, "HTTP")
    alpn_policy              = optional(string, null)
    certificate_arn          = optional(string, "")
    ssl_policy               = optional(string, "")
    tcp_idle_timeout_seconds = optional(number, 350)
  })
}

######### alb listener config ##########
variable "default_action" {
  description = "A list of default actions for the load balancer listener"
  type = list(object({
    type                        = string
    authenticate_oidc           = optional(object({
      authorization_endpoint                = string
      authentication_request_extra_params   = map(string)
      client_id                             = string
      client_secret                         = string
      issuer                                = string
      token_endpoint                        = string
      user_info_endpoint                    = string
      on_unauthenticated_request            = string
      scope                                 = string
      session_cookie_name                   = string
      session_timeout                       = string
    }))
    authenticate_cognito           = optional(object({
      user_pool_arn                       = string
      user_pool_client_id                 = string
      user_pool_domain                    = string
      authentication_request_extra_params = map(string)
      on_unauthenticated_request          = string
      scope                                = string
      session_cookie_name                 = string
      session_timeout                     = string
    }))
    fixed_response                 = optional(object({
      status_code   = string
      content_type  = string
      message_body  = string
    }))
    forward                        = optional(object({
      target_group = list(object({
        arn = string
      }))
      stickiness = optional(object({
        duration = number
        enabled  = bool
      }))
    }))
    redirect                       = optional(object({
      host         = string
      path         = string
      query        = string
      protocol     = string
      port         = string
      status_code  = string
    }))
  }))
  default = []
}

########## alb listener rule config ##########
variable "listener_rules" {
  description = "A map of listener rules"
  type = map(object({
    priority   = number
    authenticate_oidc = optional(object({
      authorization_endpoint = string
      client_id              = string
      client_secret          = string
      issuer                 = string
      token_endpoint         = string
      user_info_endpoint     = string
      authentication_request_extra_params = map(string)
      on_unauthenticated_request        = string
      scope                             = string
      session_cookie_name               = string
      session_timeout                   = number
    }))
    actions    = list(object({
      type             = string
      order            = number
      redirect         = optional(object({
        host        = string
        path        = string
        query       = string
        protocol    = string
        port        = number
        status_code = string
      }))
      fixed_response = optional(object({
        status_code  = string
        content_type = string
        message_body = string
      }))
      authenticate_cognito = optional(object({
        user_pool_arn       = string
        user_pool_client_id = string
        user_pool_domain    = string
        on_unauthenticated_request = string
      }))
    }))
    conditions = list(object({
      host_header = optional(object({
        values = list(string)
      }))
      path_pattern = optional(object({
        values = list(string)
      }))
    }))
  }))
}