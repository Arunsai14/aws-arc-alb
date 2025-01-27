variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"  # Change as needed
}

variable "environment" {
  type        = string
  description = "Name of the environment, i.e. dev, stage, prod"
  default     = "dev"
}

variable "namespace" {
  type        = string
  default     = "arc"
  description = "Namespace of the project, i.e. arc"
}

variable "project_name" {
  type        = string
  default     = "sourcefuse"
  description = "Project name"
}
variable "name" {
  description = "Name of the Load Balancer. Must be unique."
  type        = string
}

variable "name_prefix" {
  description = "Creates a unique name beginning with the specified prefix. Conflicts with name."
  type        = string
  default     = null
}

variable "load_balancer_type" {
  description = "Type of load balancer to create. Possible values: application, gateway, network."
  type        = string
  default     = "application"
}

variable "internal" {
  description = "Whether the Load Balancer is internal."
  type        = bool
  default     = false
}

variable "security_groups" {
  description = "List of security group IDs to assign to the Load Balancer."
  type        = list(string)
  default     = []
}

variable "vpc_id" {
  description = "VPC ID where the security group is created."
  type        = string
}

variable "subnets" {
  description = "List of subnet IDs to attach to the Load Balancer."
  type        = list(string)
}

variable "ip_address_type" {
  description = "Type of IP addresses used by the subnets. Possible values: ipv4, dualstack."
  type        = string
  default     = "ipv4"
}

variable "enable_deletion_protection" {
  description = "If true, deletion of the Load Balancer will be disabled."
  type        = bool
  default     = false
}

variable "enable_cross_zone_load_balancing" {
  description = "If true, cross-zone load balancing of the Load Balancer will be enabled."
  type        = bool
  default     = false
}

variable "enable_http2" {
  description = "Whether HTTP/2 is enabled for application Load Balancers."
  type        = bool
  default     = true
}

variable "enable_waf_fail_open" {
  description = "Whether to allow WAF-enabled Load Balancers to route requests if unable to forward to AWS WAF."
  type        = bool
  default     = false
}

variable "enable_xff_client_port" {
  description = "Whether the X-Forwarded-For header should preserve the source port."
  type        = bool
  default     = false
}

variable "enable_zonal_shift" {
  description = "Whether zonal shift is enabled."
  type        = bool
  default     = false
}

variable "desync_mitigation_mode" {
  description = "How the Load Balancer handles requests that pose a security risk due to HTTP desync."
  type        = string
  default     = "defensive"
}

variable "drop_invalid_header_fields" {
  description = "Whether HTTP headers with invalid fields are removed by the Load Balancer."
  type        = bool
  default     = false
}

variable "enforce_security_group_inbound_rules_on_private_link_traffic" {
  description = "Whether inbound security group rules are enforced for traffic originating from a PrivateLink."
  type        = string
  default     = "off"
}

variable "idle_timeout" {
  description = "Time in seconds that the connection is allowed to be idle."
  type        = number
  default     = 60
}

variable "preserve_host_header" {
  description = "Whether the Load Balancer should preserve the Host header."
  type        = bool
  default     = false
}

variable "xff_header_processing_mode" {
  description = "Determines how the X-Forwarded-For header is modified."
  type        = string
  default     = "append"
}

variable "customer_owned_ipv4_pool" {
  description = "ID of the customer-owned IPv4 pool to use for this Load Balancer."
  type        = string
  default     = null
}

variable "dns_record_client_routing_policy" {
  description = "How traffic is distributed among Availability Zones."
  type        = string
  default     = "any_availability_zone"
}

variable "client_keep_alive" {
  description = "Client keep alive value in seconds."
  type        = number
  default     = 3600
}

variable "enable_tls_version_and_cipher_suite_headers" {
  description = "Whether TLS headers are added to the client request."
  type        = bool
  default     = false
}

variable "access_logs" {
  description = "Access Logs configuration for the Load Balancer."
  type = object({
    enabled = bool
    bucket  = string
    prefix  = string
  })
  default = {
    enabled = false
    bucket  = null
    prefix  = null
  }
}

variable "connection_logs" {
  description = "Connection Logs configuration for the Load Balancer."
  type = object({
    enabled = bool
    bucket  = string
    prefix  = string
  })
  default = {
    enabled = false
    bucket  = null
    prefix  = null
  }
}

variable "subnet_mapping" {
  description = "Subnet mapping configuration for the Load Balancer."
  type = list(object({
    subnet_id            = string
    allocation_id        = string
    ipv6_address         = string
    private_ipv4_address = string
  }))
  default = []
}

variable "tags" {
  description = "Tags to assign to the resource."
  type        = map(string)
  default     = {}
}

variable "load_balancer_config" {
  type = object({
    name                              = optional(string, null)
    name_prefix                       = optional(string, null)
    load_balancer_type                = optional(string, "application")
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
    }),)
  })
}


variable "security_group_data" {
  type = object({
    security_group_ids_to_attach = optional(list(string), [])
    create                       = optional(bool, true)
    description                  = optional(string, null)
    ingress_rules = optional(list(object({
      description              = optional(string, null)
      cidr_block               = optional(string, null)
      source_security_group_id = optional(string, null)
      from_port                = number
      ip_protocol              = string
      to_port                  = string
      self                     = optional(bool, false)
    })), [])
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
  description = "(optional) Security Group data"
  default = {
    create = false
  }
}



variable "create_listener_rule" {
  type    = bool
  default = false
}


variable "alb" {
  type = object({
    name                       = optional(string, null)
    port                       = optional(number)
    protocol                   = optional(string, "HTTP")
    internal                   = optional(bool, false)
    load_balancer_type         = optional(string, "application")
    idle_timeout               = optional(number, 60)
    enable_deletion_protection = optional(bool, false)
    enable_http2               = optional(bool, true)
    certificate_arn            = optional(string, null)

    access_logs = optional(object({
      bucket  = string
      enabled = optional(bool, true)
      prefix  = optional(string, "")
    }))

    tags = optional(map(string), {})
  })
}

#########################################
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
    load_balancing_algorithm_type       = optional(string, "round_robin")
    target_type                         = optional(string)
    proxy_protocol_v2                   = optional(bool)
    slow_start                          = optional(number)
    tags                                = optional(map(string))

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

    target_group_health = optional(object({
      dns_failover = optional(object({
        minimum_healthy_targets_count     = number
        minimum_healthy_targets_percentage = number
      }))

      unhealthy_state_routing = optional(object({
        minimum_healthy_targets_count     = number
        minimum_healthy_targets_percentage = number
      }))
    }))

    target_failover = optional(object({
      on_deregistration = string
      on_unhealthy      = string
    }))

    target_health_state = optional(object({
      enable_unhealthy_connection_termination = bool
      unhealthy_draining_interval             = number
    }))
  })
  default = {}
}

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




variable "listener_certificates" {
  description = "A map of listener certificates with their ARN"
  type = map(object({
    certificate_arn = string
  }))
  default = {}
}

# Example variables for other options
variable "port" {
  description = "Port number"
  default = "80"
}

variable "protocol" {
  description = "Protocol for listener"
  default = "HTTP"
}

variable "alpn_policy" {
  description = "ALPN policy for TLS"
  default = "None"
}

variable "certificate_arn" {
  description = "SSL certificate ARN for HTTPS"
  default = ""
}

variable "ssl_policy" {
  description = "SSL policy"
  default = "ELBSecurityPolicy-2016-08"
}

variable "tcp_idle_timeout_seconds" {
  description = "TCP idle timeout seconds"
  default = 350
}

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





