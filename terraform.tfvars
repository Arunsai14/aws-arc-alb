name                     = "arc-load-balancer"
load_balancer_type       = "application" 
internal                 = false         
idle_timeout             = 60           
enable_deletion_protection = false      
ip_address_type          = "ipv4"  

# Subnets for the load balancer
subnets = ["subnet-6781cb49", "subnet-f55c1392"]

# VPC configuration
vpc_id = "vpc-68f96212"

# Security group rules
security_group_data = {
  create      = true
  description = "Security Group for alb"
  ingress_rules = [
    {
      description = "Allow VPC traffic"
      cidr_block  = "0.0.0.0/0" # Changed to string
      from_port   = 0
      ip_protocol = "tcp"
      to_port     = 443
    },
    {
      description = "Allow traffic from self"
      self        = true
      from_port   = 80
      ip_protocol = "tcp"
      to_port     = 80
    },
  ]
  egress_rules = [
    {
      description = "Allow all outbound traffic"
      cidr_block  = "0.0.0.0/0" # Changed to string
      from_port   = -1
      ip_protocol = "-1"
      to_port     = -1
    }
  ]
}


# Access logs configuration
access_logs = {
  enabled = false
  bucket  = "arc-terraform-alb-logs"
  prefix  = "load-balancer-logs"
}

connection_logs = {
    bucket  = "arc-terraform-alb-logs"
    prefix  = "lb-logs"
    enabled = false
  }

# Subnet mapping (optional, use if needed)
subnet_mapping = [
  {
    subnet_id            = "subnet-6781cb49"
    allocation_id        = null
    ipv6_address         = null
    private_ipv4_address = null
  },
  {
    subnet_id            = "subnet-f55c1392"
    allocation_id        = null
    ipv6_address         = null
    private_ipv4_address = null
  }
]

  alb_target_group = [{
    name        = "arc-poc-alb-tg"
    port        = 80
    protocol    = "HTTP"
    vpc_id      = "vpc-68f96212"
    target_type = "ip"
    health_check = {
      enabled = true
      path    = "/"
    }
    stickiness = {
      enabled = true
      type    = "lb_cookie"
    }
  }]
 cidr_blocks = null
  # listener_rules = []

    alb = {
    name       = "arc-poc-alb"
    internal   = false
    port       = 80
    create_alb = false
  }


#   default_actions = [
#   {
#     type = "forward"
#     forward = {
#       stickiness = {
#         enabled  = true
#         duration = 60
#       }
#     }
#   }
# ]


default_action = [
  # {
  #   type             = "forward"
  #   forward = {
  #     stickiness = {
  #       duration = 300
  #       enabled  = true
  #     }
  #   }
  # },
  # {
  #   type             = "fixed-response"
  #   fixed_response = {
  #     status_code  = "200"
  #     content_type = "text/plain"
  #     message_body = "Hello, World!"
  #   }
  # },
  {
    type             = "redirect"
    redirect = {
      host        = "example.com"
      path        = "/new-path"
      query       = "?id=123"
      protocol    = "HTTP"
      port        = "80"
      status_code = "HTTP_301"
    }
  },
  # {
  #   type             = "authenticate_oidc"
  #   authenticate_oidc = {
  #     authorization_endpoint = "https://example.com/authorize"
  #     client_id              = "your-client-id"
  #     client_secret          = "your-client-secret"
  #     issuer                 = "https://example.com"
  #     token_endpoint         = "https://example.com/token"
  #     user_info_endpoint     = "https://example.com/userinfo"
  #   }
  # },
  # {
  #   type             = "authenticate_cognito"
  #   authenticate_cognito = {
  #     user_pool_arn                     = "arn:aws:cognito-idp:region:account-id:userpool/user-pool-id"
  #     user_pool_client_id               = "client-id"
  #     user_pool_domain                  = "your-cognito-domain"
  #     authentication_request_extra_params = { "param1" = "value1" }
  #     on_unauthenticated_request        = "deny"
  #     scope                             = "openid profile"
  #     session_cookie_name               = "my-session-cookie"
  #     session_timeout                   = 3600
  #   }
  # }
]


port = 80
protocol = "HTTP"


listener_rules = {
  rule1 = {
    priority = 1
    actions = [
      {
        type  = "redirect"
        order = 1
        redirect = {
          host        = "example.com"
          path        = "/redirect"
          query       = "action=redirect"
          protocol    = "HTTP"
          port        = 80
          status_code = "HTTP_301"
        }
      }
    ]
    conditions = [
      {
        host_header = {
          values = ["example.com"]
        }
      }
    ]
  }

  rule2 = {
    priority = 2
    actions = [
      {
        type  = "fixed-response"
        order = 1
        fixed_response = {
          status_code  = "200"
          content_type = "text/plain"
          message_body = "OK"
        }
      }
    ]
    conditions = [
      {
        path_pattern = {
          values = ["/status"]
        }
      }
    ]
  }
}

# listener_certificates = [
#   {
#     certificate_arn = "arn:aws:acm:region:account-id:certificate/certificate-id"
#   }
]



# SSL and Listener settings
# certificate_arn = "arn:aws:acm:region:account-id:certificate/certificate-id"
# ssl_policy      = "ELBSecurityPolicy-2016-08"
# port            = 443
# protocol        = "HTTPS"
# alpn_policy     = "HTTP2"

# Optional settings
tcp_idle_timeout_seconds = 60

