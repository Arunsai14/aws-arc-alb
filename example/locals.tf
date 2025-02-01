locals {
load_balancer_config = {
  name                              = "arc-load-balancer"
  type                =  "application"
  internal                          = false
  ip_address_type                   = "ipv4"
  enable_deletion_protection        = false
  enable_cross_zone_load_balancing  = true
  enable_http2                      = false
  enable_waf_fail_open              = false
  enable_xff_client_port            = false
  enable_zonal_shift                = false
  desync_mitigation_mode            = "defensive"
  drop_invalid_header_fields        = false
  enforce_security_group_inbound_rules_on_private_link_traffic = "off"
  idle_timeout                      = 60
  preserve_host_header              = false
  xff_header_processing_mode        = "append"
  customer_owned_ipv4_pool         = null
  dns_record_client_routing_policy  = "any_availability_zone"
  client_keep_alive                 = 60
  enable_tls_version_and_cipher_suite_headers = false

  subnet_mapping = [
    {
      subnet_id            = data.aws_subnets.private.ids[0]
    },
    {
      subnet_id            = data.aws_subnets.private.ids[1]
    }
  ]

  access_logs = {
    enabled = false
    bucket  = "arc-terraform-alb-logs-1"
    prefix  = "alb-logs"
  }

  connection_logs = {
    enabled = false
    bucket  = "arc-terraform-alb-logs-1"
    prefix  = "connection-logs"
  }
}

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

target_group_config = {
  name        = "arc-poc-alb"
  port        = 80
  protocol    = "HTTP"
  target_type = "instance"
  health_check = {
    enabled             = true
    interval            = 30         
    path                = "/"
    port                = 80        
    protocol            = "HTTP"
    timeout             = 5          
    unhealthy_threshold = 3          
    healthy_threshold   = 2          
    matcher             = "200"      
  }
  stickiness = {
    enabled         = true
    type            = "lb_cookie"
    cookie_duration = 3600  
  }
}

target_group_attachment_config = [
  {
    target_id       = "i-024cca3753df50299"  # Instance ID
    target_type     = "instance"
    port            = 80
     }
]

default_action = [{
  type = "forward"
  forward = {
    target_groups = [{
      weight = 20
    }]
     stickiness = {
        duration = 300
        enabled  = true
      }
  }
}]

alb_listener = {
  port                     = 88               
  protocol                 = "HTTP"         
}

listener_rules = {
  rule1 = {
    priority = 9
    actions = [
      {
        type  = "redirect"
        order = 1
        redirect = {
          host        = "divyasf.sourcef.us"
          path        = "/redirect"
          query       = "action=redirect"
          protocol    = "HTTPS"
          port        = 443
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
  },

  rule2 = {
    priority = 999
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

}