locals {
load_balancer_config = {
  name                              = "arc-load-balancer"
  type                =  "network" 
  internal                          = false
  security_groups                   = ["sg-123456"]
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
    enabled = true
    bucket  = "arc-terraform-alb-logs-1"
    prefix  = "alb-logs"
  }

  connection_logs = {
    enabled = true
    bucket  = "arc-terraform-alb-logs-1"
    prefix  = "connection-logs"
  }
}

bucket_policy_doc = jsonencode({
  Version = "2012-10-17"
  Statement = [
    {
      Effect = "Allow"
      Principal = {
        Service = "delivery.logs.amazonaws.com"
      }
      "Action": [
            "s3:PutObject",
            "s3:PutObjectAcl"
     ],
      Resource = "arn:aws:s3:::${var.bucket_name}/alb-logs/*"
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = "${data.aws_caller_identity.current.account_id}"
        }
        ArnLike = {
          "aws:SourceArn" = "arn:aws:elasticloadbalancing:${var.region}:${data.aws_caller_identity.current.account_id}:loadbalancer/*"
        }
      }
    },
    {
      Effect = "Allow"
      Principal = {
        Service = "delivery.logs.amazonaws.com"
      }
      Action = "s3:GetBucketAcl"
      Resource = "arn:aws:s3:::${var.bucket_name}"
    }
  ]
})

}