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
      subnet_id            = "subnet-6781cb49"
    },
    {
      subnet_id            = "subnet-f55c1392"
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

}