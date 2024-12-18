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
      to_port     = 88
    },
    {
      description = "Allow traffic from self"
      self        = true
      from_port   = 0
      ip_protocol = "tcp"
      to_port     = 443
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
  enabled = true
  bucket  = "my-log-bucket"
  prefix  = "load-balancer-logs"
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

