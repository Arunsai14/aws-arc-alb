################################################################################
## shared
################################################################################
variable "region" {
  type        = string
  default     = "us-east-1"
  description = "AWS region"
}
variable "alb_name" {
  description = "The name of the ALB"
  type        = string
  default     = "my-app-alb"
}

variable "internal" {
  description = "Whether the ALB is internal"
  type        = bool
  default     = false
}

variable "load_balancer_type" {
  description = "Type of the load balancer"
  type        = string
  default     = "application"
}

variable "security_groups" {
  description = "The security groups to associate with the ALB"
  type        = list(string)
  default     = ["sg-0123456789abcdef0"]
}

variable "subnets" {
  description = "The subnets to associate with the ALB"
  type        = list(string)
  default     = ["subnet-0123456789abcdef0", "subnet-abcdef0123456789"]
}

variable "enable_deletion_protection" {
  description = "Whether to enable deletion protection"
  type        = bool
  default     = true
}

variable "listener_port" {
  description = "Port to listen on"
  type        = number
  default     = 80
}

variable "listener_protocol" {
  description = "Protocol for the listener"
  type        = string
  default     = "HTTP"
}

variable "target_group_name" {
  description = "The name of the target group"
  type        = string
  default     = "my-target-group"
}

variable "target_group_port" {
  description = "The port on which the targets are listening"
  type        = number
  default     = 80
}

variable "target_group_protocol" {
  description = "The protocol used by the targets"
  type        = string
  default     = "HTTP"
}

variable "vpc_id" {
  description = "VPC ID to associate with the target group"
  type        = string
  default     = ""
}

variable "host_header_values" {
  description = "List of host header values for listener rules"
  type        = list(string)
  default     = ["myapp.example.com"]
}

variable "target_instance_id" {
  description = "Instance ID for the target group attachment"
  type        = string
  default     = "i-0123456789abcdef0"
}

variable "target_instance_port" {
  description = "Port for the target instance"
  type        = number
  default     = 80
}
