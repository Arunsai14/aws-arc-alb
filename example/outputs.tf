# output "alb_arn" {
#   description = "ARN of the ALB"
#   value       = module.alb.load_balancer_arn
# }

# output "load_balancer_id" {
#   description = "ID of the load balancer"
#   value       = module.alb.load_balancer_id
# }

# output "security_group_ids" {
#   description = "Security group IDs created"
#   value       =  module.alb.security_group_ids
# }

# output "target_group_arn" {
#   description = "ARN of the target group"
#   value       = module.alb.target_group_arn
# }

# output "target_group_health_check" {
#   description = "Health check configuration of the target group"
#   value = module.alb.target_group_health_check
# }


output "private_subnet_ids" {
  description = "List of private subnet IDs"
  value       = data.aws_subnets.private.ids
}

output "private_subnet_id" {
  description = "The first private subnet ID"
  value       = data.aws_subnets.private.ids[0]
}

output "s3_bucket_name" {
  value = module.s3.bucket_id
}

output "aws_region" {
  value = data.aws_region.current.name
}