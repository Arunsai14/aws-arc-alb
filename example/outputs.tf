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

output "private_subnet_id" {
  description = "ID of the first private subnet"
  value       = data.aws_subnet.private_subnet.id
}

output "public_subnet_id" {
  description = "ID of the first public subnet"
  value       = [for s in data.aws_subnet.private : s.id]
}