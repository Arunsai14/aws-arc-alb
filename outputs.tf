output "load_balancer_arn" {
  description = "ARN of the load balancer"
  value       = aws_lb.this.arn
}

output "load_balancer_dns_name" {
  description = "DNS name of the load balancer"
  value       = aws_lb.this.dns_name
}

output "load_balancer_id" {
  description = "ID of the load balancer"
  value       = aws_lb.this.id
}

output "security_group_ids" {
  description = "Security group IDs created"
  value       = module.arc_security_group[*].id
}

output "target_group_arn" {
  description = "ARN of the target group"
  value       = aws_lb_target_group.this[0].arn
}

output "target_group_health_check" {
  description = "Health check configuration of the target group"
  value = aws_lb_target_group.this[0].health_check
}

output "target_group_stickiness" {
  description = "Stickiness configuration of the target group"
  value = aws_lb_target_group.this[0].stickiness
}

output "listener_arn" {
  description = "ARN of the load balancer listener"
  value       = aws_lb_listener.this.arn
}

output "lb_trust_store_name" {
  description = "Name of the load balancer trust store"
  value       = aws_lb_trust_store.this[*].name
}

output "target_group_attachment_ids" {
  description = "IDs of target group attachments"
  value       = aws_lb_target_group_attachment.this[*].id
}
