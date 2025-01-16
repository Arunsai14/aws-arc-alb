output "load_balancer_arn" {
  description = "The ARN of the created load balancer"
  value       = aws_lb.this.arn
}

output "load_balancer_dns_name" {
  description = "The DNS name of the created load balancer"
  value       = aws_lb.this.dns_name
}

output "load_balancer_zone_id" {
  description = "The zone ID of the created load balancer"
  value       = aws_lb.this.zone_id
}

output "security_group_id" {
  value = [for sg in module.arc_security_group : sg.id]
}