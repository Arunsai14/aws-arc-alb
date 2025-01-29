output "alb_arn" {
  description = "ARN of the ALB"
  value       = module.alb.load_balancer_arn
}