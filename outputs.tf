output "alb_dns_name" {
  description = "The DNS name of the ALB"
  value       = aws_lb.app_lb.dns_name
}

output "ecs_cluster_id" {
  description = "The ECS Cluster ID"
  value       = aws_ecs_cluster.main.id
}

# Output for the Route 53 domain name
output "domain_name-nginx" {
  value       = "nginx.ahmetdevops.click" # Statik alan adı
  description = "The domain name for the application"
}

output "domain_name-apache" {
  value       = "apache.ahmetdevops.click" # Statik alan adı
  description = "The domain name for the application"
}
output "domain_name-wordpress" {
  value       ="wordpress.ahmetdevops.click" # Statik alan adı
  description = "The domain name for the application"
}

