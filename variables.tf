variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

# variable "domain_name" {
#   description = "Domain name for SSL certificate"
#   type        = string
# }

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}
