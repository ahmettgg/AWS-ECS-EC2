provider "aws" {
  region = "us-east-1" // AWS bölgenizi belirtin
}

# VPC oluşturma
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.13.0"

  name = "my-vpc"
  cidr = "10.0.0.0/16"

  azs             = ["us-east-1a", "us-east-1b"]
  public_subnets  = ["10.0.1.0/24", "10.0.2.0/24"]
  private_subnets = ["10.0.3.0/24", "10.0.4.0/24"]

  enable_nat_gateway = true
  single_nat_gateway = true
}

# Security Group for ALB
resource "aws_security_group" "alb_sg" {
  name        = "alb-sg"
  description = "Allow inbound HTTP and HTTPS"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
ingress {
    from_port   = 8001
    to_port     = 8001
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 8002
    to_port     = 8002
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Security Group for ECS Instances
resource "aws_security_group" "ecs_sg" {
  name        = "ecs-sg"
  description = "Allow inbound traffic from ALB"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    # cidr_blocks = ["0.0.0.0/0"]
    security_groups = [aws_security_group.alb_sg.id]   # Referencing Load Balancer security group
  }
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
    }
ingress {
    from_port   = 8001
    to_port     = 8001
    protocol    = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }
  ingress {
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }
  ingress {
    from_port   = 8002
    to_port     = 8002
    protocol    = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }
   ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]   
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

##########################################################################################

## Request a new ACM certificate
# resource "aws_acm_certificate" "new_cert" {
#   domain_name       = "ahmetdevops.click"
#   validation_method = "DNS"

#   lifecycle {
#     create_before_destroy = true
#   }

#   # Automatically create DNS validation records in Route 53
#   domain_validation_options {
#     domain_name = "ahmetdevops.click"
  
#   }
# }

# # Automatically create Route 53 validation records
# resource "aws_route53_record" "new_cert_validation" {
#   for_each = {
#     for dvo in aws_acm_certificate.new_cert.domain_validation_options : dvo.domain_name => {
#       name   = dvo.resource_record_name
#       type   = dvo.resource_record_type
#       value  = dvo.resource_record_value
#     }
#   }

#   zone_id = data.aws_route53_zone.selected.zone_id
#   name    = each.value.name
#   type    = each.value.type
#   ttl     = 60
#   records = [each.value.value]
# }

# # Update listener to use the new certificate
# resource "aws_lb_listener" "https" {
#   load_balancer_arn = aws_lb.app_lb.arn
#   port              = "443"
#   protocol          = "HTTPS"
#   ssl_policy        = "ELBSecurityPolicy-2016-08"

#   # Use the new certificate ARN
#   certificate_arn = aws_acm_certificate.new_cert.arn

#   default_action {
#     type = "forward"
#     target_group_arn = aws_lb_target_group.app_tg.arn
#   }
# }

#########################################################################################

resource "aws_lb" "app_lb" {
  name               = "app-lb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = module.vpc.public_subnets
}

# Data source to pull existing ACM certificate
data "aws_acm_certificate" "existing_cert" {
  domain   = "ahmetdevops.click"  # Domain covered by the certificate
  statuses = ["ISSUED"]          # Only get the successful certificate

  # Optional: To get the latest one if there is more than one
  most_recent = true
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.app_lb.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-2016-08"
  certificate_arn   = data.aws_acm_certificate.existing_cert.arn

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "404 Not Found"
      status_code  = "404"
    
  }
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.app_lb.arn
  port              = "80"
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      protocol = "HTTPS"
      port     = "443"
      status_code = "HTTP_301"
    }
  }
}

# Host-Based Routing için ayrı listener kuralları ekleyin:
resource "aws_lb_listener_rule" "nginx_rule" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 1

  condition {
    host_header {
      values = ["nginx.ahmetdevops.click"]
    }
  }

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.nginx_tg.arn
  }
}

resource "aws_lb_listener_rule" "apache_rule" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 2

  condition {
    host_header {
      values = ["apache.ahmetdevops.click"]
    }
  }

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.apache_tg.arn
  }
}

resource "aws_lb_listener_rule" "wordpress_rule" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 3

  condition {
    host_header {
      values = ["wordpress.ahmetdevops.click"]
    }
  }

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.wordpress_tg.arn
  }
}

# Hedef Grubu - Nginx
resource "aws_lb_target_group" "nginx_tg" {
  name     = "nginx-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = module.vpc.vpc_id

  health_check {
    interval            = 30      # Health check'lerin aralığı (default 30 sn)
    timeout             = 5       # Cevap vermesi gereken süre (default 5 sn)
    healthy_threshold   = 3       # Sağlıklı sayılması için gereken başarılı cevap sayısı
    unhealthy_threshold = 3       # Sağlıksız sayılması için gereken başarısız cevap sayısı
    path                = "/"     # Health check yapılacak URL
    matcher             = "200"   # Beklenen HTTP durumu
  }
}

# Hedef Grubu - Apache
resource "aws_lb_target_group" "apache_tg" {
  name     = "apache-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = module.vpc.vpc_id

  health_check {
    interval            = 30      # Health check'lerin aralığı (default 30 sn)
    timeout             = 5       # Cevap vermesi gereken süre (default 5 sn)
    healthy_threshold   = 3       # Sağlıklı sayılması için gereken başarılı cevap sayısı
    unhealthy_threshold = 3       # Sağlıksız sayılması için gereken başarısız cevap sayısı
    path                = "/"     # Health check yapılacak URL
    matcher             = "200"   # Beklenen HTTP durumu
  }
}

# Hedef Grubu - WordPress
resource "aws_lb_target_group" "wordpress_tg" {
  name     = "wordpress-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = module.vpc.vpc_id

  health_check {
    interval            = 30      # Health check'lerin aralığı (default 30 sn)
    timeout             = 5       # Cevap vermesi gereken süre (default 5 sn)
    healthy_threshold   = 3       # Sağlıklı sayılması için gereken başarılı cevap sayısı
    unhealthy_threshold = 3       # Sağlıksız sayılması için gereken başarısız cevap sayısı
    path                = "/wp-admin/setup-config.php"     # Health check yapılacak URL
    matcher             = "200"   # Beklenen HTTP durumu
  }
}

# Varsayılan (Default) Hedef Grubu
# resource "aws_lb_target_group" "default_tg" {
#   name     = "default-tg"
#   port     = 80
#   protocol = "HTTP"
#   vpc_id   = module.vpc.vpc_id
#   health_check {
#     interval            = 30      # Health check'lerin aralığı (default 30 sn)
#     timeout             = 5       # Cevap vermesi gereken süre (default 5 sn)
#     healthy_threshold   = 3       # Sağlıklı sayılması için gereken başarılı cevap sayısı
#     unhealthy_threshold = 3       # Sağlıksız sayılması için gereken başarısız cevap sayısı
#     path                = "/"     # Health check yapılacak URL
#     matcher             = "200"   # Beklenen HTTP durumu
#   }
# }


# ECS Cluster
resource "aws_ecs_cluster" "main" {
  name = "ecs-cluster"
}

# Nginx için Task Definition
resource "aws_ecs_task_definition" "nginx_task" {
  family                   = "nginx-task"
  
  container_definitions    = jsonencode([
    {
      name      = "nginx-container",
      image     = "nginx:latest",
      memory    = 2048,
      cpu       = 1024,
      essential = true,
      portMappings = [
        {
          containerPort = 80,
          hostPort      = 8000
        },
      ],
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = "/ecs/nginx"
          "awslogs-region"        = "us-east-1"  # Bölgenizi burada belirtin
          "awslogs-stream-prefix" = "ecs"
        }
      }
    }
  ])
  requires_compatibilities = ["EC2"]
  network_mode             = "bridge"
  
}


# Apache için Task Definition
resource "aws_ecs_task_definition" "apache_task" {
  family                   = "apache-task"
  container_definitions    = jsonencode([
    {
      name      = "apache-container",
      image     = "httpd:latest",
      memory    = 2048,
      cpu       = 1024,
      essential = true,
      portMappings = [
        {
          containerPort = 80,
          hostPort      = 8001
        },
      ],
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = "/ecs/apache"
          "awslogs-region"        = "us-east-1"  # Bölgenizi burada belirtin
          "awslogs-stream-prefix" = "ecs"
        }
      }
    }
  ])
  requires_compatibilities = ["EC2"]
  network_mode             = "bridge"
}

# WordPress için Task Definition
resource "aws_ecs_task_definition" "wordpress_task" {
  family                   = "wordpress-task"
  container_definitions    = jsonencode([
    {
      name      = "wordpress-container",
      image     = "wordpress:latest",
      memory    = 2048,
      cpu       = 1024,
      essential = true,
      portMappings = [
        {
          containerPort = 80,
          hostPort      = 8002
        },
      ],
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = "/ecs/wordpress"
          "awslogs-region"        = "us-east-1"  # Bölgenizi burada belirtin
          "awslogs-stream-prefix" = "ecs"
        }
      }
    }
  ])
  requires_compatibilities = ["EC2"]
  network_mode             = "bridge"
}

# Nginx için ECS Service
resource "aws_ecs_service" "nginx_service" {
  name            = "nginx-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.nginx_task.arn
  desired_count   = 1

  launch_type = "EC2"

  load_balancer {
    target_group_arn = aws_lb_target_group.nginx_tg.arn
    container_name   = "nginx-container"
    container_port   = 80
  }
}

# Apache için ECS Service
resource "aws_ecs_service" "apache_service" {
  name            = "apache-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.apache_task.arn
  desired_count   = 1

  launch_type = "EC2"

  load_balancer {
    target_group_arn = aws_lb_target_group.apache_tg.arn
    container_name   = "apache-container"
    container_port   = 80
      }
}

# WordPress için ECS Service
resource "aws_ecs_service" "wordpress_service" {
  name            = "wordpress-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.wordpress_task.arn
  desired_count   = 1

  launch_type = "EC2"

  load_balancer {
    target_group_arn = aws_lb_target_group.wordpress_tg.arn
    container_name   = "wordpress-container"
    container_port   = 80
    }
}

# Auto Scaling Group for ECS
resource "aws_autoscaling_group" "ecs_instances" {
  desired_capacity     = 2
  max_size             = 5
  min_size             = 2
  vpc_zone_identifier  = module.vpc.public_subnets
  launch_template {
    id      = aws_launch_template.ecs_launch_template.id
    version = "$Latest"
  }
  tag {
    key                 = "Name"
    value               = "ecs-instance"
    propagate_at_launch = true
  }
 target_group_arns = [
    aws_lb_target_group.nginx_tg.arn,
    aws_lb_target_group.apache_tg.arn,
    aws_lb_target_group.wordpress_tg.arn
  ]

}

resource "aws_launch_template" "ecs_launch_template" {
  name_prefix   = "ecs-launch-template"
  image_id      = data.aws_ami.ecs_optimized.id
  instance_type = "t3.xlarge"
  key_name      = "firstkey"
  user_data = base64encode(<<-EOF
    #!/bin/bash
    echo ECS_CLUSTER=ecs-cluster >> /etc/ecs/ecs.config
  EOF
  )

  iam_instance_profile {
    name = aws_iam_instance_profile.ecs_instance_profile.name
  }
  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.ecs_sg.id]
  }
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size = 30
      volume_type = "gp2"
    }
  }
}

data "aws_ami" "ecs_optimized" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-ecs-hvm-*-x86_64-ebs"]
  }
}

resource "aws_iam_role" "ecs_instance_role" {
  name = "ecs_instance_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Action = "sts:AssumeRole",
      Effect = "Allow",
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_instance_profile" "ecs_instance_profile" {
  name = "ecs_instance_profile"
  role = aws_iam_role.ecs_instance_role.name
}

# IAM Role için politika ekleme
resource "aws_iam_role_policy_attachment" "ecs_policy" {
  role       = aws_iam_role.ecs_instance_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role"
}

# AmazonEC2FullAccess politikasını ekleme
resource "aws_iam_role_policy_attachment" "ec2_full_access_policy" {
  role       = aws_iam_role.ecs_instance_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2FullAccess"
}

# CloudWatchLogsFullAccess politikasını ekleme
resource "aws_iam_role_policy_attachment" "cloudwatch_logs_full_access_policy" {
  role       = aws_iam_role.ecs_instance_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess"
}

# Eğer Hosted Zone zaten mevcutsa data bloğu ile çekebilirsiniz
data "aws_route53_zone" "selected" {
  name = "ahmetdevops.click"
}

# Route 53 Alias kaydı ile Load Balancer DNS'ini domain'e bağlama

resource "aws_route53_record" "nginx_lb_dns" {
  zone_id = data.aws_route53_zone.selected.zone_id  
  name    = "nginx.ahmetdevops.click"
  type    = "A"

  alias {
    name                   = aws_lb.app_lb.dns_name
    zone_id                = aws_lb.app_lb.zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "apache_lb_dns" {
  zone_id = data.aws_route53_zone.selected.zone_id
  name    = "apache.ahmetdevops.click"
  type    = "A"

  alias {
    name                   = aws_lb.app_lb.dns_name
    zone_id                = aws_lb.app_lb.zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "wordpress_lb_dns" {
  zone_id = data.aws_route53_zone.selected.zone_id
  name    = "wordpress.ahmetdevops.click"
  type    = "A"

  alias {
    name                   = aws_lb.app_lb.dns_name
    zone_id                = aws_lb.app_lb.zone_id
    evaluate_target_health = false
  }
}
