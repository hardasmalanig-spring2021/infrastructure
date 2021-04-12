provider "aws" {
  region = var.region
}

variable "region" {
  type = string
}

variable "cidr_block" {
  type = string
}

variable "vpc_name" {
  type = string
}

variable "subnet_name" { # required
  type = string
}

variable "subnet_zone_count" {
  type        = number
  default     = 3
  description = "Number of subnet zones to be created"
}

variable "start" {
  type        = number
  default     = 0
  description = "Start index of second octet in subnet cidr block"
}

# Initialize availability zone data from AWS
data "aws_availability_zones" "available" {}

variable "gateway_name" { # required
  type = string
}

variable "route_table_name" { # required
  type = string
}

variable "route_table_cidr_block" {
  type = string
}

variable "ingressCIDRblock" {
  type = list(any)
}

variable "egressCIDRblock" {
  type = list(any)
}

variable "database_security_group_name" {
  type = string
}

variable "s3_bucket_name" {
  type = string
}

variable "db_instance_class" {
  type = string
}


variable "db_identifier" {
  type = string
}

variable "db_username" {
  type = string
}

variable "db_password" {
  type = string
}

variable "db_port" {
  type = string
}

variable "subnet_group_name" {
  type = string
}

variable "db_name" {
  type = string
}



variable "ami_owners" {
  type = list(any)
}

variable "s3_iam_profile_name" {
  type = string
}

variable "s3_iam_role_name" {
  type = string
}

variable "s3_iam_policy_name" {
  type = string
}

variable "key_name" {
  type = string
}

variable "ssh_key_name" {
  type = string
}


variable "ec2_name" {
  type = string
}

variable "aws_profile_name" {
  type = string
}

variable "domain_name" {
  type = string
}

variable "dns" {
  type = string
}

variable "alarm_low_evaluation_period" {
  type = string

}
variable "alarm_high_evaluation_period" {
  type = string

}
variable "alarm_low_period" {
  type = string

}
variable "alarm_high_period" {
  type = string

}
variable "alarm_low_threshold" {
  type = string

}
variable "alarm_high_threshold" {
  type = string

}


variable "dynamo_dbname" {
  type = string
}

variable "dynamo_read_capacity" {
  type = number
}

variable "dynamo_write_capacity" {
  type = number
}


data "aws_caller_identity" "current" {}
locals {
  aws_user_account_id = data.aws_caller_identity.current.account_id
}

# VPC
resource "aws_vpc" "vpc" {
  cidr_block                       = var.cidr_block
  enable_dns_hostnames             = true
  enable_dns_support               = true
  enable_classiclink_dns_support   = false
  assign_generated_ipv6_cidr_block = false
  tags = {
    Name = var.vpc_name
  }
}

# Subnets
resource "aws_subnet" "subnet" {
  count                   = var.subnet_zone_count
  cidr_block              = "10.${var.start}.${10 + count.index}.0/24"
  vpc_id                  = aws_vpc.vpc.id
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true
  tags = {
    Name = var.subnet_name
  }
}

# Internet gateway for the public subnets
resource "aws_internet_gateway" "internet_gateway" {
  vpc_id = aws_vpc.vpc.id
  tags = {
    Name = var.gateway_name # gateway would be created with this name
  }
}

# Routing table for public subnets
resource "aws_route_table" "route_table" {
  vpc_id = aws_vpc.vpc.id
  route {
    cidr_block = var.route_table_cidr_block #keeping this static according to assignment
    gateway_id = aws_internet_gateway.internet_gateway.id
  }
  tags = {
    Name = var.route_table_name # route_table would be created with this name
  }
}

# Associate subnets to the route table
resource "aws_route_table_association" "route" {
  count          = var.subnet_zone_count
  subnet_id      = element(aws_subnet.subnet.*.id, count.index)
  route_table_id = aws_route_table.route_table.id
}

#AWS Security group 
resource "aws_security_group" "application_security_group" {
  vpc_id = aws_vpc.vpc.id
  name   = "application"

  # allow ingress of port 22
  # ingress {
  #   cidr_blocks = var.ingressCIDRblock 
  #   from_port   = 22
  #   to_port     = 22
  #   protocol    = "tcp"

  # }

  # allow ingress of port 80
  # ingress {
  #  /* cidr_blocks = var.ingressCIDRblock */
  #   from_port   = 80
  #   to_port     = 80
  #   protocol    = "tcp"
  #   security_groups = [aws_security_group.loadBalancer.id]
  # }

  # allow ingress of port 443
  ingress {
    /* cidr_blocks = var.ingressCIDRblock */
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.loadBalancer.id]
  }

  ingress {
    description     = "TLS from VPC"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.loadBalancer.id]
    // cidr_blocks = var.ingressCIDRblock

  }

  # allow egress of all ports
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = var.egressCIDRblock
  }


  tags = {
    Name = "application"
  }
}


#AWS Security group for MySql
resource "aws_security_group" "database" {
  name        = var.database_security_group_name
  description = "Allow MySQL inbound traffic"
  vpc_id      = aws_vpc.vpc.id

  ingress {
    description = "MySQL"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"

    security_groups = [
      aws_security_group.application_security_group.id,
    ]
  }
  # allow all outgoing traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "database"
  }

}


resource "aws_s3_bucket" "s3_bucket" {
  bucket        = var.s3_bucket_name
  acl           = "private"
  force_destroy = true

  lifecycle_rule {
    id      = "log"
    enabled = true
    prefix  = "log/"
    tags = {
      "rule"      = "log"
      "autoclean" = "true"
    }
    transition {
      days          = 30
      storage_class = "STANDARD_IA" # or "ONEZONE_IA"
    }
  }
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "aws:kms"
      }
    }
  }
  tags = {
    Name        = "S3 bucket"
    Environment = "dev"
  }
}

#RDS
resource "aws_db_subnet_group" "rds_subnet_group" {
  name       = var.subnet_group_name
  subnet_ids = aws_subnet.subnet.*.id
}

resource "aws_db_instance" "rds_instance" {
  engine                 = "mysql"
  engine_version         = "8.0.17"
  instance_class         = var.db_instance_class
  multi_az               = false
  identifier             = var.db_identifier
  username               = var.db_username
  password               = var.db_password
  port                   = var.db_port
  db_subnet_group_name   = aws_db_subnet_group.rds_subnet_group.name
  publicly_accessible    = false
  name                   = var.db_name
  vpc_security_group_ids = [aws_security_group.database.id]
  parameter_group_name   = "rds-mysql"
  # attach security group to RDS instance
  allocated_storage   = 20
  storage_type        = "gp2"
  skip_final_snapshot = true
  storage_encrypted   = true
  kms_key_id          = aws_kms_key.rds_key.arn
  depends_on          = [aws_db_parameter_group.default]
}

resource "aws_iam_instance_profile" "s3_profile" {
  name = var.s3_iam_profile_name
  role = aws_iam_role.role.name
}

resource "aws_iam_role" "role" {
  name               = var.s3_iam_role_name
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow"
    }
  ]
}
EOF

  tags = {
    Name = "CodeDeployEC2ServiceRole"
  }
}

resource "aws_iam_policy" "policy" {
  name        = var.s3_iam_policy_name
  description = "IAM policy for EC2 to access S3 bucket"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": 
  [
    {
        "Effect": "Allow",
        "Action": [
            "s3:PutObject",
            "s3:PutObjectAcl",
            "s3:GetObject",
            "s3:GetObjectAcl",
            "s3:GetObjectVersion",
            "s3:DeleteObject",
            "s3:DeleteObjectVersion"
        ],
        "Resource": [
          "arn:aws:s3:::${var.s3_bucket_name}",
          "arn:aws:s3:::${var.s3_bucket_name}/*"
          ]
        
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "role-policy-attach" {
  role       = aws_iam_role.role.name
  policy_arn = aws_iam_policy.policy.arn
}

data "aws_ami" "ami" {
  most_recent = true
  owners      = var.ami_owners
}

# resource "aws_instance" "web" {
#   ami                    = data.aws_ami.ami.id
#   instance_type          = "t2.micro"
#   subnet_id              = aws_subnet.subnet[0].id
#   vpc_security_group_ids = aws_security_group.application_security_group.*.id
#   key_name               = var.key_name
#     associate_public_ip_address = true
#   iam_instance_profile   = aws_iam_instance_profile.s3_profile.name
#   user_data = <<-EOF
#                #!/bin/bash
#                sudo echo export "Bucket_Name=${aws_s3_bucket.s3_bucket.bucket}" >> /etc/environment
#                sudo echo export "RDS_HOSTNAME=${aws_db_instance.rds_instance.address}" >> /etc/environment
#                sudo echo export "DBendpoint=${aws_db_instance.rds_instance.endpoint}" >> /etc/environment
#                sudo echo export "RDS_DB_NAME=${aws_db_instance.rds_instance.name}" >> /etc/environment
#                sudo echo export "RDS_USERNAME=${aws_db_instance.rds_instance.username}" >> /etc/environment
#                sudo echo export "RDS_PASSWORD=${aws_db_instance.rds_instance.password}" >> /etc/environment

#                EOF

#   root_block_device {
#     volume_type = "gp2"
#     volume_size = 20
#     delete_on_termination = true
#   }
#   depends_on = [aws_s3_bucket.s3_bucket,aws_db_instance.rds_instance]

#   tags = {
#     Name = var.ec2_name
#   }
# }

# Create policy for Codedeploy running on EC2 to access s3 bucket
resource "aws_iam_role_policy" "codeDeploy_ec2_s3" {
  name = "CodeDeploy-EC2-S3"
  role = aws_iam_role.role.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:Get*",
        "s3:List*"
      ],
      "Effect": "Allow",
      "Resource": [
        "arn:aws:s3:::codedeploy.${var.aws_profile_name}.${var.domain_name}",
        "arn:aws:s3:::codedeploy.${var.aws_profile_name}.${var.domain_name}/*"
      ]
    }
  ]
}
EOF
}

# Create policy for ghaction user to upload to s3
resource "aws_iam_policy" "gh_upload_to_s3_policy" {
  name   = "GH-Upload-To-S3"
  policy = <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                  "s3:Get*",
                  "s3:List*",
                  "s3:PutObject"
            ],
            "Resource": [
                "arn:aws:s3:::codedeploy.${var.aws_profile_name}.${var.domain_name}",
                "arn:aws:s3:::codedeploy.${var.aws_profile_name}.${var.domain_name}/*"
              ]
        }
    ]
}
EOF
}

# Create policy for ghaction user to access codedeploy
resource "aws_iam_policy" "gh_code_deploy_policy" {
  name   = "GH-Code-Deploy"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:RegisterApplicationRevision",
        "codedeploy:GetApplicationRevision"
      ],
      "Resource": [
        "arn:aws:codedeploy:${var.region}:${local.aws_user_account_id}:application:${aws_codedeploy_app.code_deploy_app.name}",
        "arn:aws:codedeploy:${var.region}:${local.aws_user_account_id}:application:${aws_codedeploy_app.lambda_code_deploy_app.name}"
      ]

    },
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:CreateDeployment",
        "codedeploy:GetDeployment"
      ],
      "Resource": [
         "arn:aws:codedeploy:${var.region}:${local.aws_user_account_id}:deploymentgroup:${aws_codedeploy_app.code_deploy_app.name}/${aws_codedeploy_deployment_group.code_deploy_deployment_group.deployment_group_name}",
         "arn:aws:codedeploy:${var.region}:${local.aws_user_account_id}:deploymentgroup:${aws_codedeploy_app.lambda_code_deploy_app.name}/${aws_codedeploy_deployment_group.lambda_code_deploy_deployment_group.deployment_group_name}"
      ]
    },
    {
      "Effect": "Allow",
      "Action": [
        "codedeploy:GetDeploymentConfig"
      ],
      "Resource": [
        "arn:aws:codedeploy:${var.region}:${local.aws_user_account_id}:deploymentconfig:CodeDeployDefault.OneAtATime",
        "arn:aws:codedeploy:${var.region}:${local.aws_user_account_id}:deploymentconfig:CodeDeployDefault.HalfAtATime",
        "arn:aws:codedeploy:${var.region}:${local.aws_user_account_id}:deploymentconfig:CodeDeployDefault.AllAtOnce",
        "arn:aws:codedeploy:${var.region}:${local.aws_user_account_id}:deploymentconfig:CodeDeployDefault.LambdaAllAtOnce"
      ]
    }
  ]
}
EOF
}


resource "aws_iam_user_policy_attachment" "ghactions_s3_policy_attach" {
  user       = "ghactions"
  policy_arn = aws_iam_policy.gh_upload_to_s3_policy.arn
}

resource "aws_iam_user_policy_attachment" "ghactions_codedeploy_policy_attach" {
  user       = "ghactions"
  policy_arn = aws_iam_policy.gh_code_deploy_policy.arn
}

# Create IAM role for codedeploy
resource "aws_iam_role" "code_deploy_role" {
  name = "CodeDeployServiceRole"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "codedeploy.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

# Codedeploy app
resource "aws_codedeploy_app" "code_deploy_app" {
  compute_platform = "Server"
  name             = "csye6225-webapp"
}

# Codedeply group
resource "aws_codedeploy_deployment_group" "code_deploy_deployment_group" {
  app_name               = aws_codedeploy_app.code_deploy_app.name
  deployment_group_name  = "csye6225-webapp-deployment"
  deployment_config_name = "CodeDeployDefault.OneAtATime"
  service_role_arn       = aws_iam_role.code_deploy_role.arn
  autoscaling_groups     = [aws_autoscaling_group.autoscaling.name]

  load_balancer_info {
    target_group_info {
      name = aws_lb_target_group.albTargetGroup.name
    }
  }

  ec2_tag_filter {
    key   = "Name"
    type  = "KEY_AND_VALUE"
    value = var.ec2_name
  }

  deployment_style {
    deployment_option = "WITHOUT_TRAFFIC_CONTROL"
    deployment_type   = "IN_PLACE"
  }

  auto_rollback_configuration {
    enabled = true
    events  = ["DEPLOYMENT_FAILURE"]
  }


  depends_on = [aws_codedeploy_app.code_deploy_app]
}

# Attach policy to CodeDeploy role
resource "aws_iam_role_policy_attachment" "AWSCodeDeployRole" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
  role       = aws_iam_role.code_deploy_role.name
}


# add/update the DNS record api.dev.yourdomainname.tld. to the public IP address of the EC2 instance 
data "aws_route53_zone" "selected" {
  name         = "${var.aws_profile_name}.${var.dns}"
  private_zone = false
}

# resource "aws_route53_record" "www" {
#   zone_id = data.aws_route53_zone.selected.zone_id
#   name    = data.aws_route53_zone.selected.name
#   type    = "A"
#   ttl     = "60"
#   records = [aws_instance.web.public_ip]
# }

resource "aws_route53_record" "www" {
  zone_id = data.aws_route53_zone.selected.zone_id
  name    = data.aws_route53_zone.selected.name
  type    = "A"

  alias {
    name                   = aws_lb.application-Load-Balancer.dns_name
    zone_id                = aws_lb.application-Load-Balancer.zone_id
    evaluate_target_health = true
  }
}

resource "aws_iam_role_policy_attachment" "AmazonCloudWatchAgent" {
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
  role       = aws_iam_role.role.name
}


resource "aws_iam_role_policy_attachment" "AmazonSSMAgent" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  role       = aws_iam_role.role.name
}


resource "aws_launch_configuration" "as_conf" {
  name                        = "asg_launch_config"
  image_id                    = data.aws_ami.ami.id
  instance_type               = "t2.micro"
  security_groups             = [aws_security_group.application_security_group.id]
  key_name                    = var.key_name
  iam_instance_profile        = aws_iam_instance_profile.s3_profile.name
  associate_public_ip_address = true
  user_data                   = <<-EOF
               #!/bin/bash
               sudo echo export "Bucket_Name=${aws_s3_bucket.s3_bucket.bucket}" >> /etc/environment
               sudo echo export "RDS_HOSTNAME=${aws_db_instance.rds_instance.address}" >> /etc/environment
               sudo echo export "DBendpoint=${aws_db_instance.rds_instance.endpoint}" >> /etc/environment
               sudo echo export "RDS_DB_NAME=${aws_db_instance.rds_instance.name}" >> /etc/environment
               sudo echo export "RDS_USERNAME=${aws_db_instance.rds_instance.username}" >> /etc/environment
               sudo echo export "RDS_PASSWORD=${aws_db_instance.rds_instance.password}" >> /etc/environment
               sudo echo export "PROFILE_AWS=${var.aws_profile_name}">> /etc/environment
               sudo echo export "NAME_DOMAIN=${var.dns}" >> /etc/environment
               sudo echo export "SNS_TOPIC_ARN=${aws_sns_topic.sns_email.arn}" >> /etc/environment
               sudo echo export "DYNAMO_DB_TABLE=${var.dynamo_dbname}" >> /etc/environment
               EOF

  root_block_device {
    volume_type           = "gp2"
    volume_size           = 20
    delete_on_termination = true
    encrypted             = true
  }
  depends_on = [aws_s3_bucket.s3_bucket, aws_db_instance.rds_instance]
}


#Autoscaling Group
resource "aws_autoscaling_group" "autoscaling" {
  name                 = "autoscaling-group"
  launch_configuration = aws_launch_configuration.as_conf.name
  min_size             = 3
  max_size             = 5
  default_cooldown     = 60
  desired_capacity     = 3
  vpc_zone_identifier  = aws_subnet.subnet.*.id
  target_group_arns    = [aws_lb_target_group.albTargetGroup.arn]
  tag {
    key                 = "Name"
    value               = var.ec2_name
    propagate_at_launch = true
  }
}
# load balancer target group
resource "aws_lb_target_group" "albTargetGroup" {
  name     = "albTargetGroup"
  port     = "8080"
  protocol = "HTTP"
  vpc_id   = aws_vpc.vpc.id
  tags = {
    name = "albTargetGroup"
  }
  health_check {
    healthy_threshold   = 3
    unhealthy_threshold = 5
    timeout             = 5
    interval            = 30
    path                = "/healthstatus"
    port                = "8080"
    matcher             = "200"
  }
}

#Autoscalling Policy
resource "aws_autoscaling_policy" "WebServerScaleUpPolicy" {
  name                   = "WebServerScaleUpPolicy"
  adjustment_type        = "ChangeInCapacity"
  autoscaling_group_name = aws_autoscaling_group.autoscaling.name
  cooldown               = 60
  scaling_adjustment     = 1
}

resource "aws_autoscaling_policy" "WebServerScaleDownPolicy" {
  name                   = "WebServerScaleDownPolicy"
  adjustment_type        = "ChangeInCapacity"
  autoscaling_group_name = aws_autoscaling_group.autoscaling.name
  cooldown               = 60
  scaling_adjustment     = -1
}

resource "aws_cloudwatch_metric_alarm" "CPUAlarmLow" {
  alarm_description  = "Scale-down if CPU < 70% for 10 minutes"
  metric_name        = "CPUUtilization"
  namespace          = "AWS/EC2"
  statistic          = "Average"
  period             = var.alarm_low_period
  evaluation_periods = var.alarm_low_evaluation_period
  threshold          = var.alarm_low_threshold
  alarm_name         = "CPUAlarmLow"
  alarm_actions      = [aws_autoscaling_policy.WebServerScaleDownPolicy.arn]
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.autoscaling.name
  }
  comparison_operator = "LessThanThreshold"


}

resource "aws_cloudwatch_metric_alarm" "CPUAlarmHigh" {
  alarm_description  = "Scale-up if CPU > 90% for 10 minutes"
  metric_name        = "CPUUtilization"
  namespace          = "AWS/EC2"
  statistic          = "Average"
  period             = var.alarm_high_period
  evaluation_periods = var.alarm_high_evaluation_period
  threshold          = var.alarm_high_threshold
  alarm_name         = "CPUAlarmHigh"
  alarm_actions      = [aws_autoscaling_policy.WebServerScaleUpPolicy.arn]
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.autoscaling.name
  }
  comparison_operator = "GreaterThanThreshold"


}



#Load Balancer Security Group
resource "aws_security_group" "loadBalancer" {
  name   = "loadBalance_security_group"
  vpc_id = aws_vpc.vpc.id
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  #   ingress {
  #   from_port   = 80
  #   to_port     = 80
  #   protocol    = "tcp"
  #   cidr_blocks = ["0.0.0.0/0"]
  # }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name        = "LoadBalancer Security Group"
    Environment = var.aws_profile_name
  }
}


#Load balancer
resource "aws_lb" "application-Load-Balancer" {
  name               = "application-Load-Balancer"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.loadBalancer.id]
  subnets            = aws_subnet.subnet.*.id
  ip_address_type    = "ipv4"
  tags = {
    Environment = var.aws_profile_name
    Name        = "applicationLoadBalancer"
  }
}

resource "aws_lb_listener" "webapp-Listener" {
  load_balancer_arn = aws_lb.application-Load-Balancer.arn
  port              = "443"
  protocol          = "HTTPS"
  certificate_arn   = data.aws_acm_certificate.aws_ssl_certificate.arn
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.albTargetGroup.arn
  }
}


#SNS topic and policies
resource "aws_sns_topic" "sns_email" {
  name = "email_request"
}

resource "aws_sns_topic_policy" "sns_email_policy" {
  arn    = aws_sns_topic.sns_email.arn
  policy = data.aws_iam_policy_document.sns-topic-policy.json
}

data "aws_iam_policy_document" "sns-topic-policy" {
  policy_id = "__default_policy_ID"

  statement {
    actions = [
      "SNS:Subscribe",
      "SNS:SetTopicAttributes",
      "SNS:RemovePermission",
      "SNS:Receive",
      "SNS:Publish",
      "SNS:ListSubscriptionsByTopic",
      "SNS:GetTopicAttributes",
      "SNS:DeleteTopic",
      "SNS:AddPermission",
    ]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceOwner"

      values = [
        local.aws_user_account_id,
      ]
    }

    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    resources = [
      aws_sns_topic.sns_email.arn,
    ]

    sid = "__default_statement_ID"
  }
}

# IAM policy for SNS
resource "aws_iam_policy" "sns_iam_policy" {
  name   = "ec2_iam_policy"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "SNS:Publish"
      ],
       "Resource": "${aws_sns_topic.sns_email.arn}"
    }
  ]
}
EOF
}

# Attach the SNS topic policy to the EC2 role
resource "aws_iam_role_policy_attachment" "ec2_instance_sns" {
  policy_arn = aws_iam_policy.sns_iam_policy.arn
  role       = aws_iam_role.role.name
}


resource "aws_iam_policy" "ghactions-lambda-policy" {
  name   = "ghAction_s3_policy_lambda"
  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "lambda:*"
        ],
        
      "Resource": "arn:aws:lambda:${var.region}:${local.aws_user_account_id}:function:${aws_lambda_function.sns_lambda_email.function_name}"
    }
  ]
}
EOF
}

resource "aws_iam_user_policy_attachment" "ghactions_aws_lambda_policy_attach" {
  user       = "ghactions"
  policy_arn = aws_iam_policy.ghactions-lambda-policy.arn
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "index.js"
  output_path = "lambda_function.zip"
}


resource "aws_s3_bucket_object" "object" {
  bucket     = "codedeploy.${var.aws_profile_name}.${var.domain_name}"
  key        = "lambda_function.zip"
  source     = "./lambda_function.zip"
  depends_on = [data.archive_file.lambda_zip]
}

resource "aws_lambda_function" "sns_lambda_email" {
  s3_bucket     = "codedeploy.${var.aws_profile_name}.${var.domain_name}"
  s3_key        = "lambda_function.zip"
  function_name = "lambda_function_name"
  role          = aws_iam_role.iam_for_lambda.arn
  handler       = "index.handler"
  runtime       = "nodejs10.x"
  publish       = true
  environment {
    variables = {
      timeToLive = "5"
      tableName  = var.dynamo_dbname

    }
  }
  depends_on = [aws_s3_bucket_object.object]
}

resource "aws_sns_topic_subscription" "lambda" {
  topic_arn = aws_sns_topic.sns_email.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.sns_lambda_email.arn
}

resource "aws_lambda_permission" "lambda_sns" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.sns_lambda_email.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.sns_email.arn
}


#Lambda Policy
resource "aws_iam_policy" "aws_lambda_policy" {
  name        = "aws_lambda_policy"
  description = "Lambda Policy for dynamo ses and cloudwatch logs"
  policy      = <<EOF
{
   "Version": "2012-10-17",
   "Statement": [
       {
           "Effect": "Allow",
           "Action": [
               "logs:CreateLogGroup",
               "logs:CreateLogStream",
               "logs:PutLogEvents"
           ],
           "Resource": "*"
       },
       {
         "Sid": "LambdaDynamoDBAccess",
         "Effect": "Allow",
         "Action": [
             "dynamodb:GetItem",
             "dynamodb:PutItem",
             "dynamodb:UpdateItem",
             "dynamodb:Scan"
         ],
         "Resource": "arn:aws:dynamodb:${var.region}:${local.aws_user_account_id}:table/${var.dynamo_dbname}"
       },
       {
         "Sid": "LambdaSESAccess",
         "Effect": "Allow",
         "Action": [
             "ses:VerifyEmailAddress",
             "ses:SendEmail",
             "ses:SendRawEmail"
         ],
         "Resource": "*"
       }
   ]
}
 EOF
}

resource "aws_iam_role" "iam_for_lambda" {
  name = "iam_for_lambda"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
EOF
}

#attach lambda policy with lambda role
resource "aws_iam_role_policy_attachment" "attach_lambda_policy_to_lambda_role" {
  role       = aws_iam_role.iam_for_lambda.name
  policy_arn = aws_iam_policy.aws_lambda_policy.arn
}

resource "aws_dynamodb_table" "dynamodb-table" {

  name           = var.dynamo_dbname
  read_capacity  = var.dynamo_read_capacity
  write_capacity = var.dynamo_write_capacity
  hash_key       = "id"

  attribute {
    name = "id"
    type = "S"
  }
  tags = {
    Name = var.dynamo_dbname
  }

}


# Create IAM role for lambda codedeploy
resource "aws_iam_role" "lambda_code_deploy_role" {
  name = "LambdaCodeDeployServiceRole"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "codedeploy.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

# Lambda Codedeploy app
resource "aws_codedeploy_app" "lambda_code_deploy_app" {
  compute_platform = "Lambda"
  name             = "csye6225-lambda"
}

# Codedeply group for Lambda
resource "aws_codedeploy_deployment_group" "lambda_code_deploy_deployment_group" {
  app_name               = aws_codedeploy_app.lambda_code_deploy_app.name
  deployment_group_name  = "csye6225-lambda-deployment"
  deployment_config_name = "CodeDeployDefault.LambdaAllAtOnce"
  service_role_arn       = aws_iam_role.lambda_code_deploy_role.arn

  deployment_style {
    deployment_option = "WITH_TRAFFIC_CONTROL"
    deployment_type   = "BLUE_GREEN"
  }

  depends_on = [aws_codedeploy_app.lambda_code_deploy_app]
}

# Attach policy to Lambda CodeDeploy role
resource "aws_iam_role_policy_attachment" "AWSLambdaCodeDeployRole" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRoleForLambda"
  role       = aws_iam_role.lambda_code_deploy_role.name
}

# Create policy for Lambda Codedeploy to access s3 bucket
resource "aws_iam_role_policy" "lambda_codeDeploy_s3" {
  name = "Lambda_CodeDeploy_S3"
  role = aws_iam_role.lambda_code_deploy_role.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:Get*",
        "s3:List*"
      ],
      "Effect": "Allow",
      "Resource": [
        "arn:aws:s3:::codedeploy.${var.aws_profile_name}.${var.domain_name}",
        "arn:aws:s3:::codedeploy.${var.aws_profile_name}.${var.domain_name}/*"
      ]
    }
  ]
}
EOF
}

# Create alias for Lambda
resource "aws_lambda_alias" "lambda_alias" {
  name             = "lamda_deployment"
  function_name    = aws_lambda_function.sns_lambda_email.arn
  function_version = aws_lambda_function.sns_lambda_email.version
}


# rds parameter group to turn the performance_schema on 

resource "aws_db_parameter_group" "default" {
  name   = "rds-mysql"
  family = "mysql8.0"

  parameter {
    name         = "performance_schema"
    value        = true
    apply_method = "pending-reboot"
  }
}

data "aws_acm_certificate" "aws_ssl_certificate" {
  domain   = "${var.aws_profile_name}.${var.dns}"
  statuses = ["ISSUED"]
}

resource "aws_kms_key" "ebs_key" {
  description             = "ebs_block_key"
  deletion_window_in_days = 10
  policy                  = <<EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
              "Sid": "Enable IAM User Permissions",
              "Effect": "Allow",
              "Principal": {
                  "AWS": "arn:aws:iam::${local.aws_user_account_id}:root"
              },
              "Action": "kms:*",
              "Resource": "*"
      },
      {
        "Sid": "Allow service-linked role use of the CMK",
        "Effect": "Allow",
        "Principal": {
            "AWS": [
                "arn:aws:iam::${local.aws_user_account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
            ]
        },
        "Action": [
            "kms:Encrypt",
            "kms:Decrypt",
            "kms:ReEncrypt*",
            "kms:GenerateDataKey*",
            "kms:DescribeKey"
        ],
        "Resource": "*"
      },
      {
        "Sid": "Allow attachment of persistent resources",
        "Effect": "Allow",
        "Principal": {
            "AWS": [
                "arn:aws:iam::${local.aws_user_account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
            ]
        },
        "Action": [
            "kms:CreateGrant"
        ],
        "Resource": "*",
        "Condition": {
            "Bool": {
                "kms:GrantIsForAWSResource": true
            }
          }
      }
    ]
  }
  EOF

  tags = {
    Name = "ebs_key"
  }
}

resource "aws_ebs_default_kms_key" "example" {
  key_arn = aws_kms_key.ebs_key.arn
}


resource "aws_kms_key" "rds_key" {
  description             = "rds_key"
  deletion_window_in_days = 10
}