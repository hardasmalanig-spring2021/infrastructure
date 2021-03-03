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

variable "aws_launch_configuration_name" { # required
  type = string
}


# VPC
resource "aws_vpc" "vpc" {
  cidr_block                       = var.cidr_block
  enable_dns_hostnames             = true
  enable_dns_support               = true
  enable_classiclink_dns_support   = true
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
  ingress {
    cidr_blocks = var.ingressCIDRblock
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
  }

  # allow ingress of port 80
  ingress {
    cidr_blocks = var.ingressCIDRblock
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
  }

  # allow ingress of port 443
  ingress {
    cidr_blocks = var.ingressCIDRblock
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
  }

  ingress {
    description = "TLS from VPC"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = var.ingressCIDRblock

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
    prefix = "log/"
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
        sse_algorithm     = "aws:kms"
      }
    }
  }
  tags = {
    Name = "S3 bucket"
    # Environment = "dev"
  }
}

#RDS
resource "aws_db_subnet_group" "rds_subnet_group" {
  name       = var.subnet_group_name
  subnet_ids = aws_subnet.subnet.*.id
}

resource "aws_db_parameter_group" "db_parameter_ssl" {
  name   = "rds-mysql-ssl"
  family = "mysql5.7"

  parameter {
    name         = "performance_schema"
    value        = "1"
    apply_method = "pending-reboot"
  }
}

resource "aws_db_instance" "rds_instance" {
  engine                 = "mysql"
  engine_version         = "5.7"
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

  # attach security group to RDS instance
  allocated_storage    = 20
  storage_type         = "gp2"
  parameter_group_name = aws_db_parameter_group.db_parameter_ssl.name
  skip_final_snapshot = true
  storage_encrypted  = true
  ca_cert_identifier = "rds-ca-2019"
}

# resource "aws_launch_configuration" "launch_conf" {
#    name = var.aws_launch_configuration_name
#  }
