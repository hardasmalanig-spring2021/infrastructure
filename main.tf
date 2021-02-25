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
  type = number
  default = 3
  description = "Number of subnet zones to be created"
}

variable "start" {
  type = number
  default = 0
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

# VPC
resource "aws_vpc" "vpc" {
    cidr_block = var.cidr_block
    enable_dns_hostnames = true
    enable_dns_support = true
    enable_classiclink_dns_support = true
    assign_generated_ipv6_cidr_block = false  
    tags = {
      Name = var.vpc_name
    }
}

# Subnets
resource "aws_subnet" "subnet" {
  count = var.subnet_zone_count
  cidr_block = "10.${var.start}.${10+count.index}.0/24"
  vpc_id = aws_vpc.vpc.id
  availability_zone = data.aws_availability_zones.available.names[count.index]
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
    cidr_block = var.route_table_cidr_block  #keeping this static according to assignment
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