# Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
# Author: Madhukar Beema, Distinguished Engineer

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.small"
}

variable "key_name" {
  description = "SSH key pair name"
  type        = string
  default     = "mbaws-20262"
}

variable "vpc_id" {
  description = "VPC ID"
  type        = string
  default     = "vpc-06bb43e9b5d8c7410"
}

variable "subnet_id" {
  description = "Subnet ID"
  type        = string
  default     = "subnet-01d8a14cba67409db"
}
