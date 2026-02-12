# Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
# Author: Madhukar Beema, Distinguished Engineer

output "instance_id" {
  description = "EC2 instance ID"
  value       = aws_instance.olly_demo.id
}

output "public_ip" {
  description = "Public IP address of the EC2 instance"
  value       = aws_instance.olly_demo.public_ip
}

output "ssh_command" {
  description = "SSH command to connect to the instance"
  value       = "ssh -i ~/.ssh/mbaws-20262.pem ec2-user@${aws_instance.olly_demo.public_ip}"
}
