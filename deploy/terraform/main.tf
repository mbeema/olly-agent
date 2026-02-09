terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region  = var.aws_region
  profile = "default"
}

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_security_group" "olly_demo" {
  name        = "olly-demo-sg"
  description = "Security group for Olly demo EC2 instance"
  vpc_id      = var.vpc_id

  # SSH
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Flask demo app
  ingress {
    from_port   = 5000
    to_port     = 5000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # OTLP gRPC
  ingress {
    from_port   = 4317
    to_port     = 4317
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # OTLP HTTP
  ingress {
    from_port   = 4318
    to_port     = 4318
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # All outbound
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "olly-demo-sg"
  }
}

resource "aws_instance" "olly_demo" {
  ami                         = data.aws_ami.al2023.id
  instance_type               = var.instance_type
  key_name                    = var.key_name
  subnet_id                   = var.subnet_id
  vpc_security_group_ids      = [aws_security_group.olly_demo.id]
  associate_public_ip_address = true

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }

  user_data = <<-EOF
    #!/bin/bash
    set -ex

    # Install dependencies
    dnf update -y
    dnf install -y gcc make git postgresql16-server postgresql16

    # Install Go 1.23
    curl -Lo /tmp/go.tar.gz https://go.dev/dl/go1.23.4.linux-amd64.tar.gz
    tar -C /usr/local -xzf /tmp/go.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile.d/go.sh
    source /etc/profile.d/go.sh

    # Install Python + pip
    dnf install -y python3 python3-pip

    # Install OTEL Collector
    curl -Lo /tmp/otelcol.rpm https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v0.96.0/otelcol-contrib_0.96.0_linux_amd64.rpm
    rpm -i /tmp/otelcol.rpm || true

    # Setup PostgreSQL
    postgresql-setup --initdb
    systemctl enable postgresql
    systemctl start postgresql

    # Create demo database and user
    sudo -u postgres psql -c "CREATE USER demo WITH PASSWORD 'demo123';"
    sudo -u postgres psql -c "CREATE DATABASE demo OWNER demo;"

    # Configure PostgreSQL: md5 auth for localhost (required for demo user)
    PG_HBA=$(sudo -u postgres psql -t -c "SHOW hba_file;" | tr -d ' ')
    sed -i '/^host.*all.*all.*127.0.0.1\/32.*ident/i host    all    all    127.0.0.1/32    md5' "$PG_HBA"
    systemctl reload postgresql

    # Create directories
    mkdir -p /var/run/olly /var/log/demo-app /var/log/otel /opt/olly/configs
    chmod 777 /var/log/otel

    echo "User data complete" > /tmp/user-data-done
  EOF

  tags = {
    Name = "olly-demo"
  }
}
