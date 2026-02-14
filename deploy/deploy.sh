#!/bin/bash
# Copyright 2024-2026 Madhukar Beema, Distinguished Engineer. All rights reserved.
# Author: Madhukar Beema, Distinguished Engineer
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DIST_DIR="$PROJECT_DIR/dist"
KEY_PATH="${SSH_KEY:-$HOME/.ssh/mbaws-20262.pem}"

# Get EC2 IP from Terraform
cd "$SCRIPT_DIR/terraform"
EC2_IP=$(terraform output -raw public_ip 2>/dev/null)
if [ -z "$EC2_IP" ]; then
    echo "ERROR: Could not get EC2 IP from Terraform. Run 'terraform apply' first."
    exit 1
fi

SSH_CMD="ssh -o StrictHostKeyChecking=no -i $KEY_PATH ec2-user@$EC2_IP"
SCP_CMD="scp -o StrictHostKeyChecking=no -i $KEY_PATH"

echo "=== Deploying to $EC2_IP ==="

# Wait for instance to be ready
echo "Waiting for SSH..."
for i in $(seq 1 30); do
    if $SSH_CMD "test -f /tmp/user-data-done" 2>/dev/null; then
        echo "Instance ready."
        break
    fi
    echo "  Attempt $i/30..."
    sleep 10
done

# Upload tarball
echo "Uploading package..."
$SCP_CMD "$DIST_DIR/olly-deploy.tar.gz" "ec2-user@$EC2_IP:/tmp/"

# Deploy on EC2
echo "Installing on EC2..."
$SSH_CMD <<'REMOTE_SCRIPT'
set -ex

# Ensure MySQL/MariaDB is installed (may not be on existing instances)
if ! command -v mysql &> /dev/null; then
    echo "Installing MariaDB..."
    sudo dnf install -y mariadb105-server
    sudo systemctl enable mariadb
    sudo systemctl start mariadb
    mysql -u root <<MYSQL_SETUP
    CREATE DATABASE IF NOT EXISTS inventory;
    CREATE USER IF NOT EXISTS 'demo'@'localhost' IDENTIFIED BY 'demo123';
    GRANT ALL PRIVILEGES ON inventory.* TO 'demo'@'localhost';
    FLUSH PRIVILEGES;
MYSQL_SETUP
fi

# Ensure Redis is running
sudo systemctl enable redis6
sudo systemctl start redis6

# Ensure MongoDB is running
sudo systemctl enable mongod
sudo systemctl start mongod

# Unpack
cd /tmp
tar xzf olly-deploy.tar.gz
# Install runtimes for cross-language demo services
if ! command -v javac &> /dev/null; then
    echo "Installing Java JDK (Corretto 17)..."
    sudo dnf install -y java-17-amazon-corretto-devel
fi
if ! command -v node &> /dev/null; then
    echo "Installing Node.js..."
    sudo dnf install -y nodejs npm
fi
if ! command -v dotnet &> /dev/null; then
    echo "Installing .NET 8 SDK..."
    sudo rpm --import https://packages.microsoft.com/keys/microsoft.asc
    sudo dnf install -y https://packages.microsoft.com/config/centos/9/packages-microsoft-prod.rpm 2>/dev/null || true
    sudo dnf install -y dotnet-sdk-8.0 || echo "WARN: .NET SDK install failed — pricing-service will be skipped"
fi

# Stop existing processes
sudo pkill -9 -x olly 2>/dev/null || true
sudo pkill -9 -f 'python3.*app.py' 2>/dev/null || true
sudo pkill -9 -x order-service 2>/dev/null || true
sudo pkill -9 -x mcp-server 2>/dev/null || true
sudo pkill -9 -f 'java.*CatalogService' 2>/dev/null || true
sudo pkill -9 -f 'pricing-service' 2>/dev/null || true
sudo pkill -9 -f 'node.*server.js' 2>/dev/null || true
sleep 3

# Clear old trace data for clean analysis
sudo rm -f /var/log/otel/traces.json /var/log/otel/metrics.json /var/log/otel/logs.json

sudo mkdir -p /opt/olly/configs /opt/olly/demo-app /var/run/olly /var/log/demo-app /var/log/otel
sudo chmod 777 /var/log/otel

# Install binary and configs
sudo cp olly-deploy/olly /opt/olly/
sudo chmod +x /opt/olly/olly
sudo cp olly-deploy/configs/*.yaml /opt/olly/configs/

# Setup OTEL Collector config
sudo cp olly-deploy/otel-collector.yaml /etc/otelcol-contrib/config.yaml
sudo systemctl enable otelcol-contrib
sudo systemctl restart otelcol-contrib

# Configure PostgreSQL: md5 auth for localhost (required for demo user)
PG_HBA=$(sudo -u postgres psql -t -c "SHOW hba_file;" | tr -d ' ')
# Insert md5 rule before the default ident rule
sudo sed -i '/^host.*all.*all.*127.0.0.1\/32.*ident/i host    all    all    127.0.0.1/32    md5' "$PG_HBA"
sudo systemctl reload postgresql

# Initialize demo database with schema + grants
sudo -u postgres psql -d demo -f olly-deploy/demo-app/init_db.sql || true

# Initialize MySQL inventory database
sudo mysql -u root -e "CREATE DATABASE IF NOT EXISTS inventory; CREATE USER IF NOT EXISTS 'demo'@'localhost' IDENTIFIED BY 'demo123'; GRANT ALL PRIVILEGES ON inventory.* TO 'demo'@'localhost'; FLUSH PRIVILEGES;" || true
sudo mysql -u root inventory < olly-deploy/demo-app/init_mysql.sql || true

# Install Python deps (as root — app runs as root)
sudo pip3 install -r olly-deploy/demo-app/requirements.txt

# Prepare cross-language services in tarball dir before copy
# Node.js: npm install in tarball so node_modules gets copied
if [ -d olly-deploy/demo-app/stock-service ]; then
    echo "Installing Node.js deps for stock-service..."
    cd olly-deploy/demo-app/stock-service
    npm install --production 2>/dev/null || true
    cd /tmp
fi

# Java: always recompile on EC2 to match local JDK version
if [ -d olly-deploy/demo-app/catalog-service ] && command -v javac &> /dev/null; then
    echo "Compiling Java catalog-service..."
    cd olly-deploy/demo-app/catalog-service
    javac CatalogService.java
    cd /tmp
fi

# Copy demo-app contents (use /. to merge into existing dir, not nest)
sudo rm -rf /opt/olly/demo-app/*
sudo cp -r olly-deploy/demo-app/. /opt/olly/demo-app/

# Start olly agent (eBPF hooks attach automatically — no LD_PRELOAD needed)
sudo bash -c 'nohup /opt/olly/olly --config-dir /opt/olly/configs --log-level debug > /var/log/olly.log 2>&1 &'
sleep 2

# Install order-service (Go microservice for cross-service tracing demo)
if [ -f olly-deploy/order-service ]; then
    sudo cp olly-deploy/order-service /opt/olly/order-service
    sudo chmod +x /opt/olly/order-service
    sudo bash -c 'nohup /opt/olly/order-service > /var/log/demo-app/order-service.log 2>&1 &'
    sleep 1
fi

# Install MCP server (Go MCP demo for MCP monitoring)
if [ -f olly-deploy/mcp-server ]; then
    sudo cp olly-deploy/mcp-server /opt/olly/mcp-server
    sudo chmod +x /opt/olly/mcp-server
    sudo bash -c 'nohup /opt/olly/mcp-server > /var/log/demo-app/mcp-server.log 2>&1 &'
    sleep 1
fi

# Start cross-language demo services (reverse dependency order)

# Node.js stock-service (leaf — depends on Redis + PostgreSQL)
if [ -d /opt/olly/demo-app/stock-service ]; then
    echo "Starting stock-service (Node.js)..."
    sudo bash -c 'SERVICE_NAME=stock-service nohup node /opt/olly/demo-app/stock-service/server.js > /var/log/demo-app/stock-service.log 2>&1 &'
    sleep 1
fi

# .NET pricing-service (depends on stock-service)
if [ -d olly-deploy/pricing-service-publish ]; then
    echo "Starting pricing-service (.NET self-contained)..."
    sudo mkdir -p /opt/olly/pricing-service
    sudo cp -r olly-deploy/pricing-service-publish/. /opt/olly/pricing-service/
    sudo chmod +x /opt/olly/pricing-service/pricing-service
    sudo bash -c 'SERVICE_NAME=pricing-service nohup /opt/olly/pricing-service/pricing-service > /var/log/demo-app/pricing-service.log 2>&1 &'
    sleep 1
elif [ -f /opt/olly/demo-app/pricing-service/Program.cs ] && command -v dotnet &> /dev/null; then
    echo "Building and starting pricing-service (.NET)..."
    cd /opt/olly/demo-app/pricing-service
    sudo dotnet publish -c Release -o /opt/olly/pricing-service 2>&1 || true
    cd /tmp
    if [ -f /opt/olly/pricing-service/pricing-service ]; then
        sudo bash -c 'SERVICE_NAME=pricing-service nohup /opt/olly/pricing-service/pricing-service > /var/log/demo-app/pricing-service.log 2>&1 &'
        sleep 1
    else
        echo "WARN: pricing-service build failed"
    fi
else
    echo "WARN: .NET SDK not available — skipping pricing-service"
fi

# Java catalog-service (depends on pricing-service)
if [ -f /opt/olly/demo-app/catalog-service/CatalogService.class ]; then
    echo "Starting catalog-service (Java)..."
    sudo bash -c 'SERVICE_NAME=catalog-service nohup java -Xmx128m -Xms64m -cp /opt/olly/demo-app/catalog-service CatalogService > /var/log/demo-app/catalog-service.log 2>&1 &'
    sleep 1
fi

# Start demo app (no wrapper needed — eBPF observes all processes automatically)
# Pass OPENAI_API_KEY if set on the host (for GenAI monitoring demo)
OPENAI_KEY_FILE="/opt/olly/.openai_key"
if [ -f "$OPENAI_KEY_FILE" ]; then
    OPENAI_KEY=$(cat "$OPENAI_KEY_FILE")
    sudo bash -c "OPENAI_API_KEY=$OPENAI_KEY nohup python3 /opt/olly/demo-app/app.py > /var/log/demo-app/stdout.log 2>&1 &"
else
    sudo bash -c 'nohup python3 /opt/olly/demo-app/app.py > /var/log/demo-app/stdout.log 2>&1 &'
fi
sleep 3

echo "=== Deployment complete ==="
echo "Demo app: http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):5000"
echo "Olly agent PID:     $(pgrep -x olly || echo 'not running')"
echo "Demo app PID:       $(pgrep -f 'python3.*app.py' || echo 'not running')"
echo "Order-service PID:  $(pgrep -x order-service || echo 'not running')"
echo "MCP-server PID:     $(pgrep -x mcp-server || echo 'not running')"
echo "Catalog-svc PID:    $(pgrep -f 'java.*CatalogService' || echo 'not running')"
echo "Pricing-svc PID:    $(pgrep -f 'pricing-service' || echo 'not running')"
echo "Stock-svc PID:      $(pgrep -f 'node.*server.js' || echo 'not running')"
REMOTE_SCRIPT

echo ""
echo "=== Deployment finished ==="
echo "SSH:  $SSH_CMD"
echo "Demo: http://$EC2_IP:5000"
echo ""
echo "Next steps:"
echo "  1. Run: deploy/generate_traffic.sh"
echo "  2. Run: deploy/verify.sh"
echo "  3. Run: ssh -i \$KEY_PATH ec2-user@$EC2_IP 'python3 /tmp/analyze_traces.py'  (trace linking quality)"
