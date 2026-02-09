#!/bin/bash
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

# Unpack
cd /tmp
tar xzf olly-deploy.tar.gz
sudo mkdir -p /opt/olly/configs /opt/olly/demo-app /var/run/olly /var/log/demo-app /var/log/otel
sudo chmod 777 /var/log/otel

# Install binary and configs
sudo cp olly-deploy/olly /opt/olly/
sudo chmod +x /opt/olly/olly
sudo cp olly-deploy/configs/*.yaml /opt/olly/configs/

# Compile libolly.so on target (C can't be cross-compiled — needs target glibc)
gcc -shared -fPIC -O2 -o /tmp/libolly.so olly-deploy/libolly.c -ldl -lpthread
sudo cp /tmp/libolly.so /opt/olly/libolly.so

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

# Install Python deps (as root — app runs as root with LD_PRELOAD)
sudo pip3 install -r olly-deploy/demo-app/requirements.txt
sudo cp -r olly-deploy/demo-app /opt/olly/demo-app

# Create wrapper script for demo app with LD_PRELOAD
# (env vars don't propagate reliably through sudo bash -c)
sudo tee /opt/olly/run-demo.sh > /dev/null <<'WRAPPER'
#!/bin/bash
export LD_PRELOAD=/opt/olly/libolly.so
exec python3 /opt/olly/demo-app/app.py
WRAPPER
sudo chmod +x /opt/olly/run-demo.sh

# Start olly agent first (creates hook.sock for libolly.so)
sudo bash -c 'nohup /opt/olly/olly --config-dir /opt/olly/configs --log-level debug > /var/log/olly.log 2>&1 &'
sleep 2

# Start demo app via wrapper (LD_PRELOAD for hook interception)
sudo bash -c 'nohup /opt/olly/run-demo.sh > /var/log/demo-app/stdout.log 2>&1 &'
sleep 3

echo "=== Deployment complete ==="
echo "Demo app: http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):5000"
echo "Olly agent PID: $(pgrep -x olly || echo 'not running')"
echo "Demo app PID:   $(pgrep -x python3 || echo 'not running')"
REMOTE_SCRIPT

echo ""
echo "=== Deployment finished ==="
echo "SSH:  $SSH_CMD"
echo "Demo: http://$EC2_IP:5000"
echo ""
echo "Next steps:"
echo "  1. Run: deploy/generate_traffic.sh"
echo "  2. Run: deploy/verify.sh"
