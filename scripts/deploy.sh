#!/bin/bash

# SAGAR AdaptiveAuth Framework - Production Deployment Script
set -e  # Exit on any error

echo "🚀 Starting SAGAR AdaptiveAuth Framework Deployment..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
APP_NAME="adaptiveauth"
APP_DIR="/opt/${APP_NAME}"
BACKUP_DIR="/opt/backups/${APP_NAME}"
LOG_DIR="/var/log/${APP_NAME}"

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${RED}❌ This script should NOT be run as root${NC}"
   exit 1
fi

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
print_status "Checking prerequisites..."

if ! command -v git &> /dev/null; then
    print_error "Git is not installed"
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is not installed"
    exit 1
fi

if ! command -v pip3 &> /dev/null; then
    print_error "Pip is not installed"
    exit 1
fi

# Check if .env file exists
if [ ! -f ".env" ]; then
    print_warning ".env file not found. Copying from .env.example..."
    cp .env.example .env
    print_status "Please configure your .env file before proceeding!"
    exit 1
fi

print_status "Prerequisites check passed!"

# Create app directory if it doesn't exist
if [ ! -d "$APP_DIR" ]; then
    print_status "Creating application directory: $APP_DIR"
    sudo mkdir -p $APP_DIR
    sudo chown $USER:$USER $APP_DIR
fi

# Create log directory
if [ ! -d "$LOG_DIR" ]; then
    print_status "Creating log directory: $LOG_DIR"
    sudo mkdir -p $LOG_DIR
    sudo chown $USER:$USER $LOG_DIR
fi

# Backup current deployment if it exists
if [ -d "$APP_DIR/current" ]; then
    print_status "Creating backup of current deployment..."
    TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    BACKUP_PATH="${BACKUP_DIR}/${TIMESTAMP}"
    mkdir -p $BACKUP_PATH
    cp -r $APP_DIR/current/* $BACKUP_PATH/ || true
    print_status "Backup created at: $BACKUP_PATH"
fi

# Install/update dependencies
print_status "Installing/updating dependencies..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements-production.txt

# Copy current code to deployment directory
print_status "Deploying application files..."
rsync -av --exclude='venv' --exclude='.git' --exclude='__pycache__' . $APP_DIR/current/

# Set proper permissions
chmod +x $APP_DIR/current/*.sh
chmod +x $APP_DIR/current/*.py

# Create/update systemd service file
SERVICE_FILE="/etc/systemd/system/adaptiveauth.service"
print_status "Creating/updating systemd service..."

sudo tee $SERVICE_FILE > /dev/null <<EOF
[Unit]
Description=SAGAR AdaptiveAuth Framework
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$APP_DIR/current
EnvironmentFile=$APP_DIR/current/.env
ExecStart=$APP_DIR/current/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8080 --workers 4 --timeout-keep-alive 30
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
print_status "Reloading systemd configuration..."
sudo systemctl daemon-reload

# Stop current service if running
if sudo systemctl is-active --quiet adaptiveauth; then
    print_status "Stopping current service..."
    sudo systemctl stop adaptiveauth
fi

# Start the service
print_status "Starting AdaptiveAuth service..."
sudo systemctl start adaptiveauth

# Enable service on boot
print_status "Enabling service on boot..."
sudo systemctl enable adaptiveauth

# Wait a moment for service to start
sleep 3

# Check service status
if sudo systemctl is-active --quiet adaptiveauth; then
    print_status "✅ AdaptiveAuth service is running!"
else
    print_error "❌ AdaptiveAuth service failed to start!"
    sudo systemctl status adaptiveauth --no-pager -l
    exit 1
fi

# Health check
print_status "Performing health check..."
if curl -f http://localhost:8080/health >/dev/null 2>&1; then
    print_status "✅ Health check passed!"
else
    print_warning "⚠️ Health check failed - service may still be starting up"
fi

# Print deployment info
print_status "📋 Deployment Summary:"
echo "   Application Path: $APP_DIR/current"
echo "   Service Status: $(sudo systemctl is-active adaptiveauth)"
echo "   Port: 8080"
echo "   Health Check: http://localhost:8080/health"
echo "   API Docs: http://localhost:8080/docs"
echo "   Admin Interface: http://localhost:8080/static/index.html"

print_status "🎉 SAGAR AdaptiveAuth Framework deployed successfully!"
echo ""
echo "💡 Next Steps:"
echo "   - Configure firewall to allow traffic on port 8080 (if needed)"
echo "   - Set up SSL certificate for HTTPS (recommended)"
echo "   - Configure reverse proxy (nginx/Apache) for production use"
echo "   - Monitor logs: journalctl -u adaptiveauth -f"