#!/bin/bash

# Self-Check System Monitor Installation Script
# This script installs the self-check system monitor and sets up automated monitoring

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    print_error "This script should not be run as root. Run as regular user with sudo access."
    exit 1
fi

# Check for sudo access
if ! sudo -v; then
    print_error "This script requires sudo access. Please run as a user with sudo privileges."
    exit 1
fi

print_status "Starting Self-Check System Monitor installation..."

# Detect package manager and install dependencies
install_dependencies() {
    print_status "Installing dependencies..."

    if command -v apt &> /dev/null; then
        # Debian/Ubuntu
        sudo apt update
        sudo apt install -y python3 python3-pip
        pip3 install --user psutil
    elif command -v yum &> /dev/null; then
        # RHEL/CentOS
        sudo yum install -y python3 python3-pip
        pip3 install --user psutil
    elif command -v dnf &> /dev/null; then
        # Fedora
        sudo dnf install -y python3 python3-pip
        pip3 install --user psutil
    elif command -v pacman &> /dev/null; then
        # Arch Linux
        sudo pacman -S --noconfirm python python-pip
        pip3 install --user psutil
    elif command -v apk &> /dev/null; then
        # Alpine Linux
        sudo apk add --no-cache python3 py3-pip
        pip3 install --user psutil
    else
        print_warning "Package manager not detected. Please install python3, pip3, and psutil manually."
        print_warning "Then run: pip3 install psutil"
    fi
}

# Install the main script
install_script() {
    print_status "Installing self-check script..."

    # Make script executable
    chmod +x self-check.py

    # Copy to system location
    sudo cp self-check.py /usr/local/bin/
    sudo chmod +x /usr/local/bin/self-check.py

    print_status "Script installed to /usr/local/bin/self-check.py"
}

# Install configuration
install_config() {
    print_status "Installing configuration..."

    # Create configuration directory
    sudo mkdir -p /etc/self-check

    # Copy configuration file
    if [[ ! -f /etc/self-check/config.json ]]; then
        sudo cp config.json /etc/self-check/
        print_status "Configuration installed to /etc/self-check/config.json"
        print_warning "Please edit /etc/self-check/config.json to configure email notifications and thresholds"
    else
        print_warning "Configuration file already exists at /etc/self-check/config.json"
        print_warning "Backup created as /etc/self-check/config.json.backup"
        sudo cp /etc/self-check/config.json /etc/self-check/config.json.backup
        sudo cp config.json /etc/self-check/config.json.new
    fi
}

# Install systemd service
install_systemd_service() {
    print_status "Installing systemd service..."

    # Copy service files
    sudo cp self-check.service /etc/systemd/system/
    sudo cp self-check.timer /etc/systemd/system/

    # Reload systemd
    sudo systemctl daemon-reload

    # Enable and start the timer
    sudo systemctl enable self-check.timer
    sudo systemctl start self-check.timer

    print_status "Systemd service installed and enabled"
    print_status "Self-check will run every 15 minutes"
}

# Create log directory
setup_logging() {
    print_status "Setting up logging..."

    # Create log file with proper permissions
    sudo touch /var/log/self-check.log
    sudo chmod 644 /var/log/self-check.log

    # Set up log rotation
    sudo tee /etc/logrotate.d/self-check > /dev/null <<EOF
/var/log/self-check.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    copytruncate
}
EOF

    print_status "Logging configured"
}

# Main installation process
main() {
    print_status "Self-Check System Monitor Installer"
    print_status "====================================="

    # Check if we're in the right directory
    if [[ ! -f "self-check.py" ]]; then
        print_error "self-check.py not found. Please run this script from the self-check directory."
        exit 1
    fi

    # Install dependencies
    install_dependencies

    # Install script
    install_script

    # Install configuration
    install_config

    # Setup logging
    setup_logging

    # Install systemd service
    install_systemd_service

    print_status "Installation completed successfully!"
    print_status ""
    print_status "Next steps:"
    print_status "1. Edit /etc/self-check/config.json to configure email notifications"
    print_status "2. Test the installation: sudo /usr/local/bin/self-check.py"
    print_status "3. Check service status: sudo systemctl status self-check.timer"
    print_status "4. View logs: sudo journalctl -u self-check.service -f"
    print_status ""
    print_status "The system will automatically run checks every 15 minutes."
    print_status "Critical issues will be sent via email if configured."
}

# Run uninstaller if requested
if [[ "$1" == "uninstall" ]]; then
    print_warning "Uninstalling Self-Check System Monitor..."

    # Stop and disable service
    sudo systemctl stop self-check.timer 2>/dev/null || true
    sudo systemctl disable self-check.timer 2>/dev/null || true

    # Remove files
    sudo rm -f /etc/systemd/system/self-check.service
    sudo rm -f /etc/systemd/system/self-check.timer
    sudo rm -f /usr/local/bin/self-check.py
    sudo rm -f /etc/logrotate.d/self-check

    # Reload systemd
    sudo systemctl daemon-reload

    print_status "Self-Check System Monitor uninstalled"
    print_warning "Configuration files in /etc/self-check/ and logs were preserved"
    print_warning "To remove completely: sudo rm -rf /etc/self-check /var/log/self-check.log"

    exit 0
fi

# Show help if requested
if [[ "$1" == "help" || "$1" == "-h" || "$1" == "--help" ]]; then
    echo "Self-Check System Monitor Installer"
    echo ""
    echo "Usage:"
    echo "  ./install.sh          Install the system monitor"
    echo "  ./install.sh uninstall Remove the system monitor"
    echo "  ./install.sh help     Show this help message"
    echo ""
    exit 0
fi

# Run main installation
main