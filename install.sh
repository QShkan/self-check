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

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check Python installation and version
check_python() {
    if command_exists python3; then
        PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
        MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
        MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)

        if [ "$MAJOR" -ge 3 ] && [ "$MINOR" -ge 6 ]; then
            print_status "Python $PYTHON_VERSION found"
            return 0
        else
            print_error "Python 3.6+ required, found $PYTHON_VERSION"
            return 1
        fi
    else
        print_error "Python3 not found"
        return 1
    fi
}

# Install Python dependencies with fallback methods
install_python_deps() {
    print_status "Installing Python dependencies..."

    # Try pip3 first
    if command_exists pip3; then
        if pip3 install --user psutil; then
            print_status "psutil installed successfully via pip3"
            return 0
        fi
    fi

    # Try pip if pip3 fails
    if command_exists pip; then
        if pip install --user psutil; then
            print_status "psutil installed successfully via pip"
            return 0
        fi
    fi

    # Try system package manager as fallback
    if command -v apt &> /dev/null; then
        sudo apt install -y python3-psutil
    elif command -v yum &> /dev/null; then
        sudo yum install -y python3-psutil
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y python3-psutil
    elif command -v pacman &> /dev/null; then
        sudo pacman -S --noconfirm python-psutil
    elif command -v apk &> /dev/null; then
        sudo apk add --no-cache py3-psutil
    else
        print_error "Could not install psutil. Please install manually:"
        print_error "  pip3 install psutil"
        print_error "  or install python3-psutil via your system package manager"
        return 1
    fi
}

# Detect package manager and install dependencies
install_dependencies() {
    print_status "Checking and installing dependencies..."

    # Install system packages first
    if command -v apt &> /dev/null; then
        # Debian/Ubuntu
        print_status "Detected Debian/Ubuntu system"
        sudo apt update
        sudo apt install -y python3 python3-pip python3-venv curl wget

        # Install additional tools for security monitoring
        sudo apt install -y net-tools lsof procps coreutils util-linux

    elif command -v yum &> /dev/null; then
        # RHEL/CentOS 7
        print_status "Detected RHEL/CentOS system"
        sudo yum install -y python3 python3-pip curl wget
        sudo yum install -y net-tools lsof procps-ng coreutils util-linux

    elif command -v dnf &> /dev/null; then
        # Fedora/RHEL 8+
        print_status "Detected Fedora/RHEL 8+ system"
        sudo dnf install -y python3 python3-pip curl wget
        sudo dnf install -y net-tools lsof procps-ng coreutils util-linux

    elif command -v pacman &> /dev/null; then
        # Arch Linux
        print_status "Detected Arch Linux system"
        sudo pacman -Sy
        sudo pacman -S --noconfirm python python-pip curl wget
        sudo pacman -S --noconfirm net-tools lsof procps-ng coreutils util-linux

    elif command -v apk &> /dev/null; then
        # Alpine Linux
        print_status "Detected Alpine Linux system"
        sudo apk update
        sudo apk add --no-cache python3 py3-pip curl wget
        sudo apk add --no-cache net-tools lsof procps coreutils util-linux

    elif command -v zypper &> /dev/null; then
        # openSUSE
        print_status "Detected openSUSE system"
        sudo zypper refresh
        sudo zypper install -y python3 python3-pip curl wget
        sudo zypper install -y net-tools lsof procps coreutils util-linux

    else
        print_warning "Package manager not detected. Supported systems:"
        print_warning "  - Debian/Ubuntu (apt)"
        print_warning "  - RHEL/CentOS/Fedora (yum/dnf)"
        print_warning "  - Arch Linux (pacman)"
        print_warning "  - Alpine Linux (apk)"
        print_warning "  - openSUSE (zypper)"
        print_warning ""
        print_warning "Please install manually:"
        print_warning "  - python3 (version 3.6+)"
        print_warning "  - python3-pip"
        print_warning "  - Standard Linux utilities (net-tools, lsof, procps)"

        # Still try to continue if Python is available
        if ! check_python; then
            print_error "Cannot continue without Python 3.6+"
            exit 1
        fi
    fi

    # Verify Python installation
    if ! check_python; then
        print_error "Python installation failed or version too old"
        exit 1
    fi

    # Install Python dependencies
    if ! install_python_deps; then
        print_error "Failed to install Python dependencies"
        exit 1
    fi

    # Verify psutil installation
    if python3 -c "import psutil" 2>/dev/null; then
        print_status "All dependencies installed successfully"
    else
        print_error "psutil installation verification failed"
        print_error "Please install manually: pip3 install psutil"
        exit 1
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

    # Check system requirements
    print_status "Checking system requirements..."

    # Check if running on supported architecture
    ARCH=$(uname -m)
    case $ARCH in
        x86_64|amd64|aarch64|armv7l|armv6l)
            print_status "Supported architecture detected: $ARCH"
            ;;
        *)
            print_warning "Untested architecture: $ARCH (may still work)"
            ;;
    esac

    # Check available disk space (need at least 50MB)
    AVAILABLE_SPACE=$(df /tmp | tail -1 | awk '{print $4}')
    if [ "$AVAILABLE_SPACE" -lt 51200 ]; then
        print_warning "Low disk space in /tmp (${AVAILABLE_SPACE}KB available)"
        print_warning "Self-check requires ~10MB for caching and logs"
    fi

    # Check if systemd is available
    if ! command_exists systemctl; then
        print_warning "systemd not detected. Automatic scheduling will not be available."
        print_warning "You can still run the script manually or use cron for scheduling."
        SKIP_SYSTEMD=true
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
    print_status "2. Set up environment variables for email (copy and edit .env.example)"
    print_status "3. Test the installation: sudo /usr/local/bin/self-check.py"

    if [ "$SKIP_SYSTEMD" != "true" ]; then
        print_status "4. Check service status: sudo systemctl status self-check.timer"
        print_status "5. View logs: sudo journalctl -u self-check.service -f"
    else
        print_status "4. Check cron installation: sudo crontab -l"
        print_status "5. View logs: sudo tail -f /var/log/self-check.log"
    fi

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