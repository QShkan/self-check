# Self-Check System Monitor

A comprehensive system monitoring script for performance, resources, and security checks. Designed to work across multiple architectures including Raspberry Pi, with email notifications for critical issues.

## Features

- **Performance Monitoring**: CPU usage, memory usage, load average, swap usage
- **Resource Monitoring**: Disk space, network connectivity
- **Advanced Security Monitoring**:
  - Failed login attempts detection
  - Suspicious network connections monitoring
  - Unexpected reboot detection
  - Unusual process identification
  - Open ports scanning
  - SSH key permissions validation
  - System updates tracking
- **Temperature Monitoring**: System temperature (especially useful for Raspberry Pi)
- **Service Monitoring**: Critical system services status
- **Email Notifications**: HTML-formatted alerts for critical issues
- **Cross-Architecture Support**: Works on x86, ARM, Raspberry Pi, and other architectures
- **Performance Optimized**: Intelligent caching and lightweight execution for frequent monitoring
- **Configurable Thresholds**: Customizable warning and critical levels

## Requirements

### System Requirements
- **Operating System**: Linux (any distribution)
- **Architecture**: x86_64, ARM, AArch64 (including Raspberry Pi)
- **Python**: 3.6 or higher
- **Privileges**: Root/sudo access for comprehensive monitoring
- **Disk Space**: ~50MB for installation and caching

### Dependencies

**Required:**
- `python3` (3.6+)
- `psutil` Python library
- Standard Linux utilities (`ps`, `df`, `free`, etc.)

**Optional (enhances monitoring):**
- `systemctl` - for systemd service management
- `netstat`/`lsof` - for network monitoring
- `last` - for reboot history
- System log files (`/var/log/auth.log`, `/var/log/syslog`)

### Dependency Check

Before installation, verify all requirements:
```bash
python3 check-requirements.py
```

This will check your system and provide specific installation commands if anything is missing.

## Installation

### Quick Installation

```bash
# Clone the repository
git clone https://github.com/bk86a/self-check.git
cd self-check

# Check system requirements
python3 check-requirements.py

# Install dependencies (if needed)
pip3 install psutil

# Make the script executable
chmod +x self-check.py

# Create initial configuration
python3 self-check.py --create-config
```

### System-wide Installation

```bash
# Run the installation script
sudo ./install.sh

# This will:
# - Install the script to /usr/local/bin/
# - Install dependencies
# - Set up systemd service for automated checks
# - Create configuration in /etc/self-check/
```

## Configuration

Edit `config.json` to customize thresholds and enable email notifications:

### Port Whitelisting

To prevent false positives for legitimate services, add ports to the whitelist:

```json
{
  "security": {
    "whitelist_ports": [
      22,    // SSH
      80,    // HTTP
      443,   // HTTPS
      53,    // DNS
      25,    // SMTP
      111,   // RPC portmapper
      631,   // CUPS printing
      5432,  // PostgreSQL
      3306,  // MySQL
      6379,  // Redis
      27017  // MongoDB
    ]
  }
}
```

### Basic Configuration

```json
{
  "thresholds": {
    "cpu_usage": 85.0,
    "memory_usage": 90.0,
    "disk_usage": 90.0,
    "temperature": 75.0,
    "swap_usage": 50.0
  },
  "email": {
    "enabled": true,
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "username": "your-email@gmail.com",
    "password": "your-app-password",
    "from_email": "your-email@gmail.com",
    "to_email": "admin@yourdomain.com",
    "use_tls": true
  },
  "checks": {
    "performance": true,
    "resources": true,
    "security": true,
    "temperature": true,
    "services": true
  },
  "services": {
    "critical_services": ["ssh", "cron", "networking"]
  },
  "security": {
    "check_reboots": true,
    "check_suspicious_connections": true,
    "check_unusual_processes": true,
    "whitelist_ips": ["127.0.0.1", "::1"],
    "whitelist_ports": [22, 80, 443, 53, 25],
    "max_failed_logins": 10,
    "reboot_check_hours": 24
  }
}
```

### Email Configuration

Configure email notifications using environment variables (recommended) or config file:

#### Using Environment Variables (Recommended)

```bash
# Copy the example environment file
cp .env.example .env

# Edit with your email settings
nano .env
```

Set these environment variables:
```bash
export SMTP_SERVER=smtp.gmail.com
export SMTP_PORT=587
export SMTP_USER=your-email@gmail.com
export SMTP_PASSWORD=your-app-password
export EMAIL_FROM=your-email@gmail.com
export EMAIL_TO=admin@example.com
```

#### Gmail Setup

For Gmail accounts:
1. Enable 2-factor authentication on your Google account
2. Generate an app password (not your regular password)
3. Use the app password as `SMTP_PASSWORD`
4. Configure `EMAIL_TO` with your desired notification email address

#### Enable Email Notifications

Set `"enabled": true` in the email section of config.json:
```json
{
  "email": {
    "enabled": true,
    "use_env_vars": true
  }
}
```

## Usage

### Manual Execution

```bash
# Basic check
python3 self-check.py

# Use custom config file
python3 self-check.py --config /path/to/config.json

# Save results to JSON file
python3 self-check.py --output results.json

# Quiet mode (no console output)
python3 self-check.py --quiet

# Create default configuration file
python3 self-check.py --create-config
```

### Automated Execution

#### Using Cron

Add to your crontab (`crontab -e`):

```bash
# Run every 5 minutes (recommended for security monitoring)
*/5 * * * * /usr/bin/python3 /path/to/self-check.py --quiet

# Run every 15 minutes with email notifications
*/15 * * * * /usr/bin/python3 /path/to/self-check.py --config /etc/self-check/config.json
```

#### Using Systemd Timer (Recommended)

If you used the installation script, the systemd service is already configured:

```bash
# Check service status
sudo systemctl status self-check.timer
sudo systemctl status self-check.service

# View logs
sudo journalctl -u self-check.service -f

# Restart the timer
sudo systemctl restart self-check.timer

# Check execution frequency
sudo systemctl list-timers | grep self-check
```

## Monitored Parameters

### Performance
- CPU usage percentage
- Memory usage (RAM)
- System load average
- Swap usage

### Resources
- Disk usage per partition
- Internet connectivity
- Network interface statistics

### Security
- **Failed login attempts** (from auth.log with configurable threshold)
- **Enhanced network monitoring**:
  - Foreign IP connections with process identification
  - Unusual ports with detailed process information (name, PID, user, command line)
  - Smart whitelisting for known safe processes (browsers, updates, etc.)
- **Unexpected system reboots** (detects unplanned restarts)
- **Unusual processes** (new processes not in baseline, high CPU usage)
- **Smart port monitoring**:
  - Detailed process information for all listening ports
  - Configurable port whitelisting
  - Automatic detection of common system services
- **SSH key file permissions** (ensures proper security)
- **Available system updates** (tracks pending security patches)

### Temperature
- System temperature sensors
- Raspberry Pi CPU temperature (via `/sys/class/thermal/`)

### Services
- Critical systemd service status
- Custom service monitoring

## Architecture Support

The script automatically detects and adapts to different architectures:

- **x86/x64**: Full feature support with all security monitoring
- **ARM/Raspberry Pi**: Enhanced monitoring with temperature sensors and lightweight execution
- **Other architectures**: Core functionality with graceful feature degradation

### Performance Optimization

The script is designed for frequent execution (every 5 minutes) with minimal resource impact:

- **Intelligent Caching**: Results cached for 5 minutes to reduce system calls
- **Baseline Learning**: Establishes normal process patterns to detect anomalies
- **Lightweight Execution**: Typically completes in under 10 seconds
- **Resource Monitoring**: Self-monitors execution time and warns if taking too long

### Raspberry Pi Specific Features

- CPU temperature monitoring via thermal zone
- Optimized thresholds for ARM processors
- Memory usage adapted for smaller RAM configurations

## Output

### Console Output
```
System Self-Check Report - 2024-01-15 14:30:25
============================================================
Hostname: raspberry-pi
Platform: Linux-6.1.21-v8+-aarch64-with-glibc2.36
Architecture: aarch64

CRITICAL ISSUES:
--------------------
• [Performance] High CPU usage: 92.3%
• [Resources] High disk usage on /: 94.2%

PERFORMANCE:
------------
CPU Usage: 92.3%
Memory Usage: 67.8%
Swap Usage: 0.0%
Load Average: 1.23

RESOURCES:
----------
Disk /: 94.2% used
Disk /boot: 23.1% used
Internet: Connected

TEMPERATURE:
------------
CPU Temperature: 68.5°C
```

### JSON Output
Use `--output results.json` to save detailed results in JSON format for further processing.

## Exit Codes

- `0`: All checks passed
- `1`: Critical issues found
- `130`: Interrupted by user (Ctrl+C)

## Logging

Logs are written to `/var/log/self-check.log` (requires write permissions).

## Troubleshooting

### System Requirements Issues

**Python version too old:**
```bash
# Check Python version
python3 --version

# Install newer Python (Ubuntu/Debian)
sudo apt update
sudo apt install python3.8 python3.8-pip
sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.8 1
```

**Missing psutil library:**
```bash
# Try different installation methods
pip3 install psutil
# OR
sudo apt install python3-psutil  # Debian/Ubuntu
sudo yum install python3-psutil  # RHEL/CentOS
sudo dnf install python3-psutil  # Fedora
```

**Missing system utilities:**
```bash
# Install essential monitoring tools
sudo apt install net-tools lsof procps  # Debian/Ubuntu
sudo yum install net-tools lsof procps-ng  # RHEL/CentOS
```

### Permission Issues
Some security checks require elevated privileges:
```bash
sudo python3 self-check.py
```

### Architecture-Specific Issues

**Raspberry Pi:**
- Temperature monitoring requires access to `/sys/class/thermal/`
- Some monitoring commands may have different output formats
- Performance thresholds may need adjustment for ARM processors

**Minimal/Container Systems:**
- Some log files may not exist (`/var/log/auth.log`)
- System utilities might be missing (install `procps`, `net-tools`)
- SELinux/AppArmor may restrict access to system information

### Email Not Working
1. Check SMTP settings in config.json
2. Verify firewall allows SMTP traffic (port 587/465)
3. For Gmail, ensure app passwords are used (not regular password)
4. Test email configuration:
   ```bash
   python3 -c "import smtplib; print('SMTP module available')"
   ```

### Service Installation Issues

**systemd not available:**
- Script will automatically fall back to cron
- Manual scheduling: `crontab -e` and add the cron job

**Permission denied during installation:**
```bash
# Ensure sudo access
sudo ./install.sh

# Check if user is in sudo group
groups $USER
```

### Performance Issues

**Script running too slowly:**
- Enable lightweight mode in config.json
- Increase cache timeout to reduce system calls
- Check system load during execution

**High resource usage:**
- Adjust monitoring frequency (increase timer interval)
- Disable unnecessary checks in configuration
- Monitor execution time in logs

### Debugging

**Enable debug mode:**
```json
{
  "debug": true,
  "performance": {
    "lightweight_mode": false
  }
}
```

**Check logs:**
```bash
# System logs
sudo journalctl -u self-check.service -f

# Application logs
sudo tail -f /var/log/self-check.log

# Test run with verbose output
sudo python3 self-check.py --config config.json
```

### Getting Help

1. Run the requirements checker: `python3 check-requirements.py`
2. Test basic functionality: `python3 self-check.py --create-config`
3. Check [GitHub Issues](https://github.com/bk86a/self-check/issues) for similar problems
4. Include system information when reporting issues:
   ```bash
   uname -a
   python3 --version
   pip3 list | grep psutil
   ```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Security Considerations

- Store email passwords securely (consider using environment variables)
- Limit access to configuration files containing credentials
- Run with minimal required privileges
- Review open port warnings carefully
- Keep the system updated based on update check results

## Changelog

### v1.0.0
- Initial release
- Core monitoring functionality
- Email notifications
- Cross-architecture support
- Systemd integration
