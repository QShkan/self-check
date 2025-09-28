#!/usr/bin/env python3
"""
Self-Check Requirements Checker
Verifies that all required dependencies are available before running the main script.
"""

import sys
import subprocess
import platform
import os
from typing import List, Tuple

def check_python_version() -> bool:
    """Check if Python version is 3.6 or higher"""
    version = sys.version_info
    if version.major >= 3 and version.minor >= 6:
        print(f"✓ Python {version.major}.{version.minor}.{version.micro} (OK)")
        return True
    else:
        print(f"✗ Python {version.major}.{version.minor}.{version.micro} (requires 3.6+)")
        return False

def check_module(module_name: str) -> bool:
    """Check if a Python module is available"""
    try:
        __import__(module_name)
        print(f"✓ {module_name} module (OK)")
        return True
    except ImportError:
        print(f"✗ {module_name} module (missing)")
        return False

def check_command(command: str) -> bool:
    """Check if a system command is available"""
    try:
        result = subprocess.run(['which', command], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"✓ {command} command (OK)")
            return True
        else:
            print(f"✗ {command} command (missing)")
            return False
    except:
        print(f"✗ {command} command (check failed)")
        return False

def check_file_permissions(file_path: str) -> bool:
    """Check if a file exists and is readable"""
    if os.path.exists(file_path):
        if os.access(file_path, os.R_OK):
            print(f"✓ {file_path} (readable)")
            return True
        else:
            print(f"⚠ {file_path} (exists but not readable)")
            return False
    else:
        print(f"ℹ {file_path} (not found - optional)")
        return True  # Optional files are OK if missing

def get_installation_commands() -> List[str]:
    """Get installation commands based on the detected system"""
    system = platform.system().lower()

    if os.path.exists('/etc/debian_version'):
        return [
            "sudo apt update",
            "sudo apt install -y python3 python3-pip python3-psutil",
            "sudo apt install -y net-tools lsof procps coreutils util-linux"
        ]
    elif os.path.exists('/etc/redhat-release') or os.path.exists('/etc/centos-release'):
        if check_command('dnf'):
            return [
                "sudo dnf install -y python3 python3-pip python3-psutil",
                "sudo dnf install -y net-tools lsof procps-ng coreutils util-linux"
            ]
        else:
            return [
                "sudo yum install -y python3 python3-pip python3-psutil",
                "sudo yum install -y net-tools lsof procps-ng coreutils util-linux"
            ]
    elif os.path.exists('/etc/arch-release'):
        return [
            "sudo pacman -Sy python python-pip python-psutil",
            "sudo pacman -S net-tools lsof procps-ng coreutils util-linux"
        ]
    elif os.path.exists('/etc/alpine-release'):
        return [
            "sudo apk add python3 py3-pip py3-psutil",
            "sudo apk add net-tools lsof procps coreutils util-linux"
        ]
    else:
        return [
            "# Install using your system's package manager:",
            "# python3 python3-pip python3-psutil",
            "# net-tools lsof procps coreutils util-linux",
            "pip3 install psutil"
        ]

def main():
    """Main requirements checking function"""
    print("Self-Check System Monitor - Requirements Check")
    print("=" * 50)

    issues = []

    # Check Python version
    if not check_python_version():
        issues.append("Python 3.6+ required")

    # Check required Python modules
    required_modules = ['psutil', 'json', 'logging', 'smtplib', 'socket', 'subprocess']
    for module in required_modules:
        if not check_module(module):
            if module == 'psutil':
                issues.append("psutil module missing - install with: pip3 install psutil")
            else:
                issues.append(f"{module} module missing")

    # Check optional but recommended commands
    optional_commands = ['systemctl', 'journalctl', 'last', 'grep', 'netstat', 'lsof']
    missing_commands = []

    print("\nSystem Commands:")
    for cmd in optional_commands:
        if not check_command(cmd):
            missing_commands.append(cmd)

    # Check file permissions for common log files
    print("\nLog File Access:")
    log_files = ['/var/log/auth.log', '/var/log/secure', '/var/log/syslog', '/var/log/messages']
    for log_file in log_files:
        check_file_permissions(log_file)

    # Check system information
    print(f"\nSystem Information:")
    print(f"✓ OS: {platform.system()} {platform.release()}")
    print(f"✓ Architecture: {platform.machine()}")
    print(f"✓ Platform: {platform.platform()}")

    # Summary
    print("\n" + "=" * 50)
    if issues:
        print("❌ ISSUES FOUND:")
        for issue in issues:
            print(f"   • {issue}")

        print(f"\n📦 INSTALLATION COMMANDS:")
        for cmd in get_installation_commands():
            print(f"   {cmd}")

        if missing_commands:
            print(f"\n⚠️  MISSING OPTIONAL COMMANDS:")
            print(f"   {', '.join(missing_commands)}")
            print("   These commands enhance monitoring capabilities but are not required.")

        print(f"\n🔧 After installing dependencies, run:")
        print(f"   python3 {__file__}")

        sys.exit(1)
    else:
        print("✅ ALL REQUIREMENTS SATISFIED")
        if missing_commands:
            print(f"\n⚠️  OPTIONAL COMMANDS MISSING: {', '.join(missing_commands)}")
            print("   Install these for enhanced monitoring capabilities.")
        print("\n🚀 Ready to run self-check.py")
        sys.exit(0)

if __name__ == '__main__':
    main()