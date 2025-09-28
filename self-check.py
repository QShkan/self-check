#!/usr/bin/env python3
"""
Self-Check System Monitor
A comprehensive system monitoring script for performance, resources, and security.
Supports multiple architectures including Raspberry Pi.
"""

import os
import sys
import json
import logging
import argparse
import platform
import subprocess
import smtplib
import socket
import time
import hashlib
import pickle
import re
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
import psutil

class SystemChecker:
    def __init__(self, config_path: str = "config.json"):
        self.config_path = config_path
        self.config = self.load_config()
        self.setup_logging()
        self.issues = []
        self.warnings = []
        self.cache_dir = Path("/tmp/self-check-cache")
        self.cache_dir.mkdir(exist_ok=True)
        self.state_file = self.cache_dir / "system_state.json"
        self.baseline_file = self.cache_dir / "baseline.json"
        self.previous_state = self.load_previous_state()

        # Performance optimization: cache heavy operations
        self._process_cache = {}
        self._network_cache = {}
        self._cache_timeout = 300  # 5 minutes

    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        default_config = {
            "thresholds": {
                "cpu_usage": 85.0,
                "memory_usage": 90.0,
                "disk_usage": 90.0,
                "load_average": None,  # Will be set based on CPU count
                "temperature": 75.0,
                "swap_usage": 50.0
            },
            "email": {
                "enabled": False,
                "smtp_server": "",
                "smtp_port": 587,
                "username": "",
                "password": "",
                "from_email": "",
                "to_email": "",
                "use_tls": True
            },
            "checks": {
                "performance": True,
                "resources": True,
                "security": True,
                "temperature": True,
                "services": True
            },
            "security": {
                "check_failed_logins": True,
                "check_open_ports": True,
                "check_updates": True,
                "check_ssh_keys": True,
                "check_reboots": True,
                "check_suspicious_connections": True,
                "check_unusual_processes": True,
                "suspicious_processes": [],
                "whitelist_ips": ["127.0.0.1", "::1"],
                "whitelist_ports": [22, 80, 443, 53],
                "max_failed_logins": 10,
                "reboot_check_hours": 24,
                "connection_monitoring": True
            },
            "services": {
                "critical_services": ["ssh", "cron"],
                "check_systemd": True
            }
        }

        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    user_config = json.load(f)
                    # Merge user config with defaults
                    self._merge_config(default_config, user_config)
            except Exception as e:
                print(f"Error loading config: {e}. Using defaults.")

        return default_config

    def _merge_config(self, default: Dict, user: Dict) -> None:
        """Recursively merge user config with defaults"""
        for key, value in user.items():
            if key in default and isinstance(default[key], dict) and isinstance(value, dict):
                self._merge_config(default[key], value)
            else:
                default[key] = value

    def setup_logging(self):
        """Setup logging configuration"""
        log_level = logging.INFO
        if self.config.get('debug', False):
            log_level = logging.DEBUG

        handlers = [logging.StreamHandler()]

        # Try to add file handler, fallback to temp if no permission
        log_files = ['/var/log/self-check.log', '/tmp/self-check.log', 'self-check.log']

        for log_file in log_files:
            try:
                handlers.append(logging.FileHandler(log_file))
                break
            except PermissionError:
                continue

        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=handlers
        )
        self.logger = logging.getLogger(__name__)

    def load_previous_state(self) -> Dict[str, Any]:
        """Load previous system state for comparison"""
        if self.state_file.exists():
            try:
                with open(self.state_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                self.logger.debug(f"Could not load previous state: {e}")
        return {}

    def save_current_state(self, current_state: Dict[str, Any]):
        """Save current system state for next comparison"""
        try:
            with open(self.state_file, 'w') as f:
                json.dump(current_state, f, indent=2)
        except Exception as e:
            self.logger.debug(f"Could not save current state: {e}")

    def is_cache_valid(self, cache_key: str) -> bool:
        """Check if cache entry is still valid"""
        cache_file = self.cache_dir / f"{cache_key}.cache"
        if not cache_file.exists():
            return False

        cache_age = time.time() - cache_file.stat().st_mtime
        return cache_age < self._cache_timeout

    def get_cache(self, cache_key: str) -> Any:
        """Get cached data if valid"""
        if not self.is_cache_valid(cache_key):
            return None

        cache_file = self.cache_dir / f"{cache_key}.cache"
        try:
            with open(cache_file, 'rb') as f:
                return pickle.load(f)
        except Exception:
            return None

    def set_cache(self, cache_key: str, data: Any):
        """Save data to cache"""
        cache_file = self.cache_dir / f"{cache_key}.cache"
        try:
            with open(cache_file, 'wb') as f:
                pickle.dump(data, f)
        except Exception as e:
            self.logger.debug(f"Could not save cache {cache_key}: {e}")

    def add_issue(self, category: str, description: str, severity: str = "critical"):
        """Add an issue to the list"""
        issue = {
            "category": category,
            "description": description,
            "severity": severity,
            "timestamp": datetime.now().isoformat()
        }

        if severity == "critical":
            self.issues.append(issue)
        else:
            self.warnings.append(issue)

        self.logger.warning(f"{severity.upper()}: [{category}] {description}")

    def check_performance(self) -> Dict[str, Any]:
        """Check system performance metrics"""
        results = {}

        # CPU Usage
        cpu_percent = psutil.cpu_percent(interval=1)
        results['cpu_usage'] = cpu_percent
        if cpu_percent > self.config['thresholds']['cpu_usage']:
            self.add_issue("Performance", f"High CPU usage: {cpu_percent:.1f}%")

        # Memory Usage
        memory = psutil.virtual_memory()
        results['memory'] = {
            'total': memory.total,
            'used': memory.used,
            'percent': memory.percent
        }
        if memory.percent > self.config['thresholds']['memory_usage']:
            self.add_issue("Performance", f"High memory usage: {memory.percent:.1f}%")

        # Load Average
        if hasattr(os, 'getloadavg'):
            load_avg = os.getloadavg()
            results['load_average'] = load_avg
            cpu_count = psutil.cpu_count()
            load_threshold = self.config['thresholds']['load_average'] or cpu_count * 0.8

            if load_avg[0] > load_threshold:
                self.add_issue("Performance", f"High load average: {load_avg[0]:.2f}")

        # Swap Usage
        swap = psutil.swap_memory()
        results['swap'] = {
            'total': swap.total,
            'used': swap.used,
            'percent': swap.percent
        }
        if swap.percent > self.config['thresholds']['swap_usage']:
            self.add_issue("Performance", f"High swap usage: {swap.percent:.1f}%")

        return results

    def check_resources(self) -> Dict[str, Any]:
        """Check system resources"""
        results = {}

        # Disk Usage
        disk_usage = []
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                percent = (usage.used / usage.total) * 100

                disk_info = {
                    'device': partition.device,
                    'mountpoint': partition.mountpoint,
                    'total': usage.total,
                    'used': usage.used,
                    'percent': percent
                }
                disk_usage.append(disk_info)

                # Skip snap packages (they're always 100% by design) and small partitions
                if (percent > self.config['thresholds']['disk_usage'] and
                    not partition.mountpoint.startswith('/snap/') and
                    usage.total > 100 * 1024 * 1024):  # Skip partitions smaller than 100MB
                    self.add_issue("Resources",
                                 f"High disk usage on {partition.mountpoint}: {percent:.1f}%")

            except PermissionError:
                continue

        results['disk_usage'] = disk_usage

        # Network interfaces
        network_stats = psutil.net_io_counters(pernic=True)
        results['network'] = network_stats

        # Check for network connectivity
        try:
            socket.create_connection(("8.8.8.8", 53), timeout=3)
            results['internet_connectivity'] = True
        except OSError:
            results['internet_connectivity'] = False
            self.add_issue("Resources", "No internet connectivity")

        return results

    def check_temperature(self) -> Dict[str, Any]:
        """Check system temperature (works with physical hardware, VMs, and containers)"""
        results = {}
        temp_found = False

        try:
            # Method 1: psutil sensors (works on physical hardware)
            if hasattr(psutil, 'sensors_temperatures'):
                temps = psutil.sensors_temperatures()
                if temps:
                    results['temperatures'] = temps
                    temp_found = True

                    for name, entries in temps.items():
                        for entry in entries:
                            if entry.current and entry.current > self.config['thresholds']['temperature']:
                                self.add_issue("Temperature",
                                             f"High temperature on {name}: {entry.current}°C")

            # Method 2: Raspberry Pi specific check
            if os.path.exists('/sys/class/thermal/thermal_zone0/temp'):
                with open('/sys/class/thermal/thermal_zone0/temp', 'r') as f:
                    temp = int(f.read().strip()) / 1000.0
                    results['rpi_temperature'] = temp
                    temp_found = True

                    if temp > self.config['thresholds']['temperature']:
                        self.add_issue("Temperature", f"High Raspberry Pi temperature: {temp}°C")

            # Method 3: Check thermal zones (works on many Linux systems)
            if not temp_found:
                thermal_zones = []
                for i in range(10):  # Check thermal_zone0 through thermal_zone9
                    zone_path = f'/sys/class/thermal/thermal_zone{i}/temp'
                    if os.path.exists(zone_path):
                        try:
                            with open(zone_path, 'r') as f:
                                temp = int(f.read().strip()) / 1000.0
                                zone_type_path = f'/sys/class/thermal/thermal_zone{i}/type'
                                zone_type = 'unknown'
                                if os.path.exists(zone_type_path):
                                    with open(zone_type_path, 'r') as f:
                                        zone_type = f.read().strip()

                                thermal_zones.append({'zone': f'thermal_zone{i}', 'type': zone_type, 'temp': temp})

                                if temp > self.config['thresholds']['temperature']:
                                    self.add_issue("Temperature",
                                                 f"High temperature in {zone_type}: {temp}°C")
                        except:
                            continue

                if thermal_zones:
                    results['thermal_zones'] = thermal_zones
                    temp_found = True

            # Method 4: VM/Container detection and host temperature (if available)
            vm_detected = self._detect_virtualization()
            if vm_detected:
                results['virtualization'] = vm_detected
                results['temperature_note'] = f"Running in {vm_detected['type']} - host temperature monitoring limited"

            # If no temperature data found, note this in results
            if not temp_found:
                results['temperature_note'] = "Temperature monitoring not available (VM/container or no sensors)"

        except Exception as e:
            self.logger.debug(f"Temperature check failed: {e}")

        return results

    def _detect_virtualization(self) -> Dict[str, str]:
        """Detect if running in a VM or container"""
        virt_info = {}

        try:
            # Check for common virtualization indicators
            if os.path.exists('/proc/cpuinfo'):
                with open('/proc/cpuinfo', 'r') as f:
                    cpuinfo = f.read()
                    if 'QEMU' in cpuinfo:
                        virt_info['type'] = 'QEMU/KVM'
                    elif 'VMware' in cpuinfo:
                        virt_info['type'] = 'VMware'
                    elif 'Microsoft' in cpuinfo:
                        virt_info['type'] = 'Hyper-V'

            # Check for container indicators
            if os.path.exists('/.dockerenv'):
                virt_info['type'] = 'Docker'
            elif os.path.exists('/proc/1/cgroup'):
                with open('/proc/1/cgroup', 'r') as f:
                    if 'docker' in f.read():
                        virt_info['type'] = 'Docker'

            # Check DMI information
            if os.path.exists('/sys/class/dmi/id/product_name'):
                with open('/sys/class/dmi/id/product_name', 'r') as f:
                    product = f.read().strip()
                    if 'QEMU' in product:
                        virt_info['type'] = 'QEMU/KVM'
                        virt_info['product'] = product

        except:
            pass

        return virt_info

    def check_security(self) -> Dict[str, Any]:
        """Check security-related issues"""
        results = {}

        if self.config['security']['check_failed_logins']:
            results['failed_logins'] = self._check_failed_logins()

        if self.config['security']['check_open_ports']:
            results['open_ports'] = self._check_open_ports()

        if self.config['security']['check_updates']:
            results['updates'] = self._check_updates()

        if self.config['security']['check_ssh_keys']:
            results['ssh_keys'] = self._check_ssh_keys()

        if self.config['security']['check_reboots']:
            results['unexpected_reboots'] = self._check_unexpected_reboots()

        if self.config['security']['check_suspicious_connections']:
            results['suspicious_connections'] = self._check_suspicious_connections()

        if self.config['security']['check_unusual_processes']:
            results['unusual_processes'] = self._check_unusual_processes()

        # New comprehensive security checks
        if self.config['security'].get('check_ssh_config', True):
            results['ssh_config'] = self._check_ssh_config()

        if self.config['security'].get('check_firewall', True):
            results['firewall'] = self._check_firewall_status()

        if self.config['security'].get('check_file_permissions', True):
            results['file_permissions'] = self._check_critical_file_permissions()

        if self.config['security'].get('check_system_hardening', True):
            results['system_hardening'] = self._check_system_hardening()

        return results

    def _check_failed_logins(self) -> List[str]:
        """Check for failed login attempts"""
        failed_logins = []

        try:
            # Check auth.log for failed login attempts
            auth_logs = ['/var/log/auth.log', '/var/log/secure']

            for log_file in auth_logs:
                if os.path.exists(log_file):
                    cmd = f"grep 'Failed password' {log_file} | tail -10"
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

                    if result.stdout:
                        failed_logins.extend(result.stdout.strip().split('\n'))

                        # Count recent failed attempts
                        recent_failures = len([line for line in failed_logins
                                             if 'Failed password' in line])

                        if recent_failures > 5:
                            self.add_issue("Security",
                                         f"Multiple failed login attempts: {recent_failures}")
                    break

        except Exception as e:
            self.logger.debug(f"Failed login check failed: {e}")

        return failed_logins

    def _check_open_ports(self) -> List[Dict]:
        """Check for open network ports with detailed process information"""
        open_ports = []

        try:
            connections = psutil.net_connections(kind='inet')
            listening_ports = []

            for conn in connections:
                if conn.status == 'LISTEN':
                    port_info = {
                        'port': conn.laddr.port,
                        'address': conn.laddr.ip,
                        'pid': conn.pid,
                        'process': 'unknown',
                        'cmdline': '',
                        'user': ''
                    }

                    if conn.pid:
                        try:
                            process = psutil.Process(conn.pid)
                            port_info['process'] = process.name()
                            port_info['cmdline'] = ' '.join(process.cmdline())
                            port_info['user'] = process.username()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            port_info['process'] = 'unknown'
                    else:
                        # Try to get process info from netstat if psutil fails
                        try:
                            netstat_info = self._get_port_process_netstat(conn.laddr.port)
                            if netstat_info:
                                port_info.update(netstat_info)
                        except:
                            pass

                    listening_ports.append(port_info)

            # Check for unexpected open ports using whitelist
            whitelisted_ports = set(self.config['security'].get('whitelist_ports', [22, 80, 443, 53]))
            expected_ports = set(self.config.get('expected_ports', [22, 80, 443]))
            all_allowed_ports = whitelisted_ports | expected_ports

            for port_info in listening_ports:
                port = port_info['port']
                if port not in all_allowed_ports:
                    # Additional filtering for very common system ports
                    if not self._is_system_port(port, port_info['process']):
                        process_details = self._format_process_details(port_info)
                        self.add_issue("Security",
                                     f"Unexpected open port {port}: {process_details}",
                                     "warning")

            open_ports = listening_ports

        except Exception as e:
            self.logger.debug(f"Open ports check failed: {e}")

        return open_ports

    def _get_port_process_netstat(self, port: int) -> dict:
        """Get process information for a port using netstat as fallback"""
        try:
            result = subprocess.run(['netstat', '-tlnp'], capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if f':{port} ' in line and 'LISTEN' in line:
                    parts = line.split()
                    if len(parts) >= 7:
                        process_info = parts[6]
                        if '/' in process_info:
                            pid, process_name = process_info.split('/', 1)
                            return {
                                'pid': int(pid) if pid.isdigit() else None,
                                'process': process_name
                            }
        except:
            pass

        # Try to identify service by port using systemctl
        service_info = self._identify_service_by_port(port)
        if service_info:
            return service_info

        return {}

    def _identify_service_by_port(self, port: int) -> dict:
        """Identify service by port using systemctl, Docker, and common port mappings"""

        # First, check for Docker containers using this port
        try:
            docker_info = self._check_docker_port(port)
            if docker_info:
                return docker_info
        except:
            pass

        # Common port to service mappings
        service_map = {
            111: 'rpcbind',
            631: 'cups',
            5432: 'postgresql',
            3306: 'mysql',
            22: 'ssh',
            80: 'apache2',
            443: 'apache2',
            5353: 'avahi-daemon',
            3551: 'apcupsd',
            5678: 'n8n'  # Updated based on investigation
        }

        if port in service_map:
            service_name = service_map[port]
            try:
                # Check if service is running
                result = subprocess.run(['systemctl', 'is-active', service_name],
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    return {'process': service_name, 'service': service_name}

                # Check for snap services
                snap_result = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=running'],
                                           capture_output=True, text=True)
                for line in snap_result.stdout.split('\n'):
                    if f'snap.{service_name}' in line or service_name in line:
                        return {'process': f'snap-{service_name}', 'service': service_name}

            except:
                pass

            return {'process': service_name, 'service': service_name}

        return {}

    def _check_docker_port(self, port: int) -> dict:
        """Check if a port is used by a Docker container"""
        try:
            # Check if Docker is available (try without sudo first, then with sudo)
            for docker_cmd in [['docker'], ['sudo', 'docker']]:
                try:
                    result = subprocess.run(docker_cmd + ['ps', '--format', '{{.Names}}\t{{.Image}}\t{{.Ports}}'],
                                          capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            if line and (f':{port}->' in line or f':{port}/' in line):
                                parts = line.split('\t')
                                if len(parts) >= 3:
                                    container_name = parts[0]
                                    image = parts[1]
                                    ports = parts[2]

                                    # Extract service name from image or container name
                                    service_name = self._extract_service_name(image, container_name)

                                    return {
                                        'process': f'docker-{service_name}',
                                        'service': service_name,
                                        'container': container_name,
                                        'image': image,
                                        'ports': ports
                                    }
                        break  # If docker worked, don't try sudo
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    continue  # Try next docker command or give up

        except Exception as e:
            self.logger.debug(f"Docker port check failed: {e}")

        return {}

    def _extract_service_name(self, image: str, container_name: str) -> str:
        """Extract a meaningful service name from Docker image or container name"""
        # Check container name first (often more descriptive)
        name_lower = container_name.lower()

        # Common service patterns in container names
        service_patterns = {
            'n8n': 'n8n',
            'postgres': 'postgresql',
            'mysql': 'mysql',
            'mariadb': 'mysql',
            'nginx': 'nginx',
            'apache': 'apache',
            'redis': 'redis',
            'mongo': 'mongodb',
            'elastic': 'elasticsearch',
            'kibana': 'kibana',
            'grafana': 'grafana',
            'prometheus': 'prometheus',
            'traefik': 'traefik',
            'portainer': 'portainer',
            'nextcloud': 'nextcloud',
            'wordpress': 'wordpress',
            'jenkins': 'jenkins',
            'gitlab': 'gitlab',
            'sonarr': 'sonarr',
            'radarr': 'radarr',
            'plex': 'plex',
            'jellyfin': 'jellyfin'
        }

        # Check container name for service patterns
        for pattern, service in service_patterns.items():
            if pattern in name_lower:
                return service

        # Fall back to image name analysis
        image_lower = image.lower()
        for pattern, service in service_patterns.items():
            if pattern in image_lower:
                return service

        # Extract from image name (remove registry and tag)
        try:
            service_name = image.split(':')[0].split('/')[-1]
            # Clean up common suffixes
            service_name = service_name.replace('-docker', '').replace('_docker', '')
            return service_name
        except:
            return 'unknown'

    def _is_system_port(self, port: int, process_name: str) -> bool:
        """Check if a port is a known system service port"""
        # Well-known system ports that should not be flagged
        system_ports = {
            111: ['rpcbind', 'portmapper'],
            631: ['cupsd', 'cups'],
            5353: ['avahi-daemon', 'mdnsd'],
            68: ['dhclient', 'dhcp'],
            123: ['ntpd', 'chrony'],
            323: ['chronyd'],
            514: ['rsyslog', 'syslog'],
            6000: ['X11', 'Xorg'],
            5432: ['postgres', 'postgresql'],
            3306: ['mysql', 'mysqld'],
            6379: ['redis', 'redis-server'],
            27017: ['mongod', 'mongodb'],
            9200: ['elasticsearch'],
            5672: ['rabbitmq'],
            8080: ['tomcat', 'jetty'],
            3000: ['node', 'nodejs'],
            8000: ['python', 'django'],
            4000: ['ruby', 'rails']
        }

        if port in system_ports:
            allowed_processes = system_ports[port]
            return any(proc in process_name.lower() for proc in allowed_processes)

        # High ephemeral ports are often temporary
        if port > 32768:
            return True

        return False

    def _format_process_details(self, port_info: dict) -> str:
        """Format process details for reporting"""
        details = []

        if port_info.get('process', 'unknown') != 'unknown':
            details.append(f"process: {port_info['process']}")

        if port_info.get('pid'):
            details.append(f"PID: {port_info['pid']}")

        if port_info.get('user'):
            details.append(f"user: {port_info['user']}")

        if port_info.get('cmdline') and len(port_info['cmdline']) > 0:
            # Truncate long command lines
            cmdline = port_info['cmdline'][:60] + '...' if len(port_info['cmdline']) > 60 else port_info['cmdline']
            details.append(f"cmd: {cmdline}")

        return ' | '.join(details) if details else 'unknown process'

    def _check_updates(self) -> Dict[str, Any]:
        """Check for available system updates"""
        update_info = {}

        try:
            # Detect package manager and check for updates
            if os.path.exists('/usr/bin/apt'):
                # Debian/Ubuntu
                result = subprocess.run(['apt', 'list', '--upgradable'],
                                      capture_output=True, text=True)
                if result.returncode == 0:
                    updates = len([line for line in result.stdout.split('\n')
                                 if 'upgradable' in line]) - 1
                    update_info['apt_updates'] = updates

                    if updates > 10:
                        self.add_issue("Security", f"Many pending updates: {updates}")

            elif os.path.exists('/usr/bin/yum'):
                # RedHat/CentOS
                result = subprocess.run(['yum', 'check-update'],
                                      capture_output=True, text=True)
                if result.returncode == 100:  # Updates available
                    updates = len(result.stdout.strip().split('\n'))
                    update_info['yum_updates'] = updates

                    if updates > 10:
                        self.add_issue("Security", f"Many pending updates: {updates}")

        except Exception as e:
            self.logger.debug(f"Update check failed: {e}")

        return update_info

    def _check_ssh_keys(self) -> Dict[str, Any]:
        """Check SSH key permissions and integrity"""
        ssh_info = {}

        try:
            ssh_dirs = ['/etc/ssh', os.path.expanduser('~/.ssh')]

            for ssh_dir in ssh_dirs:
                if os.path.exists(ssh_dir):
                    for key_file in ['id_rsa', 'id_ed25519', 'ssh_host_rsa_key']:
                        key_path = os.path.join(ssh_dir, key_file)
                        if os.path.exists(key_path):
                            stat = os.stat(key_path)
                            perms = oct(stat.st_mode)[-3:]

                            if perms != '600' and 'host' not in key_file:
                                self.add_issue("Security",
                                             f"Incorrect SSH key permissions: {key_path} ({perms})")

                            ssh_info[key_path] = {'permissions': perms}

        except Exception as e:
            self.logger.debug(f"SSH key check failed: {e}")

        return ssh_info

    def _check_unexpected_reboots(self) -> Dict[str, Any]:
        """Check for unexpected system reboots"""
        reboot_info = {'unexpected_reboots': [], 'boot_time': None}

        try:
            # Get current boot time
            boot_time = datetime.fromtimestamp(psutil.boot_time())
            reboot_info['boot_time'] = boot_time.isoformat()

            # Check if this is a recent reboot
            hours_since_boot = (datetime.now() - boot_time).total_seconds() / 3600
            check_hours = self.config['security']['reboot_check_hours']

            if hours_since_boot < check_hours:
                # Check if reboot was planned (look for shutdown logs)
                planned_reboot = self._was_reboot_planned()

                if not planned_reboot:
                    self.add_issue("Security",
                                 f"Unexpected reboot detected {hours_since_boot:.1f} hours ago "
                                 f"at {boot_time.strftime('%Y-%m-%d %H:%M:%S')}")
                    reboot_info['unexpected_reboots'].append({
                        'boot_time': boot_time.isoformat(),
                        'hours_ago': hours_since_boot,
                        'planned': False
                    })

            # Check for multiple reboots in short timeframe
            recent_reboots = self._get_recent_reboots()
            if len(recent_reboots) > 3:
                self.add_issue("Security", f"Multiple reboots detected: {len(recent_reboots)} in last 24h")

        except Exception as e:
            self.logger.debug(f"Reboot check failed: {e}")

        return reboot_info

    def _was_reboot_planned(self) -> bool:
        """Check if the reboot was planned by looking at system logs"""
        try:
            # Check for planned shutdown/reboot commands in auth.log or syslog
            log_files = ['/var/log/auth.log', '/var/log/syslog', '/var/log/messages']

            for log_file in log_files:
                if os.path.exists(log_file):
                    # Look for shutdown/reboot commands in the last 2 hours before boot
                    cmd = f"grep -E '(shutdown|reboot|systemctl.*(reboot|poweroff))' {log_file} | tail -5"
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

                    if result.stdout and ('shutdown' in result.stdout.lower() or 'reboot' in result.stdout.lower()):
                        return True
                    break

            # Check for update-related reboots
            if os.path.exists('/var/run/reboot-required.pkgs'):
                return True

        except Exception as e:
            self.logger.debug(f"Planned reboot check failed: {e}")

        return False

    def _get_recent_reboots(self) -> List[datetime]:
        """Get list of recent reboots from system logs"""
        reboots = []

        try:
            # Parse wtmp or utmp for boot records
            result = subprocess.run(['last', 'reboot', '-n', '10'], capture_output=True, text=True)

            for line in result.stdout.split('\n'):
                if 'system boot' in line:
                    # Extract date from last command output
                    parts = line.split()
                    if len(parts) >= 5:
                        try:
                            date_str = ' '.join(parts[4:7])
                            boot_date = datetime.strptime(f"{datetime.now().year} {date_str}", "%Y %a %b %d %H:%M")

                            # Only include reboots within last 24 hours
                            if (datetime.now() - boot_date).total_seconds() < 86400:
                                reboots.append(boot_date)
                        except ValueError:
                            continue

        except Exception as e:
            self.logger.debug(f"Recent reboots check failed: {e}")

        return reboots

    def _check_suspicious_connections(self) -> List[Dict]:
        """Check for suspicious network connections"""
        suspicious_connections = []

        try:
            # Get current connections with caching
            cache_key = "network_connections"
            connections = self.get_cache(cache_key)

            if connections is None:
                connections = psutil.net_connections(kind='inet')
                self.set_cache(cache_key, connections)

            whitelist_ips = set(self.config['security']['whitelist_ips'])
            whitelist_ports = set(self.config['security']['whitelist_ports'])

            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    suspicious = False
                    reason = ""

                    # Check for connections to unusual ports
                    if hasattr(conn, 'raddr') and conn.raddr:
                        remote_ip = conn.raddr.ip
                        remote_port = conn.raddr.port

                        # Skip whitelisted IPs
                        if remote_ip in whitelist_ips:
                            continue

                        # Check for connections to unusual high ports
                        if remote_port > 49152 and remote_port not in whitelist_ports:
                            suspicious = True
                            reason = f"Connection to unusual high port {remote_port}"

                        # Check for connections to known suspicious ports
                        suspicious_ports = [1433, 3389, 5900, 6667, 6697]  # SQL, RDP, VNC, IRC
                        if remote_port in suspicious_ports:
                            suspicious = True
                            reason = f"Connection to potentially suspicious port {remote_port}"

                        # Check for foreign IP connections (basic geolocation check)
                        if self._is_foreign_ip(remote_ip):
                            # Check if it's a known safe process
                            process_name = self._get_process_name(conn.pid)
                            if not self._is_safe_foreign_connection(process_name, remote_port):
                                suspicious = True
                                reason = f"Connection to foreign IP {remote_ip}:{remote_port}"

                    # Note: Listening port checks are handled by _check_open_ports() to avoid duplication

                    if suspicious:
                        process_details = self._get_detailed_process_info(conn.pid)
                        conn_info = {
                            'local_addr': f"{conn.laddr.ip}:{conn.laddr.port}",
                            'remote_addr': f"{conn.raddr.ip}:{conn.raddr.port}" if hasattr(conn, 'raddr') and conn.raddr else "N/A",
                            'status': conn.status,
                            'pid': conn.pid,
                            'process': process_details.get('name', 'unknown'),
                            'user': process_details.get('user', ''),
                            'cmdline': process_details.get('cmdline', ''),
                            'reason': reason
                        }
                        suspicious_connections.append(conn_info)

                        # Enhanced reporting with process details
                        process_info = f"{process_details.get('name', 'unknown')}"
                        if process_details.get('user'):
                            process_info += f" (user: {process_details['user']})"
                        if conn.pid:
                            process_info += f" [PID: {conn.pid}]"

                        self.add_issue("Security", f"Suspicious connection: {reason} - {process_info}", "warning")

        except Exception as e:
            self.logger.debug(f"Suspicious connections check failed: {e}")

        return suspicious_connections

    def _is_foreign_ip(self, ip: str) -> bool:
        """Basic check if IP is potentially foreign (non-local)"""
        try:
            # Skip local/private IP ranges
            if ip.startswith(('127.', '10.', '192.168.', '172.')):
                return False
            if ip.startswith('169.254.'):  # Link-local
                return False
            if ip == '::1' or ip.startswith('fe80:'):  # IPv6 local
                return False

            # Very basic check - if it's not local, consider it potentially foreign
            return True
        except:
            return False

    def _is_safe_foreign_connection(self, process_name: str, port: int) -> bool:
        """Check if a foreign connection is from a safe/expected process"""
        safe_processes = {
            'claude': [443, 80],  # Claude connecting to Anthropic servers
            'firefox': [443, 80],
            'chrome': [443, 80],
            'curl': [443, 80],
            'wget': [443, 80],
            'git': [443, 80, 22],
            'ssh': [22],
            'ping': [],  # Ping can connect to any IP
            'ntp': [123],
            'ntpd': [123],
            'update': [443, 80],
            'apt': [443, 80],
            'yum': [443, 80],
            'dnf': [443, 80]
        }

        process_lower = process_name.lower()
        for safe_proc, allowed_ports in safe_processes.items():
            if safe_proc in process_lower:
                return not allowed_ports or port in allowed_ports

        return False

    def _get_process_name(self, pid: Optional[int]) -> str:
        """Get process name from PID with caching"""
        if not pid:
            return "unknown"

        if pid in self._process_cache:
            return self._process_cache[pid]

        try:
            process = psutil.Process(pid)
            name = process.name()
            self._process_cache[pid] = name
            return name
        except:
            return "unknown"

    def _get_detailed_process_info(self, pid: Optional[int]) -> dict:
        """Get detailed process information"""
        if not pid:
            return {'name': 'unknown', 'cmdline': '', 'user': ''}

        try:
            process = psutil.Process(pid)
            return {
                'name': process.name(),
                'cmdline': ' '.join(process.cmdline()),
                'user': process.username(),
                'pid': pid
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return {'name': 'unknown', 'cmdline': '', 'user': '', 'pid': pid}

    def _check_unusual_processes(self) -> List[Dict]:
        """Check for unusual or suspicious processes"""
        unusual_processes = []

        try:
            # Get baseline of normal processes
            baseline = self._get_process_baseline()
            current_processes = {}

            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time', 'cpu_percent']):
                try:
                    proc_info = proc.info
                    proc_name = proc_info['name']
                    current_processes[proc_info['pid']] = proc_info

                    # Check for processes not in baseline
                    if proc_name not in baseline and proc_name not in self.config['security']['suspicious_processes']:
                        # Skip common system processes and kernel threads
                        if not self._is_system_process(proc_name):
                            # Check if process is recently created (last 10 minutes, not hour)
                            create_time = datetime.fromtimestamp(proc_info['create_time'])
                            if (datetime.now() - create_time).total_seconds() < 600:  # Last 10 minutes
                                # Skip very short-lived processes
                                if (datetime.now() - create_time).total_seconds() > 5:
                                    unusual_processes.append({
                                        'pid': proc_info['pid'],
                                        'name': proc_name,
                                        'cmdline': ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else '',
                                        'create_time': create_time.isoformat(),
                                        'cpu_percent': proc_info['cpu_percent']
                                    })

                                    self.add_issue("Security",
                                                  f"New unusual process detected: {proc_name} (PID: {proc_info['pid']})",
                                                  "warning")

                    # Check for processes consuming unusual CPU
                    if proc_info['cpu_percent'] and proc_info['cpu_percent'] > 80:
                        self.add_issue("Security",
                                     f"Process {proc_name} using high CPU: {proc_info['cpu_percent']:.1f}%",
                                     "warning")

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

            # Update baseline with current processes
            self._update_process_baseline(current_processes)

        except Exception as e:
            self.logger.debug(f"Unusual processes check failed: {e}")

        return unusual_processes

    def _check_ssh_config(self) -> Dict[str, Any]:
        """Check SSH configuration for security issues"""
        ssh_issues = []
        ssh_info = {}

        try:
            # Try to get SSH configuration (try without sudo first, then with sudo)
            for sshd_cmd in [['sshd', '-T'], ['sudo', 'sshd', '-T']]:
                try:
                    result = subprocess.run(sshd_cmd, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        ssh_config = {}
                        for line in result.stdout.split('\n'):
                            if line.strip() and ' ' in line:
                                key, value = line.strip().split(' ', 1)
                                ssh_config[key.lower()] = value.lower()

                        ssh_info['config'] = ssh_config

                        # Check for security issues
                        if ssh_config.get('permitrootlogin', 'no') not in ['no', 'prohibit-password']:
                            self.add_issue("Security", "SSH allows root login with password")
                            ssh_issues.append("root_login_enabled")

                        if ssh_config.get('passwordauthentication', 'no') == 'yes':
                            self.add_issue("Security", "SSH password authentication enabled")
                            ssh_issues.append("password_auth_enabled")

                        if ssh_config.get('permitemptypasswords', 'no') == 'yes':
                            self.add_issue("Security", "SSH allows empty passwords")
                            ssh_issues.append("empty_passwords_allowed")

                        if ssh_config.get('x11forwarding', 'no') == 'yes':
                            ssh_issues.append("x11_forwarding_enabled")

                        break  # If sshd worked, don't try sudo
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    continue

            # Check for recent SSH authentication failures
            ssh_failures = self._check_ssh_failures()
            if ssh_failures:
                ssh_info['recent_failures'] = ssh_failures

        except Exception as e:
            self.logger.debug(f"SSH config check failed: {e}")

        ssh_info['issues'] = ssh_issues
        return ssh_info

    def _check_ssh_failures(self) -> List[str]:
        """Check for recent SSH authentication failures"""
        failures = []
        try:
            # Try journalctl first, then auth.log
            log_commands = [
                ['journalctl', '-u', 'ssh', '-S', '-24h', '-p', 'warning', '--no-pager'],
                ['sudo', 'journalctl', '-u', 'ssh', '-S', '-24h', '-p', 'warning', '--no-pager']
            ]

            for cmd in log_commands:
                try:
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if result.returncode == 0 and result.stdout.strip():
                        failure_lines = [line for line in result.stdout.split('\n')
                                       if 'Failed password' in line or 'Invalid user' in line]
                        failures.extend(failure_lines[-10:])  # Last 10 failures
                        break
                except:
                    continue

        except Exception as e:
            self.logger.debug(f"SSH failures check failed: {e}")

        return failures

    def _check_firewall_status(self) -> Dict[str, Any]:
        """Check firewall status and configuration"""
        firewall_info = {}

        try:
            # Check UFW status
            try:
                result = subprocess.run(['ufw', 'status'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    ufw_output = result.stdout.strip()
                    firewall_info['ufw'] = ufw_output

                    if 'Status: inactive' in ufw_output:
                        self.add_issue("Security", "UFW firewall is inactive")
            except FileNotFoundError:
                firewall_info['ufw'] = 'not_installed'

            # Check iptables rules
            try:
                for ipt_cmd in [['iptables', '-S'], ['sudo', 'iptables', '-S']]:
                    try:
                        result = subprocess.run(ipt_cmd, capture_output=True, text=True, timeout=10)
                        if result.returncode == 0:
                            iptables_rules = result.stdout.strip().split('\n')
                            firewall_info['iptables_rules'] = len(iptables_rules)

                            # Check if only default ACCEPT policies (potential security issue)
                            if len(iptables_rules) <= 3 and all('ACCEPT' in rule for rule in iptables_rules):
                                self.add_issue("Security", "No custom iptables rules found - firewall may be wide open")
                            break
                    except:
                        continue
            except:
                pass

        except Exception as e:
            self.logger.debug(f"Firewall check failed: {e}")

        return firewall_info

    def _check_critical_file_permissions(self) -> Dict[str, Any]:
        """Check for world-writable directories and SUID/SGID files"""
        perm_issues = []
        file_info = {}

        try:
            # Check for world-writable directories (top level only for performance)
            try:
                result = subprocess.run(['sudo', 'find', '/', '-xdev', '-type', 'd', '-perm', '-0002', '-maxdepth', '2'],
                                      capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    world_writable = [d for d in result.stdout.strip().split('\n') if d and d not in ['/tmp', '/var/tmp']]
                    if world_writable:
                        file_info['world_writable_dirs'] = world_writable[:10]  # Limit to first 10
                        if len(world_writable) > 2:  # Allow a few expected ones
                            self.add_issue("Security", f"Found {len(world_writable)} world-writable directories")
            except:
                pass

            # Check for SUID/SGID files (common locations only for performance)
            try:
                suid_paths = ['/usr/bin', '/usr/sbin', '/bin', '/sbin']
                suid_files = []

                for path in suid_paths:
                    try:
                        result = subprocess.run(['sudo', 'find', path, '-type', 'f', '(', '-perm', '-4000', '-o', '-perm', '-2000', ')'],
                                              capture_output=True, text=True, timeout=10)
                        if result.returncode == 0:
                            suid_files.extend(result.stdout.strip().split('\n'))
                    except:
                        continue

                suid_files = [f for f in suid_files if f]  # Remove empty strings
                file_info['suid_sgid_files'] = len(suid_files)

                # Flag if there are unusual numbers of SUID files
                if len(suid_files) > 50:
                    self.add_issue("Security", f"High number of SUID/SGID files found: {len(suid_files)}")

            except:
                pass

        except Exception as e:
            self.logger.debug(f"File permissions check failed: {e}")

        file_info['issues'] = perm_issues
        return file_info

    def _check_system_hardening(self) -> Dict[str, Any]:
        """Check system hardening settings (sysctl values)"""
        hardening_info = {}
        hardening_issues = []

        # Critical security sysctl settings to check
        security_settings = {
            'net.ipv4.ip_forward': '0',  # IP forwarding should be disabled
            'net.ipv4.conf.all.accept_redirects': '0',  # Don't accept ICMP redirects
            'net.ipv4.conf.all.send_redirects': '0',  # Don't send ICMP redirects
            'net.ipv4.icmp_echo_ignore_broadcasts': '1',  # Ignore broadcast pings
            'kernel.randomize_va_space': '2',  # Enable ASLR
            'kernel.kptr_restrict': '1',  # Restrict kernel pointer access
            'net.ipv4.conf.all.accept_source_route': '0',  # Don't accept source routing
            'net.ipv4.conf.all.log_martians': '1',  # Log suspicious packets
        }

        try:
            current_settings = {}

            # Get current sysctl values
            for setting, expected in security_settings.items():
                try:
                    result = subprocess.run(['sysctl', '-n', setting],
                                          capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        current_value = result.stdout.strip()
                        current_settings[setting] = current_value

                        # Check if setting matches expected secure value
                        if current_value != expected:
                            issue_desc = f"Insecure sysctl setting: {setting}={current_value} (should be {expected})"
                            self.add_issue("Security", issue_desc)
                            hardening_issues.append({
                                'setting': setting,
                                'current': current_value,
                                'expected': expected
                            })
                except:
                    continue

            hardening_info['current_settings'] = current_settings
            hardening_info['issues'] = hardening_issues

            # Check if kernel has some hardening features
            try:
                # Check if KASLR is enabled
                with open('/proc/cmdline', 'r') as f:
                    cmdline = f.read()
                    if 'nokaslr' in cmdline:
                        self.add_issue("Security", "Kernel ASLR (KASLR) is disabled")
                        hardening_issues.append({'setting': 'kaslr', 'status': 'disabled'})

            except:
                pass

        except Exception as e:
            self.logger.debug(f"System hardening check failed: {e}")

        return hardening_info

    def _get_process_baseline(self) -> Set[str]:
        """Get baseline of normal system processes"""
        if self.baseline_file.exists():
            try:
                with open(self.baseline_file, 'r') as f:
                    data = json.load(f)
                    return set(data.get('processes', []))
            except Exception:
                pass

        # Default baseline of common system processes
        return {
            'systemd', 'kthreadd', 'ksoftirqd', 'rcu_', 'watchdog', 'sshd', 'cron', 'dbus',
            'NetworkManager', 'systemd-', 'kernel', 'init', 'bash', 'python3', 'nginx',
            'apache2', 'mysql', 'postgresql', 'docker', 'containerd'
        }

    def _update_process_baseline(self, current_processes: Dict):
        """Update process baseline with current processes"""
        try:
            baseline_data = {'processes': list(set(proc['name'] for proc in current_processes.values()))}
            with open(self.baseline_file, 'w') as f:
                json.dump(baseline_data, f)
        except Exception as e:
            self.logger.debug(f"Could not update process baseline: {e}")

    def _is_system_process(self, process_name: str) -> bool:
        """Check if a process is a known system process"""
        system_prefixes = ['systemd', 'kernel', 'kthread', 'ksoftirq', 'rcu_', 'watchdog', 'kworker']
        system_processes = {
            'init', 'bash', 'sh', 'python3', 'python', 'perl', 'java', 'node',
            'sshd', 'cron', 'crond', 'dbus', 'dbus-daemon', 'NetworkManager', 'dhclient',
            'systemctl', 'ping', 'timeout', 'grep', 'awk', 'sed', 'tar', 'gzip',
            'curl', 'wget', 'git', 'vim', 'nano', 'less', 'more', 'cat', 'ls',
            'sudo', 'su', 'ps', 'top', 'htop', 'netstat', 'lsof', 'claude'
        }

        if process_name in system_processes:
            return True

        for prefix in system_prefixes:
            if process_name.startswith(prefix):
                return True

        return False

    def check_services(self) -> Dict[str, Any]:
        """Check critical system services"""
        results = {}

        if self.config['services']['check_systemd']:
            results['systemd_services'] = self._check_systemd_services()

        return results

    def _check_systemd_services(self) -> Dict[str, str]:
        """Check status of critical systemd services"""
        service_status = {}

        for service in self.config['services']['critical_services']:
            try:
                result = subprocess.run(['systemctl', 'is-active', service],
                                      capture_output=True, text=True)
                status = result.stdout.strip()
                service_status[service] = status

                if status != 'active':
                    self.add_issue("Services", f"Service {service} is {status}")

            except Exception as e:
                service_status[service] = f"check_failed: {e}"
                self.logger.debug(f"Service check failed for {service}: {e}")

        return service_status

    def get_running_services(self) -> Dict[str, Any]:
        """Get list of running services for reporting"""
        services = {'systemd': [], 'listening_ports': []}

        try:
            # Get systemd services
            result = subprocess.run(['systemctl', 'list-units', '--type=service', '--state=running', '--no-pager'],
                                  capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n')[1:]:  # Skip header
                    if '.service' in line and 'loaded active running' in line:
                        parts = line.split()
                        if parts:
                            service_name = parts[0].replace('.service', '')
                            # Skip system and uninteresting services
                            if not any(skip in service_name.lower() for skip in
                                     ['systemd', 'dbus', 'getty', 'user@', 'session-']):
                                services['systemd'].append(service_name)

            # Get services with listening ports (from open ports check)
            connections = psutil.net_connections(kind='inet')
            port_services = {}

            for conn in connections:
                if conn.status == 'LISTEN':
                    port = conn.laddr.port
                    service_info = self._identify_service_by_port(port)
                    if service_info and service_info.get('service'):
                        service_name = service_info['service']
                        if service_name not in port_services:
                            port_services[service_name] = []
                        port_services[service_name].append(port)

            services['listening_ports'] = port_services

        except Exception as e:
            self.logger.debug(f"Get running services failed: {e}")

        return services

    def send_email_notification(self, subject: str, body: str):
        """Send email notification for critical issues"""
        if not self.config['email']['enabled']:
            return

        try:
            # Use environment variables if configured
            if self.config['email'].get('use_env_vars', False):
                smtp_server = os.getenv('SMTP_SERVER', self.config['email']['smtp_server'])
                smtp_port = int(os.getenv('SMTP_PORT', str(self.config['email']['smtp_port'])))
                smtp_user = os.getenv('SMTP_USER', self.config['email']['username'])
                smtp_password = os.getenv('SMTP_PASSWORD', self.config['email']['password'])
                from_email = os.getenv('EMAIL_FROM', self.config['email']['from_email'])
                to_email = os.getenv('EMAIL_TO', self.config['email']['to_email'])
            else:
                smtp_server = self.config['email']['smtp_server']
                smtp_port = self.config['email']['smtp_port']
                smtp_user = self.config['email']['username']
                smtp_password = self.config['email']['password']
                from_email = self.config['email']['from_email']
                to_email = self.config['email']['to_email']

            if not all([smtp_server, smtp_user, smtp_password, from_email, to_email]):
                self.logger.error("Email configuration incomplete")
                return

            msg = MIMEMultipart()
            msg['From'] = from_email
            msg['To'] = to_email
            msg['Subject'] = f"[Self-Check Alert] {subject}"

            # Create HTML email body
            html_body = self._create_html_email(body)
            msg.attach(MIMEText(html_body, 'html'))

            server = smtplib.SMTP(smtp_server, smtp_port)

            if self.config['email']['use_tls']:
                server.starttls()

            server.login(smtp_user, smtp_password)
            server.send_message(msg)
            server.quit()

            self.logger.info("Email notification sent successfully")

        except Exception as e:
            self.logger.error(f"Failed to send email notification: {e}")

    def _create_html_email(self, plain_body: str) -> str:
        """Create HTML formatted email body"""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>System Self-Check Alert</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; color: #333; }}
        .container {{ max-width: 800px; margin: 0 auto; background-color: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px 8px 0 0; }}
        .header h1 {{ margin: 0 0 8px 0; padding: 0; font-size: 24px; color: white !important; }}
        .header p {{ margin: 0; padding: 0; opacity: 0.9; color: white !important; }}
        .content {{ padding: 20px; color: #333; }}
        .critical {{ background-color: #fee; border-left: 4px solid #d32f2f; padding: 15px; margin: 10px 0; color: #333; }}
        .warning {{ background-color: #fff3cd; border-left: 4px solid #f57c00; padding: 15px; margin: 10px 0; color: #333; }}
        .success {{ background-color: #e8f5e8; border-left: 4px solid #388e3c; padding: 15px; margin: 10px 0; color: #333; }}
        .critical h2, .warning h2, .success h2 {{ margin: 0 0 8px 0; color: #333; }}
        .critical p, .warning p, .success p {{ margin: 0; color: #666; }}
        .footer {{ background-color: #f8f9fa; padding: 15px; border-radius: 0 0 8px 8px; text-align: center; font-size: 12px; color: #666; }}
        pre {{ background-color: #f8f9fa; padding: 15px; border-radius: 4px; overflow-x: auto; font-size: 13px; color: #333; border: 1px solid #e9ecef; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: #000000; padding: 20px; border-radius: 8px 8px 0 0;">
            <h1 style="color: #000000; margin: 0 0 8px 0; padding: 0; font-size: 24px; font-weight: bold;">
                <font color="#000000">🔒 System Self-Check Alert</font>
            </h1>
            <p style="color: #000000; margin: 0; padding: 0;">
                <font color="#000000">Hostname: {socket.gethostname()} | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</font>
            </p>
        </div>
        <div class="content">
            <div class="{"critical" if self.issues else "warning" if self.warnings else "success"}">
                <h2>{'🚨 Critical Issues Detected' if self.issues else '⚠️ Warnings Found' if self.warnings else '✅ System Healthy'}</h2>
                <p>{'Immediate attention required' if self.issues else 'Review recommended' if self.warnings else 'All checks passed'}</p>
            </div>
            <pre>{plain_body}</pre>
        </div>
        <div class="footer">
            Generated by Self-Check System Monitor |
            <a href="https://github.com/bk86a/self-check">GitHub Repository</a>
        </div>
    </div>
        </body>
        </html>
        """
        return html

    def generate_report(self, results: Dict[str, Any]) -> str:
        """Generate a human-readable report"""
        report = []
        report.append(f"System Self-Check Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append("=" * 60)
        report.append(f"Hostname: {socket.gethostname()}")
        report.append(f"Platform: {platform.platform()}")
        report.append(f"Architecture: {platform.machine()}")
        report.append("")

        # Critical Issues
        if self.issues:
            report.append("CRITICAL ISSUES:")
            report.append("-" * 20)
            for issue in self.issues:
                report.append(f"• [{issue['category']}] {issue['description']}")
            report.append("")

        # Warnings
        if self.warnings:
            report.append("WARNINGS:")
            report.append("-" * 10)
            for warning in self.warnings:
                report.append(f"• [{warning['category']}] {warning['description']}")
            report.append("")

        # Performance Summary
        if 'performance' in results:
            perf = results['performance']
            report.append("PERFORMANCE:")
            report.append("-" * 12)
            report.append(f"CPU Usage: {perf.get('cpu_usage', 'N/A'):.1f}%")
            if 'memory' in perf:
                report.append(f"Memory Usage: {perf['memory']['percent']:.1f}%")
            if 'swap' in perf:
                report.append(f"Swap Usage: {perf['swap']['percent']:.1f}%")
            if 'load_average' in perf:
                report.append(f"Load Average: {perf['load_average'][0]:.2f}")
            report.append("")

        # Resource Summary
        if 'resources' in results:
            res = results['resources']
            report.append("RESOURCES:")
            report.append("-" * 10)
            if 'disk_usage' in res:
                for disk in res['disk_usage']:
                    # Skip snap packages in report (they're always 100% by design)
                    if not disk['mountpoint'].startswith('/snap/'):
                        report.append(f"Disk {disk['mountpoint']}: {disk['percent']:.1f}% used")
            report.append(f"Internet: {'Connected' if res.get('internet_connectivity') else 'Disconnected'}")
            report.append("")

        # Running Services Summary
        if 'running_services' in results:
            services = results['running_services']
            report.append("RUNNING SERVICES:")
            report.append("-" * 16)

            # Show systemd services
            if services.get('systemd'):
                systemd_services = services['systemd'][:10]  # Limit to first 10
                report.append(f"Active Services: {', '.join(systemd_services)}")
                if len(services['systemd']) > 10:
                    report.append(f"... and {len(services['systemd']) - 10} more")

            # Show port services
            if services.get('listening_ports'):
                report.append("Network Services:")
                for service, ports in list(services['listening_ports'].items())[:5]:  # Limit to 5
                    ports_str = ', '.join(map(str, ports))
                    report.append(f"  {service}: ports {ports_str}")

            report.append("")

        # Temperature Summary
        if 'temperature' in results:
            temp = results['temperature']
            report.append("TEMPERATURE:")
            report.append("-" * 12)

            # Raspberry Pi temperature
            if 'rpi_temperature' in temp:
                report.append(f"CPU Temperature: {temp['rpi_temperature']:.1f}°C")

            # Thermal zones
            elif 'thermal_zones' in temp:
                for zone in temp['thermal_zones'][:3]:  # Show first 3 zones
                    report.append(f"{zone['type']}: {zone['temp']:.1f}°C")

            # psutil temperatures
            elif 'temperatures' in temp:
                for sensor_name, entries in list(temp['temperatures'].items())[:2]:  # Show first 2 sensors
                    for entry in entries[:1]:  # Show first entry per sensor
                        if entry.current:
                            report.append(f"{sensor_name}: {entry.current:.1f}°C")

            # Virtualization note
            if 'temperature_note' in temp:
                report.append(temp['temperature_note'])

            # VM detection info
            if 'virtualization' in temp:
                virt = temp['virtualization']
                report.append(f"Platform: {virt.get('type', 'Virtual Machine')}")

            report.append("")

        if not self.issues and not self.warnings:
            report.append("✓ All checks passed - system is healthy")

        return "\n".join(report)

    def run_checks(self) -> Dict[str, Any]:
        """Run all enabled checks with performance optimization"""
        start_time = time.time()

        results = {
            'timestamp': datetime.now().isoformat(),
            'hostname': socket.gethostname(),
            'platform': platform.platform()
        }

        # Run checks with performance monitoring
        try:
            if self.config['checks']['performance']:
                results['performance'] = self.check_performance()

            if self.config['checks']['resources']:
                results['resources'] = self.check_resources()

            if self.config['checks']['temperature']:
                results['temperature'] = self.check_temperature()

            if self.config['checks']['security']:
                results['security'] = self.check_security()

            if self.config['checks']['services']:
                results['services'] = self.check_services()

            # Always collect running services for reporting
            results['running_services'] = self.get_running_services()

            # Save current state for next comparison
            current_state = {
                'timestamp': results['timestamp'],
                'processes': [p.name() for p in psutil.process_iter(['name'])],
                'connections': len(psutil.net_connections()),
                'boot_time': psutil.boot_time()
            }
            self.save_current_state(current_state)

        except Exception as e:
            self.logger.error(f"Error during checks: {e}")
            self.add_issue("System", f"Check execution error: {str(e)}")

        # Performance metrics
        execution_time = time.time() - start_time
        results['execution_time'] = execution_time

        if execution_time > 30:  # Warn if script takes too long
            self.add_issue("Performance", f"Self-check script took {execution_time:.1f}s to execute", "warning")

        # Generate and log report
        report = self.generate_report(results)
        if not self.config.get('quiet', False):
            print(report)

        # Send email notification if there are critical issues or warnings
        if (self.issues or self.warnings) and self.config['email']['enabled']:
            if self.issues:
                subject = f"CRITICAL System Alert - {socket.gethostname()}"
            else:
                subject = f"System Warnings - {socket.gethostname()}"
            self.send_email_notification(subject, report)

        return results

def main():
    parser = argparse.ArgumentParser(description='System Self-Check Monitor')
    parser.add_argument('--config', '-c', default='config.json',
                       help='Configuration file path')
    parser.add_argument('--output', '-o',
                       help='Output file for results (JSON format)')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Suppress console output')
    parser.add_argument('--create-config', action='store_true',
                       help='Create default configuration file')

    args = parser.parse_args()

    if args.create_config:
        checker = SystemChecker()
        with open(args.config, 'w') as f:
            json.dump(checker.config, f, indent=2)
        print(f"Default configuration created: {args.config}")
        return

    try:
        checker = SystemChecker(args.config)
        results = checker.run_checks()

        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)

        # Exit with error code if critical issues found
        sys.exit(1 if checker.issues else 0)

    except KeyboardInterrupt:
        print("\nCheck interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"Error running self-check: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()