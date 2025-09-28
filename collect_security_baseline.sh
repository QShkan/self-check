#!/usr/bin/env bash
# collect_security_baseline.sh - Read-only Linux security snapshot (Ubuntu/Debian friendly)
# Usage: bash collect_security_baseline.sh
set -euo pipefail

OUT="security_baseline_$(hostname)_$(date +%Y%m%d_%H%M%S).txt"
exec > >(tee "$OUT") 2>&1

echo "=== Host & Kernel ==="
uname -a
lsb_release -a 2>/dev/null || true
echo; echo "Uptime: $(uptime -p)"

echo; echo "=== Accounts & Auth ==="
echo "- Logged-in users:"
who
echo; echo "- Last logins (head):"
last -n 10 | sed -n '1,15p'
echo; echo "- Users with shell accounts:"
getent passwd | awk -F: '$7 ~ /(bash|zsh|fish|sh)/ {print $1":"$7}'
echo; echo "- Sudoers (direct & group):"
getent group sudo || true
grep -rE '^[^#].*' /etc/sudoers /etc/sudoers.d 2>/dev/null || true
echo; echo "- Password policy:"
grep -E '^(PASS_|ENCRYPT_METHOD|SHA_CRYPT)' /etc/login.defs || true
grep -E 'pam_(pwquality|cracklib|faillock|tally2|unix)' /etc/pam.d/common-password /etc/pam.d/common-auth 2>/dev/null || true

echo; echo "=== SSH Configuration ==="
sshd -T 2>/dev/null | sort || sudo sshd -T 2>/dev/null | sort || true
echo; echo "- Recent SSH auth failures (24h):"
journalctl -u ssh -S -24h -p warning --no-pager 2>/dev/null || sudo journalctl -u ssh -S -24h -p warning --no-pager || true

echo; echo "=== Packages & Updates ==="
apt-cache policy | head -n 20
echo; echo "- Upgradable packages:"
apt list --upgradable 2>/dev/null | sed -n '1,200p' || true
echo; echo "- Unattended-upgrades status:"
systemctl is-enabled unattended-upgrades 2>/dev/null || true
grep -E '^(Unattended-Upgrade|Allowed-Origins|Origins-Pattern)' /etc/apt/apt.conf.d/* 2>/dev/null || true

echo; echo "=== Services, Ports & Firewall ==="
echo "- Listening sockets:"
ss -tulpen 2>/dev/null || sudo ss -tulpen
echo; echo "- Systemd services (enabled):"
systemctl list-unit-files --type=service --state=enabled --no-pager
echo; echo "- Firewall (UFW):"
ufw status verbose 2>/dev/null || echo "UFW not installed or inactive"
echo; echo "- nftables / iptables rules:"
sudo nft list ruleset 2>/dev/null || sudo iptables -S 2>/dev/null || true

echo; echo "=== Filesystem Risks ==="
echo "- World-writable directories (top level under /):"
sudo find / -xdev -type d -perm -0002 -maxdepth 2 2>/dev/null
echo; echo "- SUID/SGID files (top offenders):"
sudo find / -xdev -type f -perm -4000 -o -perm -2000 2>/dev/null | sort
echo; echo "- New files in /tmp last 24h:"
sudo find /tmp -type f -mtime -1 -ls 2>/dev/null | head -n 50

echo; echo "=== Scheduled Tasks ==="
echo "- System-wide crontabs:"
sudo ls -l /etc/cron.* /etc/crontab 2>/dev/null || true
echo "- User crontabs (listed):"
for u in $(cut -d: -f1 /etc/passwd); do
  (sudo crontab -u "$u" -l 2>/dev/null | sed "s/^/[$u] /") || true
done

echo; echo "=== Logs & Alerts (last 24h) ==="
echo "- High-priority journal entries:"
journalctl -p 3 -S -24h --no-pager 2>/dev/null || sudo journalctl -p 3 -S -24h --no-pager || true
echo; echo "- Auth.log tail:"
sudo tail -n 200 /var/log/auth.log 2>/dev/null || true

echo; echo "=== Kernel & sysctl hardening ==="
grep -E '^(net\.ipv4\.ip_forward|net\.ipv4\.conf\.all\.accept_redirects|net\.ipv4\.conf\.all\.send_redirects|net\.ipv4\.icmp_echo_ignore_broadcasts|kernel\.randomize_va_space|kernel\.kptr_restrict|kernel\.unprivileged_bpf_disabled)' /etc/sysctl.conf /etc/sysctl.d/* 2>/dev/null || true
sysctl -a 2>/dev/null | grep -E 'kernel.randomize_va_space|kernel.kptr_restrict|unprivileged_bpf_disabled|ipv4.conf.all.accept_redirects|ipv4.conf.all.send_redirects' || true

echo; echo "=== Containers (if any) ==="
command -v docker >/dev/null && { echo "- Docker info:"; sudo docker info 2>/dev/null || true; echo "- Containers:"; sudo docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Ports}}\t{{.Status}}'; } || echo "Docker not installed"
command -v containerd >/dev/null && containerd --version || true
command -v podman >/dev/null && podman ps --all || true

echo; echo "=== AppArmor/SELinux ==="
aa-status 2>/dev/null || sudo aa-status 2>/dev/null || echo "AppArmor status unavailable"
getenforce 2>/dev/null || echo "SELinux not in use (expected on Ubuntu/Debian)"

echo; echo "=== Summary Hints ==="
echo "Review: upgradable pkgs, SSH (root login, auth methods), open ports, firewall rules,"
echo "SUID/SGID and world-writable dirs, failed logins, unattended-upgrades, cron jobs."
echo; echo "Output saved to: $OUT"
