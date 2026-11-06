#!/bin/bash
# Initial setup only; this does not select any experimental protection condition.
set -euo pipefail
test "$(id -u)" -eq 0
test "$(hostname)" = ssh-defence-lab
. /etc/os-release
test "$VERSION_CODENAME" = resolute

backup_dir="/root/ssh-lab-setup-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$backup_dir"
cp -a /etc/apt/sources.list /etc/apt/sources.list.d "$backup_dir/"
cp -a /etc/ssh/sshd_config.d "$backup_dir/"

cat > /etc/apt/sources.list.d/ubuntu.sources <<'SOURCES'
Types: deb
URIs: https://ports.ubuntu.com/ubuntu-ports
Suites: resolute resolute-updates resolute-security
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
SOURCES
# Replace the temporary recovery source; retain it in the backup directory.
printf '%s\n' '# Network sources are in sources.list.d/ubuntu.sources.' > /etc/apt/sources.list
if test -f /etc/apt/sources.list.d/cdrom.sources; then
    mv /etc/apt/sources.list.d/cdrom.sources "$backup_dir/"
fi
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server fail2ban python3 nftables rsyslog

cat > /etc/ssh/sshd_config.d/00-lab-access.conf <<'SSH'
# Initial private administration access. Experimental authentication is configured later.
ListenAddress 192.168.57.210
PermitRootLogin no
PasswordAuthentication no
SSH
install -d -o root -g root -m 0755 /run/sshd
/usr/sbin/sshd -t
systemctl disable --now fail2ban
# Use the standard persistent SSH service so the listening address is explicit.
systemctl disable --now ssh.socket
systemctl enable ssh.service
mkdir -p /etc/systemd/system/ssh.service.d
cat > /usr/local/sbin/ssh-lab-wait-address <<'WAIT'
#!/bin/sh
# A private ListenAddress must exist before sshd attempts to bind it.
attempt=0
while [ "$attempt" -lt 60 ]; do
    if /usr/sbin/ip -o -4 address show dev labnet | /usr/bin/grep -Fq ' 192.168.57.210/24 '; then
        exit 0
    fi
    attempt=$((attempt + 1))
    sleep 1
done
echo 'Private lab address did not appear within 60 seconds.' >&2
exit 1
WAIT
chmod 755 /usr/local/sbin/ssh-lab-wait-address
cat > /etc/systemd/system/ssh.service.d/lab-network.conf <<'SERVICE'
[Unit]
Wants=network-online.target
After=network-online.target

[Service]
ExecStartPre=/usr/local/sbin/ssh-lab-wait-address
SERVICE
systemctl daemon-reload
systemctl restart ssh.service

printf '\nInitial lab service checks\n'
systemctl is-active ssh
systemctl is-enabled fail2ban || true
/usr/sbin/sshd -V
/usr/sbin/sshd -T | sed -n '/^persourcepenalties /p; /^listenaddress /p; /^passwordauthentication /p; /^permitrootlogin /p'
ss -lntp 'sport = :22'
dpkg-query -W -f='${Package}\t${Version}\n' openssh-server fail2ban python3 nftables rsyslog
