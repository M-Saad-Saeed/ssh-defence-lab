#!/bin/bash
# Add a local Ubuntu desktop; retain the existing networkd and SSH lab configuration.
set -euo pipefail
test "$(id -u)" -eq 0
test "$(hostname)" = ssh-defence-lab
backup_dir="/root/ssh-lab-before-desktop-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$backup_dir"
cp -a /etc/netplan /etc/ssh/sshd_config.d /etc/fail2ban "$backup_dir/"
# ubuntu-settings supplies a NetworkManager renderer default. Keep the lab's
# existing networkd-managed, MAC-matched static configuration authoritative.
printf '%s\n' 'network:' '  renderer: networkd' > /etc/netplan/99-lab-renderer.yaml
chmod 600 /etc/netplan/99-lab-renderer.yaml
exec > >(tee -a /var/log/ssh-lab-desktop-install.log) 2>&1
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
    ubuntu-desktop-minimal ptyxis gnome-text-editor \
    yaru-theme-gnome-shell yaru-theme-gtk yaru-theme-icon fonts-ubuntu
systemctl set-default graphical.target
systemctl enable gdm3
/usr/sbin/sshd -t
printf '\nInstalled desktop package versions\n'
dpkg-query -W -f='${Package}\t${Version}\n' ubuntu-desktop-minimal gdm3 gnome-shell nautilus ptyxis gnome-text-editor
printf '\nPrivate network configuration after installation\n'
ip -br address
systemctl is-active ssh
