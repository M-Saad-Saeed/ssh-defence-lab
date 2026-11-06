#!/bin/zsh
# Add temporary aliases only to the verified VirtualBox private network.
set -euo pipefail
cd "${0:A:h}"
echo 'This prepares two private test addresses on your Mac, then checks normal logins.'
echo 'It does not send wrong passwords or run the experiment.'
echo 'Enter your MAC login password if prompted. Nothing appears as you type.'
echo
iface=$(/sbin/route -n get 192.168.57.210 | /usr/bin/awk '/interface:/ {print $2; exit}')
if [[ ! "$iface" =~ '^bridge[0-9]+$' ]] || ! /sbin/ifconfig "$iface" | /usr/bin/grep -q 'inet 192.168.57.1 netmask 0xffffff00'; then
    echo 'STOP: the expected private VirtualBox network is unavailable. Start the lab and ask for a network check.'
    read -r '?Press Enter to close.'
    exit 1
fi
echo "Verified private interface: $iface"
for address in 192.168.57.211 192.168.57.212; do
    if ! /sbin/ifconfig "$iface" | /usr/bin/grep -q "inet $address "; then
        # The addresses are reserved outside the configured .1-.200 DHCP range.
        /usr/bin/sudo /sbin/ifconfig "$iface" inet "$address" netmask 255.255.255.0 alias
    fi
done
if /usr/bin/python3 check-test-access.py --addresses; then
    echo
    echo 'The two source-address layouts are ready. These temporary addresses may need adding again after a Mac restart.'
else
    echo 'The address check did not pass. Keep this window open and show the error.'
fi
read -r '?Press Enter to close.'
