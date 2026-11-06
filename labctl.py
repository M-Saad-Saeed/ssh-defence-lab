#!/usr/bin/env python3
"""Mac-side setup controls. No research experiment runner is included yet."""
import argparse
import datetime
import json
from pathlib import Path
import socket
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
CELLS = ('A', 'B', 'C', 'D')


def server(verb, cell=None):
    command = '/usr/local/sbin/ssh-lab-control ' + verb + (' ' + cell if cell else '')
    password = (ROOT / '.local/console-password.txt').read_text().strip()
    response = subprocess.run(['/usr/bin/ssh', '-F', str(ROOT / 'ssh_config'), '-o',
                               'BatchMode=yes', 'ssh-defence-lab', 'sudo -S -p "" ' + command],
                              input=password + '\n', text=True, capture_output=True, timeout=120)
    if response.returncode:
        raise RuntimeError(response.stderr.strip() or response.stdout.strip())
    return json.loads(response.stdout)


def save(kind, data):
    (ROOT / 'evidence').mkdir(exist_ok=True)
    destination = ROOT / 'evidence' / (kind + '-' + datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d-%H%M%S-%f') + '.json')
    destination.write_text(json.dumps(data, indent=2) + '\n')
    return str(destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='verb', required=True)
    sub.add_parser('status')
    sub.add_parser('plan')
    sub.add_parser('use').add_argument('condition', choices=CELLS)
    sub.add_parser('verify').add_argument('condition', choices=CELLS)
    sub.add_parser('health')
    probe = sub.add_parser('probe', help='One correct-credential setup login; never sends wrong passwords.')
    probe.add_argument('--user', choices=['legit_user', 'guess_target'], default='legit_user')
    probe.add_argument('--source', choices=['192.168.57.211', '192.168.57.212'], default='192.168.57.212')
    options = parser.parse_args()
    if options.verb == 'plan':
        print((ROOT / 'scenarios.json').read_text())
        return
    if options.verb == 'probe':
        from ssh_probe import probe as normal_login
        data = normal_login(options.user, options.source)
        data['evidence_file'] = save('python-probe', data)
        print(json.dumps(data, indent=2))
        if data['outcome'] != 'success':
            raise SystemExit(1)
        return
    if options.verb == 'health':
        data = server('status')
        cell = data['recorded_state']['condition']
        server('verify', cell)
        for source in ('192.168.57.211', '192.168.57.212'):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                try:
                    sock.bind((source, 0))
                except OSError as error:
                    raise RuntimeError('Private test addresses are missing after a VM/network restart. Run Prepare Test Addresses.command on the Mac, then try again.') from error
        subprocess.run([sys.executable, str(ROOT / 'check-test-access.py'), '--addresses'], check=True)
        print('PASS: source addresses, successful fixture logins, administrator access and configuration ' + cell)
        print('This verifies environment setup; live detection and measurement validation remain separate.')
        print('State evidence:', save('environment-health', data))
        return
    data = server(options.verb, getattr(options, 'condition', None))
    destination = save('condition-' + options.verb, data)
    cell = data['recorded_state']['condition'] if data['recorded_state'] else 'not selected'
    print('Configuration:', cell)
    print('OpenSSH:', data['ssh_active'])
    print('Native penalties:', 'off' if data['effective_ssh']['persourcepenalties'] == 'no' else 'on')
    print('Fail2ban:', 'on' if data['fail2ban_active'] else 'off')
    print('Evidence:', destination)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, subprocess.SubprocessError) as error:
        print('STOP:', error, file=sys.stderr)
        sys.exit(1)
