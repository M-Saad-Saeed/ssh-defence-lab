#!/usr/bin/env python3
"""Basic successful-login checks only. No guessing, scheduling or research runs."""
import argparse
import datetime
import json
import os
from pathlib import Path
import socket
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
PRIVATE = ROOT / '.local'
SERVER = '192.168.57.210'


def ssh_args(user, source=None):
    args = ['/usr/bin/ssh', '-F', str(ROOT / 'ssh_config'), '-o', 'ConnectTimeout=5',
            '-o', 'ConnectionAttempts=1', '-o', 'ServerAliveInterval=5',
            '-o', 'ServerAliveCountMax=1', '-o', 'ControlMaster=no',
            '-o', 'ControlPath=none', '-o', 'LogLevel=ERROR', '-T', '-l', user]
    if source:
        args += ['-b', source]
    return args


def check(user, source=None):
    args = ssh_args(user, source)
    env = os.environ.copy()
    if user == 'guess_target':
        args += ['-o', 'PreferredAuthentications=password', '-o', 'PubkeyAuthentication=no',
                 '-o', 'PasswordAuthentication=yes', '-o', 'NumberOfPasswordPrompts=1']
        env.update(SSH_ASKPASS=str(PRIVATE / 'fixture-askpass'), SSH_ASKPASS_REQUIRE='force', DISPLAY='fixture-check')
    else:
        args += ['-o', 'BatchMode=yes', '-o', 'PreferredAuthentications=publickey',
                 '-i', str(PRIVATE / 'legit_user_ed25519')]
    args += ['ssh-defence-lab', 'true']
    result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True,
                            text=True, timeout=20, env=env, start_new_session=True)
    expected = 'SSH_LAB_LOGIN_OK ' + user
    if result.returncode or result.stdout.strip() != expected:
        raise RuntimeError(f'{user} from {source or "default address"}: login check failed: {result.stderr.strip()}')
    return {'user': user, 'requested_source': source, 'success_marker': result.stdout.strip()}


def installed(address):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((address, 0))
            return True
        except OSError:
            return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--addresses', action='store_true', help='Also verify the two configured source addresses.')
    options = parser.parse_args()
    sources = ['192.168.57.211', '192.168.57.212']
    if options.addresses and not all(installed(ip) for ip in sources):
        raise SystemExit('Test addresses are missing. Run Prepare Test Addresses.command first.')
    # Use the SERVER clock for its journal window; Mac/VM clocks can differ.
    timestamp = subprocess.run(['/usr/bin/ssh', '-F', str(ROOT / 'ssh_config'), '-o',
                                'BatchMode=yes', 'ssh-defence-lab', 'date +%s'],
                               capture_output=True, text=True, timeout=20, check=True)
    since = int(timestamp.stdout.strip()) - 1
    results = [check('guess_target'), check('legit_user')]
    if options.addresses:
        # Same X for the two roles; Y for the genuine role in the separate layout.
        results += [check('guess_target', sources[0]), check('legit_user', sources[0]), check('legit_user', sources[1])]
    # sshd-session records may not remain under ssh.service after PAM changes scope.
    command = f'journalctl --since=@{since} --no-pager -o json'
    response = subprocess.run(['/usr/bin/ssh', '-F', str(ROOT / 'ssh_config'), '-o',
                               'BatchMode=yes', 'ssh-defence-lab', command],
                              capture_output=True, text=True, timeout=20, check=True)
    accepted = []
    for line in response.stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        message = event.get('MESSAGE', '')
        if message.startswith(('Accepted password for guess_target ', 'Accepted publickey for legit_user ')):
            accepted.append(message)
    for method, user in [('password', 'guess_target'), ('publickey', 'legit_user')]:
        if not any(message.startswith(f'Accepted {method} for {user} from ') for message in accepted):
            raise RuntimeError('Missing server authentication evidence for ' + user)
    if options.addresses:
        required = [('password', 'guess_target', sources[0]),
                    ('publickey', 'legit_user', sources[0]),
                    ('publickey', 'legit_user', sources[1])]
        for method, user, address in required:
            prefix = f'Accepted {method} for {user} from {address} port '
            if not any(message.startswith(prefix) for message in accepted):
                raise RuntimeError('Missing server-observed address evidence for ' + user + ' from ' + address)
    now = datetime.datetime.now(datetime.timezone.utc)
    report = {'purpose': 'setup validation, not a research run', 'time_utc': now.isoformat(),
              'checks': results, 'server_authentication_evidence': accepted,
              'two_address_layouts_verified': options.addresses}
    (ROOT / 'evidence').mkdir(exist_ok=True)
    destination = ROOT / 'evidence' / ('access-check-' + now.strftime('%Y%m%d-%H%M%S') + '.json')
    destination.write_text(json.dumps(report, indent=2) + '\n')
    print('PASS: successful password login for guess_target and key login for legit_user.')
    if options.addresses:
        print('PASS: server records prove shared (.211/.211) and separate (.211/.212) source addresses.')
    else:
        print('Two-address layout is not verified yet.')
    print('Setup evidence:', destination)
    print('No wrong passwords or research workloads were sent.')


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, subprocess.SubprocessError, OSError) as error:
        print('STOP:', error, file=sys.stderr)
        sys.exit(1)
