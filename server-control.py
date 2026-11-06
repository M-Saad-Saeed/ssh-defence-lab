#!/usr/bin/env python3
"""Root-only control of the four fixed configurations in SSH-Defence-Lab.

Switching restarts the services and clears their lab state. Never run during a
measurement. It does not send login attempts or perform research experiments.
"""
import argparse
import datetime
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

SSH = Path('/etc/ssh/sshd_config.d/00-lab-access.conf')
JAIL = Path('/etc/fail2ban/jail.d/zz-ssh-lab.local')
DAEMON = Path('/etc/fail2ban/fail2ban.d/zz-ssh-lab.local')
STATE = Path('/var/lib/ssh-lab/control-state.json')
TABLE = 'ssh_lab_f2b'
NATIVE = ('crash:90s authfail:5s noauth:1s grace-exceeded:10s '
          'refuseconnection:10s max:600s min:15s max-sources4:65536 '
          'max-sources6:65536 overflow:permissive overflow6:permissive')
CELLS = {'A': (False, False), 'B': (True, False), 'C': (False, True), 'D': (True, True)}


def command(*args, check=True):
    result = subprocess.run(args, text=True, capture_output=True, timeout=35)
    if check and result.returncode:
        raise RuntimeError(' '.join(args) + ': ' + result.stderr.strip() + result.stdout.strip())
    return result


def effective(user='labadmin'):
    text = command('/usr/sbin/sshd', '-T', '-C', f'user={user},host=lab-client,addr=192.168.57.211').stdout
    return dict(line.split(' ', 1) for line in text.splitlines() if ' ' in line)


def status():
    options = effective()
    active = command('systemctl', 'is-active', 'fail2ban', check=False).stdout.strip() == 'active'
    names = ['listenaddress', 'permitrootlogin', 'passwordauthentication', 'loglevel',
             'maxauthtries', 'maxstartups', 'persourcemaxstartups', 'logingracetime',
             'persourcenetblocksize', 'persourcepenaltyexemptlist', 'persourcepenalties']
    data = {'recorded_state': json.loads(STATE.read_text()) if STATE.exists() else None,
            'effective_ssh': {name: options.get(name) for name in names},
            'ssh_active': command('systemctl', 'is-active', 'ssh', check=False).stdout.strip(),
            'ssh_main_pid': command('systemctl', 'show', 'ssh', '-p', 'MainPID', '--value').stdout.strip(),
            'fail2ban_active': active,
            'firewall_lab_table': command('nft', '-j', 'list', 'table', 'inet', TABLE, check=False).stdout.strip()}
    if active:
        for query in [('status',), ('status', 'ssh-lab'), ('get', 'ssh-lab', 'maxretry'),
                      ('get', 'ssh-lab', 'findtime'), ('get', 'ssh-lab', 'bantime'),
                      ('get', 'ssh-lab', 'ignoreip'), ('get', 'ssh-lab', 'banip')]:
            data['fail2ban_' + '_'.join(query)] = command('fail2ban-client', *query).stdout.strip()
    return data


def verify(cell):
    native, f2b = CELLS[cell]
    data = status()
    values = data['effective_ssh']
    if data['ssh_active'] != 'active' or data['fail2ban_active'] != f2b:
        raise RuntimeError('Unexpected service state')
    if (values['persourcepenalties'] != 'no') != native:
        raise RuntimeError('Native penalty state differs from selected condition')
    if native:
        configured = dict(part.split(':', 1) for part in values['persourcepenalties'].split())
        planned = dict((key, value.removesuffix('s')) for key, value in
                       (part.split(':', 1) for part in NATIVE.split()))
        if configured != planned:
            raise RuntimeError('Native penalty parameters differ from the fixed plan')
    expected = {'listenaddress': '192.168.57.210:22', 'passwordauthentication': 'no',
                'permitrootlogin': 'no', 'loglevel': 'VERBOSE', 'maxauthtries': '6',
                'maxstartups': '10:30:100', 'persourcemaxstartups': 'none',
                'persourcenetblocksize': '32:128', 'logingracetime': '120',
                'persourcepenaltyexemptlist': '192.168.57.1/32'}
    for key, value in expected.items():
        if values.get(key) != value:
            raise RuntimeError('Unexpected fixed SSH option: ' + key)
    for user, method in [('guess_target', 'password'), ('legit_user', 'publickey')]:
        if effective(user)['authenticationmethods'] != method:
            raise RuntimeError('Incorrect dummy account authentication: ' + user)
    if f2b:
        for option, value in [('maxretry', '5'), ('findtime', '600'), ('bantime', '600')]:
            if data['fail2ban_get_ssh-lab_' + option] != value:
                raise RuntimeError('Unexpected Fail2ban parameter: ' + option)
        if command('fail2ban-client', 'get', 'ssh-lab', 'banip').stdout.strip():
            raise RuntimeError('Reset left banned addresses')
        if not data['firewall_lab_table']:
            raise RuntimeError('Fail2ban lab firewall table was not installed')
        if not data['fail2ban_status'].endswith('ssh-lab'):
            raise RuntimeError('Unexpected Fail2ban jail list')
        if '/var/log/auth.log' not in command('fail2ban-client', 'get', 'ssh-lab', 'logpath').stdout:
            raise RuntimeError('Incorrect Fail2ban log source')
    elif data['firewall_lab_table']:
        raise RuntimeError('Lab firewall table remains with Fail2ban off')
    return data


def select(cell):
    # Detect test sessions before resetting; administrator sessions are unaffected.
    connections = command('ss', '-Htn', 'state', 'established', '( sport = :22 )').stdout
    if any(ip in connections for ip in ('192.168.57.211:', '192.168.57.212:')):
        raise RuntimeError('A test connection is still open. Close it before switching.')
    native, f2b = CELLS[cell]
    now = datetime.datetime.now(datetime.timezone.utc)
    backup = Path('/root/ssh-lab-config-backups') / now.strftime('%Y%m%d-%H%M%S-%f')
    backup.mkdir(parents=True, mode=0o700)
    originals = {str(path): path.read_bytes() if path.exists() else None for path in (SSH, JAIL, DAEMON, STATE)}
    for number, (name, content) in enumerate(originals.items()):
        if content is not None:
            (backup / f'{number}-{Path(name).name}').write_bytes(content)
    (backup / 'paths.json').write_text(json.dumps(list(originals), indent=2))
    previous_active = command('systemctl', 'is-active', 'fail2ban', check=False).stdout.strip() == 'active'
    previous_enabled = command('systemctl', 'is-enabled', 'fail2ban', check=False).stdout.strip() == 'enabled'
    previous_pid = command('systemctl', 'show', 'ssh', '-p', 'MainPID', '--value').stdout.strip()
    try:
        SSH.write_text(f'''# Fixed SSH experiment settings. Managed by ssh-lab-control.
ListenAddress 192.168.57.210
PermitRootLogin no
PasswordAuthentication no
KbdInteractiveAuthentication no
LogLevel VERBOSE
MaxAuthTries 6
MaxStartups 10:30:100
PerSourceMaxStartups none
PerSourceNetBlockSize 32:128
LoginGraceTime 120
PerSourcePenaltyExemptList 192.168.57.1/32
PerSourcePenalties {NATIVE if native else 'no'}
''')
        JAIL.write_text(f'''# A-D experiment: only the ssh-lab jail may be active.
[sshd]
enabled = false

[ssh-lab]
enabled = {'true' if f2b else 'false'}
filter = sshd[mode=normal]
backend = polling
logpath = /var/log/auth.log tail
usedns = no
port = 22
protocol = tcp
maxretry = 5
findtime = 600
bantime = 600
bantime.increment = false
ignoreip = 127.0.0.1/8 ::1 192.168.57.1/32
ignoreself = true
action = nftables[name=ssh-lab, port=22, protocol=tcp, table={TABLE}, chain=ssh_lab_input, actionstart_on_demand=false, blocktype=reject]
''')
        DAEMON.parent.mkdir(exist_ok=True)
        DAEMON.write_text('''# Disposable in-memory state for repeatable service resets.
[Definition]
dbfile = None
logtarget = /var/log/fail2ban.log
loglevel = INFO
''')
        command('/usr/sbin/sshd', '-t')
        command('fail2ban-client', '-t')
        # Stopping the daemon clears its memory and removes its own action rules.
        command('systemctl', 'stop', 'fail2ban')
        if command('nft', 'list', 'table', 'inet', TABLE, check=False).returncode == 0:
            command('nft', 'delete', 'table', 'inet', TABLE)
        command('systemctl', 'restart', 'ssh')
        if command('systemctl', 'show', 'ssh', '-p', 'MainPID', '--value').stdout.strip() == previous_pid:
            raise RuntimeError('SSH parent process did not restart')
        command('systemctl', 'enable' if f2b else 'disable', 'fail2ban')
        if f2b:
            command('systemctl', 'start', 'fail2ban')
            for _ in range(30):
                if command('fail2ban-client', 'ping', check=False).returncode == 0:
                    break
                time.sleep(0.2)
        # A fixed short settle period is setup time, outside all observation windows.
        time.sleep(1)
        result = verify(cell)
        state = {'condition': cell, 'native_penalties': native, 'fail2ban': f2b,
                 'reset_time_utc': now.isoformat(), 'backup': str(backup),
                 'note': 'Configuration/reset verified; live detection and measurement validation still separate.'}
        STATE.parent.mkdir(parents=True, exist_ok=True)
        STATE.write_text(json.dumps(state, indent=2) + '\n')
        result['recorded_state'] = state
        (backup / 'applied-status.json').write_text(json.dumps(result, indent=2) + '\n')
        return result
    except Exception:
        command('systemctl', 'stop', 'fail2ban', check=False)
        for name, content in originals.items():
            path = Path(name)
            if content is None:
                path.unlink(missing_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(content)
        command('/usr/sbin/sshd', '-t')
        command('systemctl', 'restart', 'ssh')
        command('systemctl', 'enable' if previous_enabled else 'disable', 'fail2ban')
        if previous_active:
            command('systemctl', 'start', 'fail2ban')
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='verb', required=True)
    sub.add_parser('status')
    sub.add_parser('use').add_argument('condition', choices=CELLS)
    sub.add_parser('verify').add_argument('condition', choices=CELLS)
    options = parser.parse_args()
    if os.geteuid() != 0 or Path('/etc/hostname').read_text().strip() != 'ssh-defence-lab':
        raise SystemExit('Root on ssh-defence-lab only.')
    private = command('ip', '-o', '-4', 'addr', 'show', 'dev', 'labnet').stdout
    if '192.168.57.210/24' not in private:
        raise SystemExit('Private lab address is missing.')
    lock = open('/run/ssh-lab-control.lock', 'w')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    result = select(options.condition) if options.verb == 'use' else (
             verify(options.condition) if options.verb == 'verify' else status())
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
