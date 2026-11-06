#!/usr/bin/env python3
"""Run as root in the lab VM. Creates fixtures; does not run experiments."""
import datetime
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import sys


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def main():
    if os.geteuid() != 0 or Path('/etc/hostname').read_text().strip() != 'ssh-defence-lab':
        raise SystemExit('Run as root on ssh-defence-lab only.')
    fixture_path = Path(sys.argv[1])
    if fixture_path.stat().st_mode & 0o077:
        raise SystemExit('Fixture file must be private (mode 600).')
    fixtures = json.loads(fixture_path.read_text())
    key = fixtures['legitimate_public_key'].strip()
    if not key.startswith('ssh-ed25519 ') or '\n' in key:
        raise SystemExit('Expected one Ed25519 public key.')
    names = ('guess_target', 'legit_user')
    for name in names:
        password = fixtures[name + '_password']
        if len(password) < 24 or any(c in password for c in ':\r\n'):
            raise SystemExit('Invalid fixture password.')
        try:
            entry = pwd.getpwnam(name)
        except KeyError:
            continue
        if entry.pw_gecos != 'SSH Lab Test Fixture' or entry.pw_dir != '/home/' + name:
            raise SystemExit('Refusing to modify an existing non-fixture account: ' + name)
    backup = Path('/root/ssh-lab-before-accounts-' + datetime.datetime.now().strftime('%Y%m%d-%H%M%S'))
    backup.mkdir(mode=0o700)
    config = Path('/etc/ssh/sshd_config')
    original = config.read_text()
    shutil.copy2(config, backup / 'sshd_config')
    managed = Path('/etc/ssh/ssh-lab-users.conf')
    if managed.exists():
        shutil.copy2(managed, backup / managed.name)
    for name in names:
        try:
            entry = pwd.getpwnam(name)
        except KeyError:
            run('/usr/sbin/useradd', '--create-home', '--shell', '/bin/sh',
                '--comment', 'SSH Lab Test Fixture', name)
            entry = pwd.getpwnam(name)
        if run('/usr/bin/id', '-Gn', name, capture_output=True).stdout.split() != [name]:
            raise SystemExit('Fixture has unexpected group membership: ' + name)
        run('/usr/sbin/chpasswd', input=name + ':' + fixtures[name + '_password'] + '\n')
    entry = pwd.getpwnam('legit_user')
    sshdir = Path(entry.pw_dir) / '.ssh'
    sshdir.mkdir(mode=0o700, exist_ok=True)
    os.chown(sshdir, entry.pw_uid, entry.pw_gid)
    os.chmod(sshdir, 0o700)
    auth = sshdir / 'authorized_keys'
    auth.write_text('restrict ' + key + '\n')
    os.chown(auth, entry.pw_uid, entry.pw_gid)
    os.chmod(auth, 0o600)
    session = Path('/usr/local/libexec/ssh-lab-test-session')
    session.parent.mkdir(parents=True, exist_ok=True)
    session.write_text('#!/bin/sh\nprintf "SSH_LAB_LOGIN_OK %s\\n" "$(id -un)"\n')
    os.chmod(session, 0o755)
    managed.write_text('''# Synthetic fixture accounts, private lab only. No experimental A-D selection.
Match User guess_target
    PasswordAuthentication yes
    PubkeyAuthentication no
    KbdInteractiveAuthentication no
    AuthenticationMethods password
    DisableForwarding yes
    PermitTTY no
    ForceCommand /usr/local/libexec/ssh-lab-test-session
Match User legit_user
    PasswordAuthentication no
    PubkeyAuthentication yes
    KbdInteractiveAuthentication no
    AuthenticationMethods publickey
    DisableForwarding yes
    PermitTTY no
    ForceCommand /usr/local/libexec/ssh-lab-test-session
Match all
''')
    os.chmod(managed, 0o644)
    include = 'Include /etc/ssh/ssh-lab-users.conf'
    candidate = backup / 'candidate_sshd_config'
    candidate.write_text(original if include in original.splitlines() else
                         original.rstrip() + '\n\n# SSH lab fixture accounts (keep at end)\n' + include + '\n')
    try:
        run('/usr/sbin/sshd', '-t', '-f', str(candidate))
        expected = {
            'labadmin': {'passwordauthentication': 'no'},
            'guess_target': {'passwordauthentication': 'yes', 'pubkeyauthentication': 'no', 'authenticationmethods': 'password'},
            'legit_user': {'passwordauthentication': 'no', 'pubkeyauthentication': 'yes', 'authenticationmethods': 'publickey'},
        }
        for name, checks in expected.items():
            effective = run('/usr/sbin/sshd', '-T', '-f', str(candidate), '-C',
                            f'user={name},host=lab-client,addr=192.168.57.211', capture_output=True).stdout
            values = dict(line.split(' ', 1) for line in effective.splitlines() if ' ' in line)
            for option, value in checks.items():
                if values.get(option) != value:
                    raise RuntimeError(f'{name}: unexpected {option}')
        config.write_text(candidate.read_text())
        run('/usr/sbin/sshd', '-t')
        run('/usr/bin/systemctl', 'reload', 'ssh')
    except Exception:
        config.write_text(original)
        if (backup / managed.name).exists():
            shutil.copy2(backup / managed.name, managed)
        else:
            managed.unlink(missing_ok=True)
        run('/usr/sbin/sshd', '-t')
        run('/usr/bin/systemctl', 'reload', 'ssh')
        raise
    fixture_path.unlink()
    print('Prepared two unprivileged dummy accounts; administrator access preserved.')
    print('Dummy SSH sessions return a fixed success marker and cannot forward or open a terminal.')
    print('SSH backup:', backup)
    print('No password guesses or research runs were performed.')


if __name__ == '__main__':
    main()
