"""One fresh, source-bound SSH connection with a correct fixture credential.

This helper verifies the Python client environment. It has no wrong-password
workload or scheduling implementation. Never interprets a timeout as proof of a ban.
"""
import json
import logging
from pathlib import Path
import socket
import threading
import time

import paramiko

ROOT = Path(__file__).resolve().parent
SERVER = '192.168.57.210'
logging.getLogger('paramiko').addHandler(logging.NullHandler())
logging.getLogger('paramiko').propagate = False


def probe(user='legit_user', source='192.168.57.212', deadline=10.0):
    if user not in ('legit_user', 'guess_target') or source not in ('192.168.57.211', '192.168.57.212'):
        raise ValueError('Only the two private lab accounts and source aliases are supported.')
    if not 1 <= deadline <= 30:
        raise ValueError('Setup check deadline must be between 1 and 30 seconds.')
    started = time.monotonic()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    transport = None
    channel = None
    timer = threading.Timer(deadline, sock.close)
    timer.daemon = True
    result = {'purpose': 'normal-login setup check', 'user': user, 'source': source,
              'deadline_seconds': deadline, 'outcome': 'error', 'phase': 'bind'}

    def remaining():
        left = deadline - (time.monotonic() - started)
        if left <= 0:
            raise TimeoutError('Common deadline exceeded')
        return left

    try:
        sock.bind((source, 0))
        result['client_port'] = sock.getsockname()[1]
        result['phase'] = 'connect'
        sock.settimeout(remaining())
        timer.start()
        sock.connect((SERVER, 22))
        result['phase'] = 'ssh_handshake'
        transport = paramiko.Transport(sock)
        transport.banner_timeout = remaining()
        transport.start_client(timeout=remaining())
        key = transport.get_remote_server_key()
        pins = paramiko.HostKeys(str(ROOT / '.local/known_hosts'))
        if not pins.check(SERVER, key):
            raise RuntimeError('Server host key does not match the pinned lab key')
        result['host_key_verified'] = True
        result['phase'] = 'authenticate'
        transport.auth_timeout = remaining()
        if user == 'legit_user':
            private = paramiko.Ed25519Key.from_private_key_file(str(ROOT / '.local/legit_user_ed25519'))
            transport.auth_publickey(user, private)
            result['authentication_method'] = 'publickey'
        else:
            fixture = json.loads((ROOT / '.local/test-fixtures.json').read_text())
            # Exactly one explicit password method; disable keyboard-interactive fallback.
            transport.auth_password(user, fixture['guess_target_password'], fallback=False)
            result['authentication_method'] = 'password'
        if not transport.is_authenticated():
            raise RuntimeError('Authentication was not completed')
        result['phase'] = 'session'
        channel = transport.open_session(timeout=remaining())
        channel.settimeout(remaining())
        channel.exec_command('true')
        output = bytearray()
        while True:
            channel.settimeout(remaining())
            data = channel.recv(1024)
            if not data:
                break
            output.extend(data)
            if len(output) > 4096:
                raise RuntimeError('Unexpected excessive session output')
        code = channel.recv_exit_status()
        remaining()
        if code != 0 or output.decode().strip() != 'SSH_LAB_LOGIN_OK ' + user:
            raise RuntimeError('Expected session success marker was not received')
        result.update(outcome='success', phase='completed')
    except Exception as error:
        result.update(error_type=type(error).__name__, error=str(error))
        if time.monotonic() - started >= deadline:
            result['outcome'] = 'deadline_exceeded'
    finally:
        timer.cancel()
        if channel:
            channel.close()
        if transport:
            transport.close()
        sock.close()
        result['elapsed_seconds'] = round(time.monotonic() - started, 6)
    return result
