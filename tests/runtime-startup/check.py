#!/usr/bin/env python3
"""Verify API and all workers survive io_uring allocation failure and re-exec.

Usage: python3 tests/runtime-startup/check.py /path/to/sni-router
Uses an isolated child, ephemeral loopback ports and a child-only memlock limit.
"""
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

if sys.platform == 'linux':
    import pwd
    import resource


def reservation():
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    return sock


def listeners(port):
    return sum(line.split()[1].endswith(f':{port:04X}') and line.split()[3] == '0A'
               for line in Path('/proc/net/tcp').read_text().splitlines()[1:])


def check(binary, directory, limited, identity):
    with reservation() as api, reservation() as tcp:
        api_port, tcp_port = api.getsockname()[1], tcp.getsockname()[1]
    token = secrets.token_hex(16)
    config = directory / 'config.yaml'
    config.write_text(f"""listeners:
  - name: test
    bind: ['127.0.0.1:{tcp_port}']
    routes:
      - sni: '*'
        backend: redirect
backends:
  redirect:
    mode: redirect_https
api:
  bind: '127.0.0.1:{api_port}'
  token: '{token}'
runtime:
  io_uring_entries: 16384
timeouts:
  drain: 1
""")
    config.chmod(0o644)

    def child_limits():
        # Root can bypass memlock on some hosts. Drop privileges only in the
        # disposable child, and never change the calling user's limits.
        if identity:
            os.setgroups([])
            os.setgid(identity.pw_gid)
            os.setuid(identity.pw_uid)
        if limited:
            _, hard = resource.getrlimit(resource.RLIMIT_MEMLOCK)
            limit = 65536 if hard == resource.RLIM_INFINITY else min(65536, hard)
            resource.setrlimit(resource.RLIMIT_MEMLOCK, (limit, limit))

    def request(path, method='GET'):
        req = urllib.request.Request(f'http://127.0.0.1:{api_port}{path}',
                                     method=method,
                                     headers={'Authorization': f'Bearer {token}'})
        with urllib.request.urlopen(req, timeout=1) as reply:
            return json.load(reply)

    def ready(process, log):
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise AssertionError(f'exited {process.returncode}: {log.read_text()}')
            text = log.read_text()
            cores = re.findall(r'cores=(\d+)', text)
            if cores and listeners(tcp_port) == int(cores[-1]):
                try:
                    status = request('/status')
                    assert status.get('version'), 'API has no version'
                    return int(cores[-1])
                except (OSError, urllib.error.URLError):
                    pass
            time.sleep(0.05)
        raise AssertionError('API or workers missing: ' + log.read_text())

    log = directory / ('limited.log' if limited else 'normal.log')
    with log.open('w') as output:
        process = subprocess.Popen([str(binary), '-c', str(config)],
                                   stdout=output, stderr=output,
                                   preexec_fn=child_limits)
        try:
            cores = ready(process, log)
            # Re-exec is also the final step of POST /update. Its API response
            # precedes the restart, so wait for a new startup log each time.
            for _ in range(3):
                previous = log.read_text().count('sni-router starting')
                request('/restart', 'POST')
                deadline = time.monotonic() + 10
                while log.read_text().count('sni-router starting') == previous:
                    assert process.poll() is None, 'process exited during re-exec'
                    assert time.monotonic() < deadline, 're-exec did not start'
                    time.sleep(0.05)
                assert ready(process, log) == cores, 'worker count changed after re-exec'
            text = log.read_text()
            if limited and 'runtime allocation failed' not in text:
                print('SKIP memlock failure: host selected legacy or does not charge ring memory')
            else:
                if limited:
                    assert 'falling back to epoll' in text, 'fallback was not exercised'
                print(f"PASS {'limited' if limited else 'normal'}: API, {cores} workers, 3 re-execs",
                      flush=True)
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def main():
    if sys.platform != 'linux':
        print('SKIP: Linux required')
        return
    release = Path('/proc/sys/kernel/osrelease').read_text().lower()
    if 'microsoft' in release and 'wsl2' not in release:
        print('SKIP: WSL1 cannot validate io_uring allocation')
        return
    identity = None
    if os.geteuid() == 0:
        try:
            identity = pwd.getpwnam('nobody')
        except KeyError:
            print('SKIP: root needs an unprivileged nobody account for the child')
            return
    try:
        with reservation():
            pass
    except OSError as error:
        print(f'SKIP: loopback unavailable: {error}')
        return
    with tempfile.TemporaryDirectory(prefix='sni-startup-') as tmp:
        directory = Path(tmp)
        directory.chmod(0o755)
        binary = directory / 'sni-router'
        shutil.copyfile(Path(sys.argv[1]).resolve(strict=True), binary)
        binary.chmod(0o755)
        for limited in (True, False):
            check(binary, directory, limited, identity)


if __name__ == '__main__':
    main()
