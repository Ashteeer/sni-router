#!/usr/bin/env python3
"""Linux integration regression: false write readiness must not spin a worker.

Usage: python3 tests/forwarder-backpressure/check.py /path/to/sni-router
Needs a C compiler and loopback TCP. No live services or fixed ports are used.
"""
import concurrent.futures
import errno
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time


def bound_socket():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen()
    sock.settimeout(15)
    return sock


def splice_available():
    if not hasattr(os, "splice"):
        print("SKIP splice: feature probe requires Python 3.10 or newer")
        return False
    with bound_socket() as listener:
        with socket.create_connection(listener.getsockname()) as sender:
            with listener.accept()[0] as receiver:
                read_fd, write_fd = os.pipe()
                try:
                    os.write(write_fd, b"x")
                    os.splice(read_fd, sender.fileno(), 1, flags=os.SPLICE_F_NONBLOCK)
                    receiver.settimeout(5)
                    assert receiver.recv(1) == b"x"
                except OSError as error:
                    if error.errno not in (errno.EINVAL, errno.ENOSYS, errno.EPERM,
                                           errno.EOPNOTSUPP):
                        raise
                    print(f"SKIP splice: kernel or sandbox refuses splice: {error}")
                    return False
                finally:
                    os.close(read_fd)
                    os.close(write_fd)
    return True


def check(binary, directory, copy_mode):
    with bound_socket() as backend, bound_socket() as reservation:
        port = reservation.getsockname()[1]
        backend_port = backend.getsockname()[1]
        config = directory / "config.yaml"
        config.write_text(f"""listeners:
  - name: regression
    bind: ['127.0.0.1:{port}']
    routes:
      - sni: '*'
        backend: echo
backends:
  echo:
    servers: ['127.0.0.1:{backend_port}']
timeouts:
  drain: 1
log:
  level: error
""")
        counter = directory / "counter"
        counter.write_bytes(bytes(4096))
        env = dict(os.environ, LD_PRELOAD=str(directory / "fault.so"),
                   SNI_TEST_COUNTER=str(counter))
        env.pop("SNI_TEST_COPY", None)
        if copy_mode:
            env["SNI_TEST_COPY"] = "1"
        reservation.close()
        with (directory / "router.log").open("w+") as log:
            process = subprocess.Popen([binary, "-c", str(config)], env=env,
                                       stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 10
                while True:
                    if process.poll() is not None:
                        log.seek(0)
                        raise AssertionError(log.read())
                    try:
                        client = socket.create_connection(("127.0.0.1", port), timeout=1)
                        break
                    except ConnectionRefusedError:
                        if time.monotonic() >= deadline:
                            log.seek(0)
                            raise AssertionError("listener not ready: " + log.read())
                        time.sleep(0.02)

                payload = b"plain-tcp:" + bytes(range(251)) * 4096

                def reply():
                    with backend.accept()[0] as peer:
                        peer.settimeout(15)
                        received = bytearray()
                        while chunk := peer.recv(65536):
                            received.extend(chunk)
                        assert received == payload, "upstream bytes or half-close lost"
                        peer.sendall(payload[::-1])
                        peer.shutdown(socket.SHUT_WR)

                start = time.monotonic()
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                    future = pool.submit(reply)
                    with client:
                        client.settimeout(15)
                        client.sendall(payload)
                        client.shutdown(socket.SHUT_WR)
                        received = bytearray()
                        while chunk := client.recv(65536):
                            received.extend(chunk)
                        assert received == payload[::-1], "downstream bytes or EOF lost"
                    future.result(timeout=15)
                elapsed = time.monotonic() - start
                stat = Path(f"/proc/{process.pid}/stat").read_text().split()
                cpu = (int(stat[13]) + int(stat[14])) / os.sysconf("SC_CLK_TCK")
                attempts = struct.unpack("=Q", counter.read_bytes()[:8])[0]
                mode = "copy" if copy_mode else "splice"
                print(f"{mode}: {len(payload)} bytes each way, "
                      f"EAGAIN={attempts}, CPU={cpu:.3f}s, elapsed={elapsed:.3f}s", flush=True)
                assert attempts > 0, "fault injection did not reach the forwarder"
                # Count failed retries, not CPU/time ratios that depend on the host.
                assert attempts < 512, f"busy loop: {attempts} retries in a 500ms stall"
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def main():
    compiler = shutil.which("cc")
    if sys.platform != "linux" or not compiler:
        print("SKIP: requires Linux and a C compiler")
        return
    # WSL1 loses edge-triggered readiness; it cannot validate this regression.
    release = Path("/proc/sys/kernel/osrelease").read_text().lower()
    if "microsoft" in release and "wsl2" not in release:
        print("SKIP: WSL1 does not provide reliable TCP readiness for this test")
        return
    try:
        with bound_socket():
            pass
    except OSError as error:
        print(f"SKIP: loopback TCP unavailable: {error}")
        return
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    with tempfile.TemporaryDirectory(prefix="sni-backpressure-") as tmp:
        directory = Path(tmp)
        subprocess.run([compiler, "-shared", "-fPIC", "-O2", "-Wall", "-Wextra",
                        str(Path(__file__).with_name("fault.c")), "-ldl", "-o",
                        str(directory / "fault.so")], check=True)
        failed = False
        for copy_mode in ((False, True) if splice_available() else (True,)):
            try:
                check(binary, directory, copy_mode)
            except AssertionError as error:
                print(f"FAIL: {error}", flush=True)
                failed = True
        if failed:
            sys.exit(1)


if __name__ == "__main__":
    main()
