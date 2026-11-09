"""Loopback-only regression tests; no AnyTLS account or remote server needed."""

import contextlib
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import unittest


BINARY = Path(os.environ.get("ANYTLS_BIN", "zig-out/bin/anytls-zig")).resolve()
TIMEOUT = 12


@contextlib.contextmanager
def client_process(upstream_port=1):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    process = subprocess.Popen(
        [str(BINARY), "-server", f"127.0.0.1:{upstream_port}", "-p", "test-only",
         "-sni", "localhost",
         "-l", f"127.0.0.1:{port}"],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(100):
            if process.poll() is not None:
                raise RuntimeError("client exited before listening")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise RuntimeError("client did not start listening")
        yield port
    finally:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def connect(port):
    conn = socket.create_connection(("127.0.0.1", port), timeout=2)
    conn.settimeout(TIMEOUT)
    return conn


def recv_exact(conn, size):
    result = b""
    while len(result) < size:
        chunk = conn.recv(size - len(result))
        if not chunk:
            raise AssertionError("connection closed before SOCKS reply")
        result += chunk
    return result


@contextlib.contextmanager
def echo_server():
    # Minimal local AnyTLS peer: consume auth/target, then echo data frames.
    with tempfile.TemporaryDirectory() as directory, socket.socket() as listener:
        cert = str(Path(directory) / "cert.pem")
        key = str(Path(directory) / "key.pem")
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
             "ec_paramgen_curve:P-256", "-nodes", "-keyout", key, "-out", cert,
             "-subj", "/CN=localhost", "-days", "1"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(TIMEOUT)
        failures = []

        def serve():
            try:
                raw, _ = listener.accept()
                with raw, context.wrap_socket(raw, server_side=True) as peer:
                    peer.settimeout(20)
                    auth = recv_exact(peer, 34)
                    recv_exact(peer, int.from_bytes(auth[32:34], "big"))
                    target_seen = False
                    while True:
                        cmd, sid, size = struct.unpack("!BIH", recv_exact(peer, 7))
                        data = recv_exact(peer, size)
                        if cmd == 2:
                            if not target_seen:
                                target_seen = True
                                continue
                            peer.sendall(struct.pack("!BIH", 2, sid, len(data)) + data)
                            return
            except Exception as error:
                failures.append(error)

        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        try:
            yield listener.getsockname()[1]
        finally:
            worker.join(timeout=22)
            if worker.is_alive():
                raise AssertionError("local AnyTLS peer did not stop")
            if failures:
                raise AssertionError("local AnyTLS peer failed") from failures[0]


class SocksHandshakeTests(unittest.TestCase):
    def test_stalled_connections_release_workers_without_client_disconnect(self):
        with client_process() as port, contextlib.ExitStack() as stack:
            holders = [stack.enter_context(connect(port)) for _ in range(32)]
            for conn in holders:
                conn.sendall(b"\x05")
            time.sleep(0.2)
            with connect(port) as newcomer:
                newcomer.sendall(b"\x05\x01\x00")
                self.assertEqual(recv_exact(newcomer, 2), b"\x05\x00")

    def test_incomplete_methods_are_closed(self):
        with client_process() as port, connect(port) as conn:
            started = time.monotonic()
            conn.sendall(b"\x05\x02\x00")
            self.assertEqual(conn.recv(1), b"")
            self.assertGreaterEqual(time.monotonic() - started, 8)

    def test_incomplete_target_is_closed(self):
        with client_process() as port, connect(port) as conn:
            conn.sendall(b"\x05\x01\x00")
            self.assertEqual(recv_exact(conn, 2), b"\x05\x00")
            conn.sendall(b"\x05\x01\x00\x03\x0b" + b"a")
            self.assertEqual(conn.recv(1), b"")

    def test_greeting_and_target_share_one_deadline(self):
        with client_process() as port, connect(port) as conn:
            started = time.monotonic()
            conn.sendall(b"\x05")
            time.sleep(6)
            conn.sendall(b"\x01\x00")
            self.assertEqual(recv_exact(conn, 2), b"\x05\x00")
            conn.sendall(b"\x05\x01")
            conn.settimeout(TIMEOUT - (time.monotonic() - started))
            self.assertEqual(conn.recv(1), b"")
            self.assertGreaterEqual(time.monotonic() - started, 8)

    def test_normal_greeting_is_not_delayed(self):
        with client_process() as port, connect(port) as conn:
            conn.settimeout(1)
            conn.sendall(b"\x05\x01\x00")
            self.assertEqual(recv_exact(conn, 2), b"\x05\x00")

    @unittest.skipUnless(ssl.HAS_TLSv1_3, "local AnyTLS peer requires TLS 1.3 support in Python")
    def test_established_relay_survives_handshake_deadline(self):
        with echo_server() as upstream, client_process(upstream) as port, connect(port) as conn:
            conn.sendall(b"\x05\x01\x00")
            self.assertEqual(recv_exact(conn, 2), b"\x05\x00")
            conn.sendall(b"\x05\x01\x00\x03\x0bexample.com\x01\xbb")
            self.assertEqual(recv_exact(conn, 10), b"\x05\x00\x00\x01" + b"\x00" * 6)
            time.sleep(11)
            conn.sendall(b"after-idle")
            self.assertEqual(recv_exact(conn, 10), b"after-idle")


if __name__ == "__main__":
    unittest.main()
