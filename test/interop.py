#!/usr/bin/env python3
"""Disposable loopback interoperability tests against Python/OpenSSL. No live PKI."""
import argparse
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import concurrent.futures
import os
import pathlib
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time


def port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def context(cert, alpn=('http/1.1',), keylog=None, group='X25519'):
    c = ssl.create_default_context(cafile=str(cert))
    c.minimum_version = c.maximum_version = ssl.TLSVersion.TLSv1_3
    c.set_ecdh_curve(group)
    if keylog:
        c.keylog_filename = str(keylog)
    if alpn:
        c.set_alpn_protocols(list(alpn))
    return c


def exchange(p, cert, payload, alpn=('http/1.1',), keylog=None, group='X25519'):
    with socket.create_connection(('127.0.0.1', p), timeout=4) as raw:
        with context(cert, alpn, keylog, group).wrap_socket(raw, server_hostname='localhost') as s:
            assert s.version() == 'TLSv1.3'
            assert s.cipher()[0] == 'TLS_AES_128_GCM_SHA256'
            assert s.selected_alpn_protocol() == ('http/1.1' if alpn else None)
            s.sendall(payload)
            data = b''
            while len(data) < len(payload):
                chunk = s.recv(16384)
                assert chunk, 'premature EOF'
                data += chunk
            assert data == payload
            s.unwrap().close()  # Authenticate close_notify in both directions.


def exact(s, n):
    data = b''
    while len(data) < n:
        b = s.recv(n-len(data))
        if not b:
            raise EOFError
        data += b
    return data


class Bridge:
    """TLS record manipulation without reading secrets or decrypting anything."""
    def __init__(self, target, mutate=0, fragment=False, split_hello=False, forge=None):
        self.sock = socket.socket()
        self.sock.bind(('127.0.0.1', 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self.run, args=(target, mutate, fragment, split_hello, forge), daemon=True)
        self.thread.start()

    def run(self, target, mutate, fragment, split_hello, forge):
        try:
            client, _ = self.sock.accept()
            with client, socket.create_connection(('127.0.0.1', target), timeout=5) as upstream:
                def pump(source, dest, alter):
                    encrypted = 0
                    first = True
                    try:
                        while True:
                            hdr = exact(source, 5)
                            size = struct.unpack('!H', hdr[3:])[0]
                            b = exact(source, size)
                            if alter and hdr[0] == 23:
                                encrypted += 1
                                if encrypted == mutate:
                                    b = b[:-1] + bytes([b[-1] ^ 1])
                            if alter and hdr[0] == 23 and encrypted == 1 and forge:
                                # Re-authenticate a deliberately wrong Finished with the real
                                # test handshake secret, isolating transcript-MAC validation.
                                secret = next(bytes.fromhex(l.split()[2]) for l in forge.read_text().splitlines()
                                              if l.startswith('CLIENT_HANDSHAKE_TRAFFIC_SECRET '))
                                def expand(label, n):
                                    full = b'tls13 '+label
                                    info = struct.pack('!H', n)+bytes([len(full)])+full+b'\0'
                                    return hmac.new(secret, info+b'\1', hashlib.sha256).digest()[:n]
                                key, iv = expand(b'key', 16), expand(b'iv', 12)
                                plain = AESGCM(key).decrypt(iv, b, hdr)
                                assert plain[0] == 20 and len(plain) == 37
                                plain = plain[:4]+bytes([plain[4]^1])+plain[5:]
                                b = AESGCM(key).encrypt(iv, plain, hdr)
                            wire = hdr + b
                            if alter and first and split_hello:
                                wire = b''.join(bytes([22])+hdr[1:3]+struct.pack('!H', len(b[i:i+17]))+b[i:i+17]
                                                for i in range(0, len(b), 17))
                            first = False
                            if fragment:
                                for i in range(0, len(wire), 7):
                                    dest.sendall(wire[i:i+7])
                            else:
                                dest.sendall(wire)
                    except (OSError, EOFError):
                        try:
                            dest.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                forward = threading.Thread(target=pump, args=(client, upstream, True), daemon=True)
                forward.start()
                pump(upstream, client, False)
                forward.join(timeout=2)
        finally:
            self.sock.close()

    def join(self):
        self.thread.join(timeout=5)
        assert not self.thread.is_alive(), 'bridge did not stop'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--binary', default='.build/tls-echo')
    args = ap.parse_args()
    with tempfile.TemporaryDirectory(prefix='lantern-tls-test-') as td:
        d = pathlib.Path(td)
        key, cert = d/'key.pem', d/'cert.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
                        '-keyout', str(key), '-out', str(cert)], check=True, capture_output=True)
        p = port()
        with open(d/'server.log', 'w+') as log:
            server = subprocess.Popen([args.binary, str(cert), str(key), str(p)], stdout=log, stderr=log)
            try:
                for _ in range(200):
                    if server.poll() is not None:
                        log.seek(0)
                        raise AssertionError(log.read())
                    try:
                        with socket.create_connection(('127.0.0.1', p), timeout=.1):
                            break
                    except OSError:
                        time.sleep(.02)
                exchange(p, cert, b'hello TLS\x00\xff')
                exchange(p, cert, b'P-256 handshake', group='prime256v1')
                exchange(p, cert, b'no ALPN', ())
                exchange(p, cert, os.urandom(256*1024))
                with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
                    list(pool.map(lambda _: exchange(p, cert, os.urandom(8192)), range(36)))
                for settings in [dict(fragment=True), dict(split_hello=True), dict(fragment=True, split_hello=True)]:
                    bridge = Bridge(p, **settings)
                    exchange(bridge.port, cert, os.urandom(32768))
                    bridge.join()
                for encrypted_record in [1, 2]:
                    bridge = Bridge(p, mutate=encrypted_record)
                    try:
                        exchange(bridge.port, cert, b'tamper test')
                    except (OSError, ssl.SSLError, AssertionError):
                        pass
                    else:
                        raise AssertionError('tampered record accepted')
                    bridge.join()
                keylog = d/'test-only-traffic-secrets.log'
                bridge = Bridge(p, forge=keylog)
                try:
                    exchange(bridge.port, cert, b'wrong Finished', keylog=keylog)
                except (OSError, ssl.SSLError, AssertionError):
                    pass
                else:
                    raise AssertionError('valid-AEAD/wrong-Finished accepted')
                bridge.join()
                try:
                    exchange(p, cert, b'unsupported ALPN', ('h2',))
                except (OSError, ssl.SSLError):
                    pass
                else:
                    raise AssertionError('unsupported ALPN accepted')
                c = context(cert)
                c.minimum_version = c.maximum_version = ssl.TLSVersion.TLSv1_2
                with socket.create_connection(('127.0.0.1', p), timeout=3) as raw:
                    try:
                        c.wrap_socket(raw, server_hostname='localhost')
                    except (OSError, ssl.SSLError):
                        pass
                    else:
                        raise AssertionError('TLS 1.2 accepted')
                # Openssl's command mode requests a bidirectional KeyUpdate.
                client = subprocess.Popen(['openssl', 's_client', '-connect', f'127.0.0.1:{p}',
                    '-servername', 'localhost', '-CAfile', str(cert), '-tls1_3', '-groups', 'X25519',
                    '-alpn', 'http/1.1'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    client.stdin.write(b'before-update\n'); client.stdin.flush(); time.sleep(.15)
                    client.stdin.write(b'K\n'); client.stdin.flush(); time.sleep(.15)
                    client.stdin.write(b'after-update\n'); client.stdin.flush(); time.sleep(.15)
                    client.stdin.write(b'Q\n'); client.stdin.flush()
                    out, err = client.communicate(timeout=5)
                    assert b'before-update' in out and b'after-update' in out, (out, err)
                finally:
                    if client.poll() is None:
                        client.kill(); client.wait()
                exchange(p, cert, b'still healthy')
            finally:
                server.terminate()
                server.wait(timeout=5)
        print('OpenSSL interoperability passed: certificates, concurrency, fragmentation, large transfer, tampering, forged Finished, ALPN, downgrade rejection, KeyUpdate, closure')


if __name__ == '__main__':
    main()
