#!/usr/bin/env python3
"""Independent TLS negotiation peers: HRR invariants and authenticated OpenSSL retries.
All keys and optional traffic are confined to disposable loopback processes.
"""
import argparse
import os
import pathlib
import select
import socket
import struct
import subprocess
import tempfile
import threading
import time
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives import serialization

RETRY = bytes.fromhex('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c')

def vector(size, value):
    return len(value).to_bytes(size, 'big') + value

def ext(kind, value):
    return struct.pack('!H', kind) + vector(2, value)

def message(kind, value):
    return bytes([kind]) + vector(3, value)

def record(kind, value):
    return bytes([kind]) + b'\x03\x03' + vector(2, value)

def send_handshake(connection, wire, split=16384):
    for offset in range(0, len(wire), split):
        connection.sendall(record(22, wire[offset:offset+split]))

def exact(connection, size):
    result = b''
    while len(result) < size:
        block = connection.recv(size-len(result))
        if not block:
            raise EOFError
        result += block
    return result

def read_record(connection):
    kind, version, size = struct.unpack('!BHH', exact(connection, 5))
    assert version in (0x0301, 0x0303) and size <= 16640
    return kind, exact(connection, size)

def read_handshake(connection):
    result = b''
    for _ in range(128):
        kind, payload = read_record(connection)
        if kind == 20:
            assert payload == b'\x01' and not result
            continue
        assert kind == 22, (kind, payload[:16])
        result += payload
        if len(result) >= 4:
            size = 4+int.from_bytes(result[1:4], 'big')
            if len(result) >= size:
                assert len(result) == size
                return result
    raise AssertionError('too many fragments')

def pop_vector(data, size):
    length = int.from_bytes(data[:size], 'big')
    assert len(data) >= size+length
    return data[size:size+length], data[size+length:]

def extensions(data):
    values = []
    while data:
        kind = int.from_bytes(data[:2], 'big')
        value, data = pop_vector(data[2:], 2)
        values.append((kind, value))
    return values

def parse_client(wire):
    assert wire[0] == 1 and len(wire) == 4+int.from_bytes(wire[1:4], 'big')
    body = wire[4:]
    _, tail = pop_vector(body[34:], 1)
    _, tail = pop_vector(tail, 2)
    _, tail = pop_vector(tail, 1)
    prefix = body[:len(body)-len(tail)]
    values, remaining = pop_vector(tail, 2)
    assert not remaining
    return prefix, extensions(values)

def public(group):
    if group == 29:
        return x25519.X25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

def client_hello(group=29, shares=(), random=b'r'*32, session=b's'*32, changes=None, suites=b'\x13\x01'):
    values = [(0, vector(2, b'\x00'+vector(2, b'localhost'))),
              (10, vector(2, struct.pack('!H', group))),
              (13, vector(2, b'\x08\x04')), (43, vector(1, b'\x03\x04')),
              (16, vector(2, vector(1, b'http/1.1'))),
              (51, vector(2, b''.join(struct.pack('!H', g)+vector(2, key) for g, key in shares)))]
    for kind, value in (changes or []):
        values = [(k, v) for k, v in values if k != kind]
        if value is not None:
            values.append((kind, value))
    return message(1, b'\x03\x03'+random+vector(1, session)+vector(2, suites)+
                   vector(1, b'\x00')+vector(2, b''.join(ext(k, v) for k, v in values)))

def server_hello(session, group=None, key=None, cookie=None, retry=True, extras=b'', suite=0x1301):
    values = ext(43, b'\x03\x04')
    if group is not None:
        values += ext(51, struct.pack('!H', group)+(vector(2, key) if key is not None else b''))
    if cookie is not None:
        values += ext(44, vector(2, cookie))
    return message(2, b'\x03\x03'+(RETRY if retry else b't'*32)+vector(1, session)+
                   struct.pack('!H', suite)+b'\x00'+vector(2, values+extras))

def rejected(connection):
    try:
        for _ in range(3):
            kind, payload = read_record(connection)
            if kind == 20:
                continue
            assert kind == 21, ('unexpected handshake/application data', kind, payload[:12])
            return
    except (EOFError, ConnectionResetError):
        return
    raise AssertionError('connection did not reject malformed negotiation')

def connect(port):
    return socket.create_connection(('127.0.0.1', port), timeout=4)

def openssl_retry(port, cert, group):
    marker = ('authenticated-retry-'+group+'\n').encode()
    process = subprocess.Popen(['openssl', 's_client', '-connect', f'127.0.0.1:{port}',
        '-servername', 'localhost', '-CAfile', str(cert), '-verify_return_error',
        '-verify_hostname', 'localhost', '-tls1_3', '-groups', 'P-384:'+group,
        '-alpn', 'http/1.1', '-msg'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    try:
        process.stdin.write(marker); process.stdin.flush()
        output = b''
        errors = b''
        deadline = time.monotonic()+8
        while marker not in output and time.monotonic() < deadline:
            ready, _, _ = select.select([process.stdout, process.stderr], [], [], .1)
            for stream in ready:
                block = os.read(stream.fileno(), 65536)
                if stream is process.stdout:
                    output += block
                else:
                    errors += block
            if process.poll() is not None:
                break
        assert marker in output, (group, output[-1500:], errors, process.poll())
        # The first P-384 share has no overlap; authenticated echo therefore
        # exercises the server's retry transcript and the second key share.
        assert output.count(b'ClientHello') == 2, output[-1500:]
        assert output.count(b'ServerHello') == 2, output[-1500:]
        process.stdin.write(b'Q\n'); process.stdin.flush()
        tail, error = process.communicate(timeout=5)
        assert process.returncode == 0, (output+tail, error)
    finally:
        if process.poll() is None:
            process.kill(); process.wait()


def check_server(port, cert):
    # Reject excessive lists before quadratic duplicate checking can dominate CPU.
    with connect(port) as connection:
        groups = b''.join(struct.pack('!H', group) for group in range(1, 130))
        send_handshake(connection, client_hello(changes=[(10, vector(2, groups))]))
        rejected(connection)
    for group in (29, 23):
        valid = public(group)
        for change in ['random', 'session', 'sni', 'alpn', 'groups', 'extra', 'missing',
                       'wrong-group', 'multiple', 'short', 'invalid-point', 'cookie', 'padding',
                       'suites', 'compressed', 'out-of-field']:
            with connect(port) as connection:
                send_handshake(connection, client_hello(group))
                retry = read_handshake(connection)
                assert retry[0] == 2 and retry[6:38] == RETRY
                assert ext(51, struct.pack('!H', group)) in retry
                options = {'group': group, 'shares': [(group, valid)]}
                if change == 'random': options['random'] = b'v'*32
                elif change == 'session': options['session'] = b'v'*32
                elif change == 'sni': options['changes'] = [(0, vector(2, b'\x00'+vector(2, b'evil.test')))]
                elif change == 'alpn': options['changes'] = [(16, vector(2, vector(1, b'h2')))]
                elif change == 'groups': options['changes'] = [(10, vector(2, b'\x00\x1d\x00\x17'))]
                elif change == 'extra': options['changes'] = [(1234, b'new')]
                elif change == 'missing': options['shares'] = []
                elif change == 'wrong-group': options['shares'] = [(23 if group == 29 else 29, public(23 if group == 29 else 29))]
                elif change == 'multiple': options['shares'] *= 2
                elif change == 'short': options['shares'] = [(group, valid[:-1])]
                elif change == 'invalid-point': options['shares'] = [(group, b'\x00'*32 if group == 29 else b'\x04'+b'\x00'*64)]
                elif change == 'cookie': options['changes'] = [(44, vector(2, b'unsolicited'))]
                elif change == 'padding': options['changes'] = [(21, b'nonzero')]
                elif change == 'suites': options['suites'] = b'\x13\x01\x13\x02'
                elif change == 'compressed': options['shares'] = [(group, b'\x02'+valid[-32:])]
                elif change == 'out-of-field': options['shares'] = [(group, b'\x04'+b'\xff'*64)]
                send_handshake(connection, client_hello(**options), split=17)
                rejected(connection)
        # PSK binders/ages may change, but a new identity cannot appear. We do
        # not select a PSK: successful negotiation remains certificate ECDHE.
        def psk(identity, age=0, binder=b'b'*32):
            return vector(2, vector(2, identity)+age.to_bytes(4, 'big'))+vector(2, vector(1, binder))
        for changed_identity in [False, True]:
            with connect(port) as connection:
                first = client_hello(group, changes=[(45, vector(1, b'\x01')), (41, psk(b'ticket'))])
                send_handshake(connection, first)
                assert read_handshake(connection)[6:38] == RETRY
                next_hello = client_hello(group, [(group, valid)], changes=[(21, b'\x00'*23),
                    (45, vector(1, b'\x01')), (41, psk(b'new-ticket' if changed_identity else b'ticket', 7, b'c'*32))])
                send_handshake(connection, next_hello)
                if changed_identity:
                    rejected(connection)
                else:
                    response = read_handshake(connection)
                    assert response[0] == 2 and response[6:38] != RETRY
        openssl_retry(port, cert, 'X25519' if group == 29 else 'P-256')


def check_client(binary, cert):
    cases = ['already-offered', 'unsupported', 'nothing', 'empty-cookie', 'bad-session',
             'bad-suite', 'duplicate-version', 'unsolicited', 'second-retry',
             'changed-group', 'invalid-p256', 'cookie-only', 'large-cookie']
    for case in cases:
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0)); listener.listen(1); listener.settimeout(5)
            errors = []
            def serve():
                try:
                    connection, _ = listener.accept()
                    with connection:
                        connection.settimeout(4)
                        first = read_handshake(connection)
                        prefix, original = parse_client(first)
                        session, _ = pop_vector(first[38:], 1)
                        group, cookie, extras, suite = 23, None, b'', 0x1301
                        if case == 'already-offered': group = 29
                        elif case == 'unsupported': group = 24
                        elif case == 'nothing': group = None
                        elif case == 'empty-cookie': cookie = b''
                        elif case == 'bad-session': session = b'wrong'
                        elif case == 'bad-suite': suite = 0x1302
                        elif case == 'duplicate-version': extras = ext(43, b'\x03\x04')
                        elif case == 'unsolicited': extras = ext(16, vector(2, vector(1, b'http/1.1')))
                        elif case == 'cookie-only': group, cookie = None, b'cookie'
                        elif case == 'large-cookie': cookie = b'c'*20000
                        retry = server_hello(session, group, cookie=cookie, extras=extras, suite=suite)
                        send_handshake(connection, retry, split=613 if case == 'large-cookie' else 17)
                        if case in ['second-retry', 'changed-group', 'invalid-p256', 'cookie-only', 'large-cookie']:
                            second = read_handshake(connection)
                            second_prefix, values = parse_client(second)
                            assert prefix == second_prefix
                            stable = lambda entries: [(k,v) for k,v in entries if k not in (44,51)]
                            assert stable(original) == stable(values)
                            mapping = dict(values)
                            if cookie is not None: assert mapping[44] == vector(2, cookie)
                            shares, _ = pop_vector(mapping[51], 2)
                            selected = int.from_bytes(shares[:2], 'big')
                            assert selected == (29 if group is None else group)
                            if group is None: assert mapping[51] == dict(original)[51]
                            if case in ['second-retry', 'large-cookie', 'cookie-only']:
                                send_handshake(connection, retry)
                            elif case == 'changed-group':
                                send_handshake(connection, server_hello(session, 29, public(29), retry=False))
                            else:
                                send_handshake(connection, server_hello(session, 23, b'\x04'+b'\x00'*64, retry=False))
                        rejected(connection)
                except BaseException as error:
                    errors.append(error)
            worker = threading.Thread(target=serve, daemon=True); worker.start()
            result = subprocess.run([binary, '127.0.0.1', str(listener.getsockname()[1]), str(cert), '/', 'localhost'],
                                    capture_output=True, timeout=12)
            worker.join(timeout=6)
            assert not worker.is_alive() and not errors, (case, errors)
            assert result.returncode != 0, (case, result)
    print('Negotiation adversarial checks passed: retry invariants, duplicate/unsolicited extensions, second retry, cookies, malformed keys, authenticated OpenSSL retries')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', required=True)
    parser.add_argument('--client', required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='lantern-negotiation-') as tmp:
        directory = pathlib.Path(tmp)
        cert, key = directory/'cert.pem', directory/'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost',
            '-addext', 'keyUsage=digitalSignature', '-keyout', str(key), '-out', str(cert)],
            check=True, capture_output=True)
        with socket.socket() as temporary:
            temporary.bind(('127.0.0.1', 0)); port = temporary.getsockname()[1]
        with (directory/'server.log').open('w+') as log:
            server = subprocess.Popen([args.server, str(cert), str(key), str(port)], stdout=log, stderr=log)
            try:
                for _ in range(200):
                    assert server.poll() is None, 'echo server died'
                    try:
                        with connect(port): break
                    except OSError: time.sleep(.02)
                check_server(port, cert)
                check_client(args.client, cert)
                assert server.poll() is None, 'malformed negotiation killed server'
            finally:
                server.terminate(); server.wait(timeout=5)


if __name__ == '__main__':
    main()
