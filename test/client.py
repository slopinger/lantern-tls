#!/usr/bin/env python3
"""Own TLS client against real OpenSSL servers, including trust rejection."""
import argparse
import pathlib
import socket
import ssl
import threading
import subprocess
import tempfile
import time


def freeport():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0))
        return s.getsockname()[1]


def check_sni(binary, cert, key, reference, expected):
    observed = []
    errors = []
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    context.set_ecdh_curve('X25519')
    context.set_servername_callback(lambda _socket, name, _context: observed.append(name))
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(5)
        port = listener.getsockname()[1]
        def serve():
            try:
                connection, _ = listener.accept()
                connection.settimeout(5)
                with context.wrap_socket(connection, server_side=True) as secured:
                    request = b''
                    while b'\r\n\r\n' not in request:
                        block = secured.recv(4096)
                        assert block, 'missing HTTP request'
                        request += block
                    secured.sendall(b'HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok')
                    try:
                        secured.unwrap()
                    except ssl.SSLEOFError:
                        pass  # tls-fetch closes after receiving the authenticated close_notify.
            except Exception as error:
                errors.append(error)
        worker = threading.Thread(target=serve, daemon=True)
        worker.start()
        result = subprocess.run([binary, '127.0.0.1', str(port), str(cert), '/', reference],
                                capture_output=True, timeout=10)
        worker.join(timeout=6)
        assert not worker.is_alive() and not errors, errors
        assert result.returncode == 0 and result.stdout.endswith(b'ok'), result
        assert observed == [expected], (reference, observed, expected)


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--binary',default='.build/tls-fetch')
    args=p.parse_args()
    with tempfile.TemporaryDirectory(prefix='lantern-tls-client-') as tmp:
        d=pathlib.Path(tmp)
        cases = [
            ('rsa', 'localhost', 'DNS:localhost', 'localhost', True),
            ('ec', 'localhost', 'DNS:localhost', 'localhost', True),
            ('wrong-host', 'invalid.example', 'DNS:invalid.example', 'localhost', False),
            ('cn-only', 'localhost', None, 'localhost', False),
            ('ip', 'wrong.example', 'IP:127.0.0.1', '127.0.0.1', True),
            ('ip-dns', '127.0.0.1', 'DNS:127.0.0.1', '127.0.0.1', False),
            ('ip-wrong', '127.0.0.1', 'IP:127.0.0.2', '127.0.0.1', False),
            ('ip-cn-only', '127.0.0.1', None, '127.0.0.1', False),
            ('wildcard', 'unused', 'DNS:*.example.test', 'www.example.test', True),
            ('wildcard-deep', 'unused', 'DNS:*.example.test', 'a.b.example.test', False),
            ('partial-wildcard', 'unused', 'DNS:f*.example.test', 'foo.example.test', False),
            ('case', 'unused', 'DNS:LOCALHOST', 'LoCaLhOsT', True),
            ('ip6', 'unused', 'IP:::1', '::1', True),
            ('ip6-wrong', '::1', 'IP:::2', '::1', False),
        ]
        for kind, host, san, reference, accepted in cases:
            key,cert=d/f'{kind}-key.pem',d/f'{kind}-cert.pem'
            keytype=['-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256'] if kind=='ec' else ['-newkey','rsa:2048']
            subprocess.run(['openssl','req','-x509',*keytype,'-nodes','-days','1','-subj',f'/CN={host}',
                *(['-addext',f'subjectAltName={san}'] if san else []),'-addext','keyUsage=digitalSignature',
                '-keyout',str(key),'-out',str(cert)],check=True,capture_output=True)
            port=freeport()
            server=subprocess.Popen(['openssl','s_server','-accept',f'127.0.0.1:{port}',
                '-cert',str(cert),'-key',str(key),'-www','-tls1_3','-groups','X25519'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            try:
                for _ in range(100):
                    try:
                        with socket.create_connection(('127.0.0.1',port),timeout=.1):break
                    except OSError:time.sleep(.02)
                result=subprocess.run([args.binary,'127.0.0.1',str(port),str(cert),'/',reference],capture_output=True,timeout=10)
                if not accepted:
                    assert result.returncode!=0 and b'certificate validation failed' in result.stderr,result
                else:
                    assert result.returncode==0 and b'HTTP/1.0 200 ok' in result.stdout,(result.stdout,result.stderr)
                    rejected=subprocess.run([args.binary,'127.0.0.1',str(port),'system','/',reference],capture_output=True,timeout=10)
                    assert rejected.returncode!=0 and b'certificate validation failed' in rejected.stderr,rejected
                    if kind in ['rsa', 'case', 'ip', 'ip6']:
                        check_sni(args.binary, cert, key, reference, None if kind.startswith('ip') else reference.lower())
            finally:
                server.terminate();server.wait(timeout=5)
        print('Client interoperability passed: RSA/ECDSA, SAN-only DNS/IP identities, wildcard scope, no CN fallback, unknown-CA rejection, tickets, HTTP response')


if __name__=='__main__':main()
