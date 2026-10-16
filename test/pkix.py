#!/usr/bin/env python3
"""Independent generated-chain policy checks; no external CA or network."""
import argparse
import datetime
import ipaddress
import pathlib
import socket
import ssl
import subprocess
import tempfile
import threading
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID, ObjectIdentifier


def run(binary):
    now = datetime.datetime.now(datetime.timezone.utc)
    keys = [rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(3)]
    def cert(name, key, issuer, signing, ca, extensions=()):
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        b = (x509.CertificateBuilder().subject_name(subject)
             .issuer_name(subject if issuer is None else issuer.subject)
             .public_key(key.public_key()).serial_number(x509.random_serial_number())
             .not_valid_before(now-datetime.timedelta(days=1))
             .not_valid_after(now+datetime.timedelta(days=2))
             .add_extension(x509.BasicConstraints(ca=ca, path_length=2 if ca else None), True)
             .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                 key_encipherment=False, data_encipherment=False, key_agreement=False,
                 key_cert_sign=ca, crl_sign=ca, encipher_only=None, decipher_only=None), True))
        for extension, critical in extensions:
            b = b.add_extension(extension, critical)
        return b.sign(signing, hashes.SHA256())
    root = cert('root', keys[0], None, keys[0], True)
    dns = lambda n: x509.DNSName(n)
    ip = lambda n: x509.IPAddress(ipaddress.ip_address(n))
    network = lambda n: x509.IPAddress(ipaddress.ip_network(n))
    unknown = x509.UnrecognizedExtension(ObjectIdentifier('1.3.6.1.4.1.55555.7'), b'\x05\x00')
    cases = [
        ('ordinary-chain', [], [dns('www.example.test')], 'www.example.test', True, []),
        ('dns-permitted', [dns('example.test')], [dns('www.example.test')], 'www.example.test', True, []),
        ('dns-violation', [dns('allowed.test')], [dns('www.example.test')], 'www.example.test', False, []),
        ('dns-extra-san', [dns('example.test')], [dns('www.example.test'), dns('outside.test')], 'www.example.test', False, []),
        ('ipv4-permitted', [network('127.0.0.0/8')], [ip('127.0.0.1')], '127.0.0.1', True, []),
        ('ipv4-violation', [network('192.0.2.0/24')], [ip('127.0.0.1')], '127.0.0.1', False, []),
        ('ipv6-permitted', [network('2001:db8::/32')], [ip('2001:db8::1')], '2001:db8::1', True, []),
        ('ipv6-violation', [network('2001:db8:1::/48')], [ip('2001:db8:2::1')], '2001:db8:2::1', False, []),
        ('dns-excluded-case', [], [dns('WWW.Example.Test')], 'www.example.test', False, [],
         [(x509.NameConstraints(None, [dns('example.test')]), True)]),
        ('ipv4-excluded', [], [ip('127.0.0.1')], '127.0.0.1', False, [],
         [(x509.NameConstraints(None, [network('127.0.0.0/8')]), True)]),
        ('ipv6-excluded', [], [ip('2001:db8::1')], '2001:db8::1', False, [],
         [(x509.NameConstraints(None, [network('2001:db8::/32')]), True)]),
        ('intermediate-purpose', [], [dns('www.example.test')], 'www.example.test', False, [],
         [(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False)]),
        ('intermediate-critical', [], [dns('www.example.test')], 'www.example.test', False, [], [(unknown, True)]),
        ('unsupported-uri-constraint', [], [dns('www.example.test')], 'www.example.test', False, [],
         [(x509.NameConstraints([x509.UniformResourceIdentifier('example.test')], None), True)]),
        ('malformed-constraints', [], [dns('www.example.test')], 'www.example.test', False, [],
         [(x509.UnrecognizedExtension(ObjectIdentifier('2.5.29.30'), b'\x05\x00'), True)]),
        ('trusted-intermediate-constraints', [], [dns('www.example.test')], 'www.example.test', False, []),
        ('root-constraints', [], [dns('www.example.test')], 'www.example.test', False, []),
        ('san-limit-valid', [], [dns('www.example.test')] + [dns(f'n{i}.example.test') for i in range(127)], 'www.example.test', True, []),
        ('san-limit-rejected', [], [dns('www.example.test')] + [dns(f'n{i}.example.test') for i in range(128)], 'www.example.test', False, []),
        ('constraint-limit-valid', [dns('example.test')] + [dns(f'n{i}.test') for i in range(63)], [dns('www.example.test')], 'www.example.test', True, []),
        ('constraint-limit-rejected', [dns('example.test')] + [dns(f'n{i}.test') for i in range(64)], [dns('www.example.test')], 'www.example.test', False, []),
        ('noncontiguous-ip-mask', [], [ip('127.0.0.1')], '127.0.0.1', False, [],
         [(x509.UnrecognizedExtension(ObjectIdentifier('2.5.29.30'), bytes.fromhex('300ea00c300a87087f000000ff00ff00')), True)]),
        ('issuer-not-ca', [], [dns('www.example.test')], 'www.example.test', False, []),
        ('trusted-intermediate-valid', [], [dns('www.example.test')], 'www.example.test', True, []),
        ('root-valid-constraints', [], [dns('www.example.test')], 'www.example.test', True, []),
        ('leaf-critical', [], [dns('www.example.test')], 'www.example.test', False, [(unknown, True)]),
        ('leaf-noncritical', [], [dns('www.example.test')], 'www.example.test', True, [(unknown, False)]),
    ]
    failures = []
    with tempfile.TemporaryDirectory(prefix='lantern-pkix-') as temporary:
        d = pathlib.Path(temporary)
        trust = d/'root.pem'; trust.write_bytes(root.public_bytes(serialization.Encoding.PEM))
        key = d/'key.pem'; key.write_bytes(keys[2].private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        for case in cases:
            label, permitted, names, reference, expected, extra = case[:6]
            issuer_extra = case[6] if len(case) > 6 else []
            extensions = [(x509.NameConstraints(permitted_subtrees=permitted, excluded_subtrees=None), True)] if permitted else []
            trust.write_bytes(root.public_bytes(serialization.Encoding.PEM))
            if label in ['root-constraints', 'root-valid-constraints']:
                constrained_root = cert('root', keys[0], None, keys[0], True,
                    [(x509.NameConstraints([dns('example.test' if label.endswith('valid') or label == 'root-valid-constraints' else 'allowed.test')], None), True)])
                trust.write_bytes(constrained_root.public_bytes(serialization.Encoding.PEM))
            if label in ['trusted-intermediate-constraints', 'trusted-intermediate-valid']:
                constrained_issuer = cert('intermediate', keys[1], root, keys[0], True,
                    [(x509.NameConstraints([dns('example.test' if label.endswith('valid') or label == 'root-valid-constraints' else 'allowed.test')], None), True)])
                trust.write_bytes(constrained_issuer.public_bytes(serialization.Encoding.PEM))
            intermediate = cert('intermediate', keys[1], root, keys[0], label != 'issuer-not-ca', extensions + issuer_extra)
            leaf = cert(reference, keys[2], intermediate, keys[1], False,
                [(x509.SubjectAlternativeName(names), False),
                 (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)] + extra)
            chain = d/'chain.pem'; chain.write_bytes(leaf.public_bytes(serialization.Encoding.PEM)+intermediate.public_bytes(serialization.Encoding.PEM))
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(chain, key); context.set_ecdh_curve('X25519')
            observed = []
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0)); listener.listen(); listener.settimeout(5)
                def serve():
                    try:
                        connection, _ = listener.accept(); connection.settimeout(5)
                        with context.wrap_socket(connection, server_side=True) as secured:
                            request = secured.recv(8192)
                            if request: observed.append(request)
                            secured.sendall(b'HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok')
                            try: secured.unwrap()
                            except ssl.SSLError: pass
                    except (ssl.SSLError, OSError): pass  # rejected handshakes close the peer
                worker = threading.Thread(target=serve, daemon=True); worker.start()
                result = subprocess.run([binary, '127.0.0.1', str(listener.getsockname()[1]), str(trust), '/', reference], capture_output=True, timeout=12)
                worker.join(6)
                assert not worker.is_alive(), label
            accepted = result.returncode == 0 and result.stdout.endswith(b'ok')
            print(f'{label}: accepted={accepted}, expected={expected}, HTTP sent={bool(observed)}', flush=True)
            if accepted != expected or (not expected and observed): failures.append(label)
    assert not failures, failures

if __name__ == '__main__':
    parser=argparse.ArgumentParser(); parser.add_argument('--binary', required=True)
    run(parser.parse_args().binary)
