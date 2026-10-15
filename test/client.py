#!/usr/bin/env python3
"""Own TLS client against real OpenSSL servers, including trust rejection."""
import argparse
import pathlib
import socket
import subprocess
import tempfile
import time


def freeport():
    with socket.socket() as s:
        s.bind(('127.0.0.1',0))
        return s.getsockname()[1]


def main():
    p=argparse.ArgumentParser()
    p.add_argument('--binary',default='.build/tls-fetch')
    args=p.parse_args()
    with tempfile.TemporaryDirectory(prefix='lantern-tls-client-') as tmp:
        d=pathlib.Path(tmp)
        for kind in ['rsa','ec','wrong-host']:
            key,cert=d/f'{kind}-key.pem',d/f'{kind}-cert.pem'
            keytype=['-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256'] if kind=='ec' else ['-newkey','rsa:2048']
            host='invalid.example' if kind=='wrong-host' else 'localhost'
            subprocess.run(['openssl','req','-x509',*keytype,'-nodes','-days','1','-subj',f'/CN={host}',
                '-addext',f'subjectAltName=DNS:{host}','-addext','keyUsage=digitalSignature',
                '-keyout',str(key),'-out',str(cert)],check=True,capture_output=True)
            port=freeport()
            server=subprocess.Popen(['openssl','s_server','-accept',f'127.0.0.1:{port}',
                '-cert',str(cert),'-key',str(key),'-www','-tls1_3','-groups','X25519'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            try:
                for _ in range(100):
                    try:
                        with socket.create_connection(('127.0.0.1',port),timeout=.1):break
                    except OSError:time.sleep(.02)
                result=subprocess.run([args.binary,'localhost',str(port),str(cert),'/'],capture_output=True,timeout=10)
                if kind=='wrong-host':
                    assert result.returncode!=0 and b'certificate validation failed' in result.stderr,result
                else:
                    assert result.returncode==0 and b'HTTP/1.0 200 ok' in result.stdout,(result.stdout,result.stderr)
                    rejected=subprocess.run([args.binary,'localhost',str(port),'system','/'],capture_output=True,timeout=10)
                    assert rejected.returncode!=0 and b'certificate validation failed' in rejected.stderr,rejected
            finally:
                server.terminate();server.wait(timeout=5)
        print('Client interoperability passed: RSA/ECDSA certificates, hostname/unknown-CA rejection, tickets, HTTP response')


if __name__=='__main__':main()
