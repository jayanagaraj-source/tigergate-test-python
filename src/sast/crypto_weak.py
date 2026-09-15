"""SAST fixture: weak cryptography and TLS misuse (CWE-295, CWE-326, CWE-327, CWE-328, CWE-329, CWE-338, CWE-347)."""
import hashlib
import random
import ssl

import jwt
import paramiko
import requests
from Crypto.Cipher import AES, DES
from cryptography.hazmat.primitives.asymmetric import rsa


def hash_password_md5(password: str) -> str:
    # tg-expect: SAST-040 | high | CWE-328 | MD5 used to hash passwords
    return hashlib.md5(password.encode()).hexdigest()


def hash_password_sha1(password: str) -> str:
    # tg-expect: SAST-041 | medium | CWE-328 | SHA-1 used to hash passwords
    return hashlib.sha1(password.encode()).hexdigest()


def encrypt_des(key: bytes, data: bytes) -> bytes:
    # tg-expect: SAST-042 | high | CWE-327 | Broken cipher: DES
    return DES.new(key, DES.MODE_ECB).encrypt(data)


def encrypt_aes_ecb(key: bytes, data: bytes) -> bytes:
    # tg-expect: SAST-043 | medium | CWE-327 | Insecure block mode: AES-ECB
    return AES.new(key, AES.MODE_ECB).encrypt(data)


def encrypt_aes_static_iv(key: bytes, data: bytes) -> bytes:
    # tg-expect: SAST-044 | medium | CWE-329 | Static, predictable IV for AES-CBC
    return AES.new(key, AES.MODE_CBC, iv=b"0000000000000000").encrypt(data)


def new_reset_token() -> str:
    # tg-expect: SAST-045 | medium | CWE-338 | Non-cryptographic PRNG used for security token
    return str(random.randint(100000, 999999))


def new_rsa_key():
    # tg-expect: SAST-046 | high | CWE-326 | RSA key size below 2048 bits
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)


def fetch_insecure(url: str) -> str:
    # tg-expect: SAST-047 | high | CWE-295 | TLS certificate verification disabled (verify=False)
    return requests.get(url, verify=False, timeout=10).text


def unverified_context():
    # tg-expect: SAST-048 | high | CWE-295 | ssl._create_unverified_context disables certificate validation
    return ssl._create_unverified_context()


def legacy_tls_context():
    # tg-expect: SAST-049 | high | CWE-327 | Deprecated protocol TLSv1
    return ssl.SSLContext(ssl.PROTOCOL_TLSv1)


def ssh_connect(host: str):
    client = paramiko.SSHClient()
    # tg-expect: SAST-050 | high | CWE-295 | Paramiko AutoAddPolicy accepts unknown host keys
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host)
    return client


def read_claims(token: str) -> dict:
    # tg-expect: SAST-051 | critical | CWE-347 | JWT decoded without signature verification
    return jwt.decode(token, options={"verify_signature": False})
