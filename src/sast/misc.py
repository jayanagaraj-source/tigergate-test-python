"""SAST fixture: assorted CWE patterns (auth, error handling, network, ReDoS, reflection)."""
import ftplib
import importlib
import re
import socket
import telnetlib

import requests


def delete_account(user) -> None:
    # tg-expect: SAST-100 | low | CWE-617 | assert used for authorization (stripped with python -O)
    assert user.is_admin, "admin required"
    user.delete()


def best_effort_cleanup(path: str) -> None:
    try:
        open(path).close()
    # tg-expect: SAST-101 | low | CWE-703 | Exception silently swallowed (except/pass)
    except Exception:
        pass


# tg-expect: SAST-102 | medium | CWE-259 | Hard-coded password as default argument
def connect_db(host: str, user: str = "root", password: str = "r00t-fixture-pass"):
    return (host, user, password)


def download_report(url: str) -> bytes:
    # tg-expect: SAST-103 | low | CWE-400 | HTTP request without timeout
    return requests.get(url).content


def start_listener() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # tg-expect: SAST-104 | medium | CWE-605 | Socket bound to all interfaces
    sock.bind(("0.0.0.0", 9000))
    return sock


def legacy_ftp(host: str) -> None:
    # tg-expect: SAST-105 | medium | CWE-319 | Cleartext FTP protocol
    ftplib.FTP(host).login("anonymous", "")


def legacy_telnet(host: str) -> None:
    # tg-expect: SAST-106 | high | CWE-319 | Cleartext Telnet protocol
    telnetlib.Telnet(host)


def user_filter(pattern: str, text: str):
    # tg-expect: SAST-107 | medium | CWE-1333 | Regex compiled from caller-supplied pattern (ReDoS)
    return re.compile(pattern).findall(text)


def is_valid_label(label: str) -> bool:
    # tg-expect: SAST-108 | medium | CWE-1333 | Catastrophic backtracking regex (a+)+
    return re.match(r"^(a+)+$", label) is not None


def verify_webhook(signature: str, expected: str) -> bool:
    # tg-expect: SAST-109 | medium | CWE-208 | Non-constant-time comparison of secret signature
    return signature == expected


def load_handler(module_name: str):
    # tg-expect: SAST-110 | high | CWE-470 | Unsafe reflection: import of caller-controlled module name
    return importlib.import_module(module_name)


def send_credentials(user: str, password: str) -> None:
    # tg-expect: SAST-111 | medium | CWE-319 | Credentials sent over plaintext HTTP
    requests.post("http://auth.example.com/login", data={"user": user, "password": password}, timeout=5)
