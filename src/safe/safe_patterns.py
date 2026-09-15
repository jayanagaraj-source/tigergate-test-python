"""Negative controls for SAST: secure equivalents of the patterns in src/sast/."""
import hashlib
import hmac
import os
import re
import secrets
import shlex
import sqlite3
import subprocess
import tempfile

import defusedxml.ElementTree as SafeET
import requests
import yaml
from flask import Flask, abort, redirect, request, send_from_directory, url_for
from markupsafe import escape
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ["FLASK_SECRET_KEY"]
UPLOAD_DIR = "/srv/uploads"
ALLOWED_REDIRECTS = {"home", "dashboard"}


def find_user(conn: sqlite3.Connection, username: str):
    # tg-negative: NEG-SAST-001 | Parameterized query
    return conn.execute("SELECT * FROM users WHERE name = ?", (username,)).fetchall()


def find_order(conn: sqlite3.Connection, user_id: str):
    safe_id = int(user_id)
    # tg-negative: NEG-SAST-002 | [soft] f-string SQL with value sanitised by int() (taint engines should clear it)
    return conn.execute(f"SELECT * FROM orders WHERE user_id = {safe_id}").fetchall()


def ping_host(host: str) -> bytes:
    # tg-negative: NEG-SAST-003 | subprocess with argument list, no shell
    return subprocess.run(["ping", "-c", "1", host], check=True, capture_output=True).stdout


def list_dir(path: str) -> bytes:
    # tg-negative: NEG-SAST-004 | [soft] shlex.quote before shell execution
    return subprocess.check_output("ls -la " + shlex.quote(path), shell=True)


def load_config(stream):
    # tg-negative: NEG-SAST-005 | yaml.safe_load
    return yaml.safe_load(stream)


def hash_password(password: str, salt: bytes) -> bytes:
    # tg-negative: NEG-SAST-006 | PBKDF2-HMAC-SHA256 with 600k iterations
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)


def file_checksum(data: bytes) -> str:
    # tg-negative: NEG-SAST-007 | MD5 explicitly marked non-security (usedforsecurity=False)
    return hashlib.md5(data, usedforsecurity=False).hexdigest()


def new_reset_token() -> str:
    # tg-negative: NEG-SAST-008 | CSPRNG via secrets module
    return secrets.token_urlsafe(32)


def fetch(url: str) -> str:
    # tg-negative: NEG-SAST-009 | TLS verification on (default) with timeout
    return requests.get(url, timeout=10).text


def verify_webhook(signature: str, expected: str) -> bool:
    # tg-negative: NEG-SAST-010 | Constant-time comparison
    return hmac.compare_digest(signature, expected)


def scratch_file() -> str:
    # tg-negative: NEG-SAST-011 | tempfile.mkstemp
    fd, path = tempfile.mkstemp()
    os.close(fd)
    return path


def parse_invoice(xml_text: str):
    # tg-negative: NEG-SAST-012 | defusedxml parser
    return SafeET.fromstring(xml_text)


def is_valid_label(label: str) -> bool:
    # tg-negative: NEG-SAST-013 | Linear-time regex
    return re.fullmatch(r"[a-z0-9-]{1,63}", label) is not None


@app.route("/hello")
def hello():
    # tg-negative: NEG-SAST-014 | User input HTML-escaped before rendering
    return "<h1>Hello " + str(escape(request.args.get("name", ""))) + "</h1>"


@app.route("/download")
def download():
    # tg-negative: NEG-SAST-015 | send_from_directory confines path to UPLOAD_DIR
    return send_from_directory(UPLOAD_DIR, request.args["file"])


@app.route("/upload", methods=["POST"])
def upload():
    uploaded = request.files["file"]
    # tg-negative: NEG-SAST-016 | secure_filename applied to upload name
    uploaded.save(os.path.join(UPLOAD_DIR, secure_filename(uploaded.filename)))
    return "ok"


@app.route("/go")
def go():
    target = request.args.get("next", "home")
    if target not in ALLOWED_REDIRECTS:
        abort(400)
    # tg-negative: NEG-SAST-017 | Redirect target validated against allow-list
    return redirect(url_for(target))


if __name__ == "__main__":
    # tg-negative: NEG-SAST-018 | Loopback bind, debug off
    app.run(host="127.0.0.1", port=5000, debug=False)
