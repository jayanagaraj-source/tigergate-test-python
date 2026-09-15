"""SAST fixture: Flask app with source-to-sink (taint) flows.

Sources are ``flask.request`` attributes; each marked sink receives tainted data.
"""
import os
import pickle
import sqlite3
import subprocess

import requests
from flask import Flask, make_response, redirect, render_template_string, request, send_file

app = Flask(__name__)
# tg-expect: SAST-060 | high | CWE-798 | Hard-coded Flask SECRET_KEY
app.config["SECRET_KEY"] = "flask-fixture-secret-key-do-not-use"
# tg-expect: SAST-061 | medium | CWE-614 | Session cookie sent without Secure flag
app.config["SESSION_COOKIE_SECURE"] = False
# tg-expect: SAST-062 | medium | CWE-1004 | Session cookie readable by JavaScript (HttpOnly disabled)
app.config["SESSION_COOKIE_HTTPONLY"] = False
# tg-expect: SAST-063 | medium | CWE-352 | CSRF protection globally disabled
app.config["WTF_CSRF_ENABLED"] = False


@app.route("/search")
def search():
    term = request.args.get("q", "")
    conn = sqlite3.connect("app.db")
    # tg-expect: SAST-064 | critical | CWE-89 | Tainted SQL injection: request.args -> execute
    rows = conn.execute("SELECT * FROM products WHERE name LIKE '%" + term + "%'").fetchall()
    return {"rows": rows}


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    # tg-expect: SAST-065 | high | CWE-79 | Reflected XSS: request.args concatenated into HTML response
    return make_response("<h1>Hello " + name + "</h1>")


@app.route("/preview", methods=["POST"])
def preview():
    template = request.form["template"]
    # tg-expect: SAST-066 | critical | CWE-1336 | Tainted SSTI: request.form -> render_template_string
    return render_template_string(template)


@app.route("/download")
def download():
    filename = request.args["file"]
    # tg-expect: SAST-067 | high | CWE-22 | Path traversal: request.args -> send_file
    return send_file(os.path.join("/srv/uploads", filename))


@app.route("/read")
def read_file():
    path = request.args["path"]
    # tg-expect: SAST-068 | high | CWE-22 | Path traversal: request.args -> open()
    with open(path) as handle:
        return handle.read()


@app.route("/fetch")
def fetch():
    url = request.args["url"]
    # tg-expect: SAST-069 | high | CWE-918 | SSRF: request.args -> requests.get
    return requests.get(url, timeout=5).text


@app.route("/go")
def go():
    # tg-expect: SAST-070 | medium | CWE-601 | Open redirect: request.args -> redirect
    return redirect(request.args.get("next"))


@app.route("/diag")
def diag():
    command = request.args["cmd"]
    # tg-expect: SAST-071 | critical | CWE-78 | Tainted command injection: request.args -> subprocess shell=True
    return subprocess.check_output(command, shell=True)


@app.route("/restore", methods=["POST"])
def restore():
    # tg-expect: SAST-072 | critical | CWE-502 | Tainted deserialization: request body -> pickle.loads
    return str(pickle.loads(request.get_data()))


@app.route("/upload", methods=["POST"])
def upload():
    uploaded = request.files["file"]
    # tg-expect: SAST-073 | high | CWE-22 | Upload saved with client-controlled filename (no secure_filename)
    uploaded.save(os.path.join("/srv/uploads", uploaded.filename))
    return "ok"


@app.route("/login", methods=["POST"])
def login():
    # tg-expect: SAST-074 | medium | CWE-532 | Password written to application log
    app.logger.info("login user=%s password=%s", request.form["user"], request.form["password"])
    return "ok"


@app.route("/lookup")
def lookup():
    params = {"id": request.args.get("id")}
    query = build_lookup_query(params)
    conn = sqlite3.connect("app.db")
    # tg-expect: SAST-075 | high | CWE-89 | Tainted SQL injection propagated through dict and helper function
    return {"rows": conn.execute(query).fetchall()}


def build_lookup_query(params: dict) -> str:
    return "SELECT * FROM accounts WHERE id = " + params["id"]


@app.after_request
def add_cors(response):
    # tg-expect: SAST-076 | medium | CWE-942 | Wildcard CORS origin combined with credentials
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return response


if __name__ == "__main__":
    # tg-expect: SAST-077 | high | CWE-489 | Flask debug mode enabled (Werkzeug debugger RCE)
    # tg-expect: SAST-078 | medium | CWE-605 | Server bound to all interfaces (0.0.0.0)
    app.run(host="0.0.0.0", port=5000, debug=True)
