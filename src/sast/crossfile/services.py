"""Cross-file taint sinks reached from routes.py."""
import os
import sqlite3


def restart_service(name: str) -> str:
    # tg-expect: SAST-120 | critical | CWE-78 | Cross-file taint: request.args (routes.py) -> os.system
    os.system("systemctl restart " + name)
    return "restarted"


def report_rows(table: str):
    conn = sqlite3.connect("app.db")
    # tg-expect: SAST-121 | high | CWE-89 | Cross-file taint: request.args (routes.py) -> execute
    return {"rows": conn.execute("SELECT * FROM " + table).fetchall()}
