"""SAST fixture: injection sinks (CWE-78, CWE-89, CWE-90, CWE-94, CWE-95, CWE-643, CWE-1336)."""
import os
import sqlite3
import subprocess

import ldap
from jinja2 import Template
from sqlalchemy import text


def find_user_concat(conn: sqlite3.Connection, username: str):
    cursor = conn.cursor()
    # tg-expect: SAST-010 | high | CWE-89 | SQL injection: concatenated string passed to cursor.execute
    cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")
    return cursor.fetchall()


def find_orders_fstring(conn: sqlite3.Connection, user_id: str):
    # tg-expect: SAST-011 | high | CWE-89 | SQL injection: f-string query passed to execute
    return conn.execute(f"SELECT * FROM orders WHERE user_id = {user_id}").fetchall()


def find_email_percent(conn: sqlite3.Connection, email: str):
    query = "SELECT id FROM users WHERE email = '%s'" % email
    # tg-expect: SAST-012 | high | CWE-89 | SQL injection: %-formatted query flows through a variable into execute
    return conn.execute(query).fetchone()


def find_user_sqlalchemy(session, name: str):
    # tg-expect: SAST-013 | high | CWE-89 | SQL injection: str.format inside sqlalchemy text()
    return session.execute(text("SELECT * FROM users WHERE name = '{}'".format(name)))


def ping_host(host: str) -> None:
    # tg-expect: SAST-014 | critical | CWE-78 | OS command injection: os.system with concatenated input
    os.system("ping -c 1 " + host)


def archive_path(path: str) -> None:
    # tg-expect: SAST-015 | critical | CWE-78 | OS command injection: subprocess with shell=True and dynamic string
    subprocess.call("tar czf /var/backups/app.tgz " + path, shell=True)


def dns_lookup(domain: str) -> str:
    # tg-expect: SAST-016 | high | CWE-78 | OS command injection: os.popen with formatted input
    return os.popen("nslookup %s" % domain).read()


def calculate(expression: str):
    # tg-expect: SAST-017 | critical | CWE-95 | Code injection: eval on caller-supplied expression
    return eval(expression)


def run_plugin(source: str) -> None:
    # tg-expect: SAST-018 | critical | CWE-94 | Code injection: exec on caller-supplied source
    exec(source)


def render_greeting(name: str) -> str:
    # tg-expect: SAST-019 | high | CWE-1336 | Server-side template injection: input concatenated into Jinja2 template source
    return Template("Hello " + name + "!").render()


def ldap_find(conn, username: str):
    # tg-expect: SAST-020 | high | CWE-90 | LDAP injection: unescaped input in search filter
    return conn.search_s("ou=people,dc=example,dc=com", ldap.SCOPE_SUBTREE, "(uid=" + username + ")")


def xpath_find(tree, username: str):
    # tg-expect: SAST-021 | high | CWE-643 | XPath injection: concatenated input in xpath expression
    return tree.xpath("//user[name/text()='" + username + "']")
