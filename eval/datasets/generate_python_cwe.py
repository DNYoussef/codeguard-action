#!/usr/bin/env python
"""
Python CWE Benchmark Generator

Generates synthetic vulnerability test cases for Python, organized by CWE.
Each CWE gets 6 vulnerable + 4 safe variants = 10 test cases.
This is our "Python Juliet" since NIST Juliet only covers C/C++/Java/C#.

Usage:
    python generate_python_cwe.py              # Generate all CWEs
    python generate_python_cwe.py --cwe 89     # Single CWE
    python generate_python_cwe.py --list        # List available CWEs

Output: eval/samples/python-cwe/{CWE-ID}/vulnerable/*.patch + clean/*.patch
"""

import argparse
import sys
from pathlib import Path
from textwrap import dedent

_EVAL = Path(__file__).resolve().parent.parent
OUTPUT_DIR = _EVAL / "samples" / "python-cwe"


def patch(file_path: str, code: str) -> str:
    """Generate a unified diff patch that adds code as a new file."""
    lines = code.strip().splitlines()
    out = f"diff --git a/{file_path} b/{file_path}\n"
    out += "new file mode 100644\n"
    out += "index 0000000..1111111\n"
    out += f"--- /dev/null\n"
    out += f"+++ b/{file_path}\n"
    out += f"@@ -0,0 +1,{len(lines)} @@\n"
    for line in lines:
        out += f"+{line}\n"
    return out


# ---------------------------------------------------------------------------
# CWE-89: SQL Injection
# ---------------------------------------------------------------------------

CWE_89_VULN = [
    ("sqli_format_string.py", "src/db/users.py", dedent("""\
        import sqlite3
        def get_user(username):
            conn = sqlite3.connect("app.db")
            cursor = conn.cursor()
            query = "SELECT * FROM users WHERE username = '%s'" % username
            cursor.execute(query)
            return cursor.fetchone()
    """)),
    ("sqli_fstring.py", "src/db/search.py", dedent("""\
        import sqlite3
        def search_users(term):
            conn = sqlite3.connect("app.db")
            cursor = conn.cursor()
            cursor.execute(f"SELECT * FROM users WHERE name LIKE '%{term}%'")
            return cursor.fetchall()
    """)),
    ("sqli_concat.py", "src/db/orders.py", dedent("""\
        import sqlite3
        def get_order(order_id):
            conn = sqlite3.connect("app.db")
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM orders WHERE id = " + order_id)
            return cursor.fetchone()
    """)),
    ("sqli_format_method.py", "src/db/products.py", dedent("""\
        import sqlite3
        def find_product(name):
            conn = sqlite3.connect("app.db")
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM products WHERE name = '{}'".format(name))
            return cursor.fetchone()
    """)),
    ("sqli_multiline.py", "src/db/reports.py", dedent("""\
        import sqlite3
        def generate_report(start_date, end_date, status):
            conn = sqlite3.connect("app.db")
            cursor = conn.cursor()
            sql = "SELECT * FROM orders "
            sql += "WHERE created_at >= '" + start_date + "' "
            sql += "AND created_at <= '" + end_date + "' "
            sql += "AND status = '" + status + "'"
            cursor.execute(sql)
            return cursor.fetchall()
    """)),
    ("sqli_flask_request.py", "src/web/api.py", dedent("""\
        from flask import request
        import sqlite3
        def search():
            q = request.args.get("q", "")
            conn = sqlite3.connect("app.db")
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM items WHERE name LIKE '%" + q + "%'")
            return cursor.fetchall()
    """)),
]

CWE_89_CLEAN = [
    ("sqli_safe_param.py", "src/db/users.py", dedent("""\
        import sqlite3
        def get_user(username):
            conn = sqlite3.connect("app.db")
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            return cursor.fetchone()
    """)),
    ("sqli_safe_named.py", "src/db/search.py", dedent("""\
        import sqlite3
        def search_users(term):
            conn = sqlite3.connect("app.db")
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE name LIKE ?", (f"%{term}%",))
            return cursor.fetchall()
    """)),
    ("sqli_safe_orm.py", "src/db/orders.py", dedent("""\
        from sqlalchemy.orm import Session
        from models import Order
        def get_order(db: Session, order_id: int):
            return db.query(Order).filter(Order.id == order_id).first()
    """)),
    ("sqli_safe_django.py", "src/db/products.py", dedent("""\
        from django.db.models import Q
        from .models import Product
        def find_product(name):
            return Product.objects.filter(Q(name__icontains=name))
    """)),
]

# ---------------------------------------------------------------------------
# CWE-79: Cross-Site Scripting (XSS)
# ---------------------------------------------------------------------------

CWE_79_VULN = [
    ("xss_direct_response.py", "src/web/views.py", dedent("""\
        from flask import request
        def greet():
            name = request.args.get("name", "")
            return "<h1>Hello, " + name + "</h1>"
    """)),
    ("xss_template_string.py", "src/web/profile.py", dedent("""\
        from flask import request
        from jinja2 import Template
        def profile():
            bio = request.form.get("bio", "")
            t = Template("<div>" + bio + "</div>")
            return t.render()
    """)),
    ("xss_render_template_string.py", "src/web/search.py", dedent("""\
        from flask import request, render_template_string
        def search_results():
            query = request.args.get("q", "")
            return render_template_string("<p>Results for: " + query + "</p>")
    """)),
    ("xss_markup_safe.py", "src/web/comments.py", dedent("""\
        from flask import request
        from markupsafe import Markup
        def render_comment():
            text = request.form.get("comment", "")
            return Markup("<div class='comment'>" + text + "</div>")
    """)),
    ("xss_json_response.py", "src/web/api.py", dedent("""\
        from flask import request
        def user_data():
            name = request.args.get("name", "")
            return "<script>var user = '" + name + "';</script>"
    """)),
    ("xss_django_safe.py", "src/web/django_views.py", dedent("""\
        from django.utils.safestring import mark_safe
        def render_widget(user_input):
            return mark_safe("<div>" + user_input + "</div>")
    """)),
]

CWE_79_CLEAN = [
    ("xss_safe_escape.py", "src/web/views.py", dedent("""\
        from flask import request
        from markupsafe import escape
        def greet():
            name = escape(request.args.get("name", ""))
            return f"<h1>Hello, {name}</h1>"
    """)),
    ("xss_safe_template.py", "src/web/profile.py", dedent("""\
        from flask import request, render_template
        def profile():
            bio = request.form.get("bio", "")
            return render_template("profile.html", bio=bio)
    """)),
    ("xss_safe_json.py", "src/web/api.py", dedent("""\
        from flask import request, jsonify
        def user_data():
            name = request.args.get("name", "")
            return jsonify({"user": name})
    """)),
    ("xss_safe_django.py", "src/web/django_views.py", dedent("""\
        from django.shortcuts import render
        def render_widget(request):
            user_input = request.GET.get("input", "")
            return render(request, "widget.html", {"content": user_input})
    """)),
]

# ---------------------------------------------------------------------------
# CWE-78: OS Command Injection
# ---------------------------------------------------------------------------

CWE_78_VULN = [
    ("cmdi_os_system.py", "src/utils/deploy.py", dedent("""\
        import os
        def deploy_branch(branch_name):
            os.system("git checkout " + branch_name)
            os.system("docker build -t app:" + branch_name + " .")
    """)),
    ("cmdi_subprocess_shell.py", "src/utils/backup.py", dedent("""\
        import subprocess
        def backup_db(db_name):
            subprocess.call("pg_dump " + db_name + " > backup.sql", shell=True)
    """)),
    ("cmdi_popen.py", "src/utils/network.py", dedent("""\
        import os
        def ping_host(hostname):
            output = os.popen("ping -c 1 " + hostname).read()
            return output
    """)),
    ("cmdi_eval.py", "src/utils/calculator.py", dedent("""\
        def calculate(expression):
            result = eval(expression)
            return result
    """)),
    ("cmdi_exec.py", "src/utils/plugin.py", dedent("""\
        def run_plugin(plugin_code):
            exec(plugin_code)
    """)),
    ("cmdi_flask_os.py", "src/web/admin.py", dedent("""\
        from flask import request
        import os
        def run_command():
            cmd = request.form.get("command", "")
            return os.popen(cmd).read()
    """)),
]

CWE_78_CLEAN = [
    ("cmdi_safe_subprocess_list.py", "src/utils/deploy.py", dedent("""\
        import subprocess
        def deploy_branch(branch_name):
            subprocess.run(["git", "checkout", branch_name], check=True)
            subprocess.run(["docker", "build", "-t", f"app:{branch_name}", "."], check=True)
    """)),
    ("cmdi_safe_shlex.py", "src/utils/backup.py", dedent("""\
        import subprocess
        import shlex
        def backup_db(db_name):
            cmd = ["pg_dump", shlex.quote(db_name)]
            with open("backup.sql", "w") as f:
                subprocess.run(cmd, stdout=f, check=True)
    """)),
    ("cmdi_safe_allowlist.py", "src/utils/network.py", dedent("""\
        import subprocess
        import re
        def ping_host(hostname):
            if not re.match(r'^[a-zA-Z0-9.-]+$', hostname):
                raise ValueError("Invalid hostname")
            result = subprocess.run(["ping", "-c", "1", hostname], capture_output=True, text=True)
            return result.stdout
    """)),
    ("cmdi_safe_ast.py", "src/utils/calculator.py", dedent("""\
        import ast
        import operator
        OPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul}
        def calculate(expression):
            tree = ast.parse(expression, mode='eval')
            return _eval_node(tree.body)
        def _eval_node(node):
            if isinstance(node, ast.Num):
                return node.n
            if isinstance(node, ast.BinOp):
                return OPS[type(node.op)](_eval_node(node.left), _eval_node(node.right))
            raise ValueError("Unsupported expression")
    """)),
]

# ---------------------------------------------------------------------------
# CWE-502: Deserialization of Untrusted Data
# ---------------------------------------------------------------------------

CWE_502_VULN = [
    ("deser_pickle_loads.py", "src/cache/loader.py", dedent("""\
        import pickle
        def load_session(data):
            return pickle.loads(data)
    """)),
    ("deser_yaml_load.py", "src/config/parser.py", dedent("""\
        import yaml
        def parse_config(config_str):
            return yaml.load(config_str)
    """)),
    ("deser_pickle_file.py", "src/data/reader.py", dedent("""\
        import pickle
        def load_model(path):
            with open(path, "rb") as f:
                return pickle.load(f)
    """)),
    ("deser_marshal.py", "src/cache/codec.py", dedent("""\
        import marshal
        def decode_bytecode(data):
            return marshal.loads(data)
    """)),
    ("deser_shelve.py", "src/data/store.py", dedent("""\
        import shelve
        def get_user_data(user_id):
            with shelve.open("users") as db:
                return db[user_id]
    """)),
    ("deser_jsonpickle.py", "src/api/handler.py", dedent("""\
        import jsonpickle
        def deserialize_request(body):
            return jsonpickle.decode(body)
    """)),
]

CWE_502_CLEAN = [
    ("deser_safe_json.py", "src/cache/loader.py", dedent("""\
        import json
        def load_session(data):
            return json.loads(data)
    """)),
    ("deser_safe_yaml.py", "src/config/parser.py", dedent("""\
        import yaml
        def parse_config(config_str):
            return yaml.safe_load(config_str)
    """)),
    ("deser_safe_dataclass.py", "src/data/reader.py", dedent("""\
        import json
        from dataclasses import dataclass
        @dataclass
        class Model:
            name: str
            weights: list[float]
        def load_model(path):
            with open(path, "r") as f:
                data = json.load(f)
            return Model(**data)
    """)),
    ("deser_safe_msgpack.py", "src/cache/codec.py", dedent("""\
        import json
        def decode_message(data):
            return json.loads(data.decode("utf-8"))
    """)),
]

# ---------------------------------------------------------------------------
# CWE-798: Hardcoded Credentials
# ---------------------------------------------------------------------------

CWE_798_VULN = [
    ("creds_api_key.py", "src/config/settings.py", dedent("""\
        API_KEY = "HARDCODED_API_KEY_do_not_use_1234567890abcdef"
        DATABASE_URL = "postgresql://admin:password123@prod-db:5432/app"
    """)),
    ("creds_aws.py", "src/config/aws.py", dedent("""\
        AWS_ACCESS_KEY_ID = "FAKE_AWS_KEY_EXAMPLE_1234567890"
        AWS_SECRET_ACCESS_KEY = "FAKE_AWS_SECRET_EXAMPLE_abcdef1234567890abcdef"
        AWS_REGION = "us-east-1"
    """)),
    ("creds_jwt_secret.py", "src/auth/token.py", dedent("""\
        import jwt
        SECRET_KEY = "super-secret-jwt-key-do-not-share"
        def create_token(user_id):
            return jwt.encode({"user_id": user_id}, SECRET_KEY, algorithm="HS256")
    """)),
    ("creds_smtp.py", "src/email/sender.py", dedent("""\
        import smtplib
        SMTP_PASSWORD = "my-email-password-123"
        def send_email(to, subject, body):
            server = smtplib.SMTP("smtp.gmail.com", 587)
            server.login("app@example.com", SMTP_PASSWORD)
            server.sendmail("app@example.com", to, body)
    """)),
    ("creds_github_token.py", "src/integrations/github.py", dedent("""\
        import requests
        GITHUB_TOKEN = "FAKE_GITHUB_TOKEN_xxxxxxxxxxxxxxxxxxxx"
        def get_repos():
            headers = {"Authorization": f"token {GITHUB_TOKEN}"}
            return requests.get("https://api.github.com/user/repos", headers=headers).json()
    """)),
    ("creds_db_inline.py", "src/db/connection.py", dedent("""\
        import psycopg2
        def get_connection():
            return psycopg2.connect(
                host="production-db.internal",
                database="mainapp",
                user="admin",
                password="Pr0duction!Pass#2024"
            )
    """)),
]

CWE_798_CLEAN = [
    ("creds_safe_env.py", "src/config/settings.py", dedent("""\
        import os
        API_KEY = os.environ["API_KEY"]
        DATABASE_URL = os.environ["DATABASE_URL"]
    """)),
    ("creds_safe_vault.py", "src/config/aws.py", dedent("""\
        import os
        AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
        AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
        AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
    """)),
    ("creds_safe_keyring.py", "src/auth/token.py", dedent("""\
        import os
        import jwt
        def create_token(user_id):
            secret = os.environ["JWT_SECRET"]
            return jwt.encode({"user_id": user_id}, secret, algorithm="HS256")
    """)),
    ("creds_safe_config_file.py", "src/db/connection.py", dedent("""\
        import os
        import psycopg2
        def get_connection():
            return psycopg2.connect(os.environ["DATABASE_URL"])
    """)),
]

# ---------------------------------------------------------------------------
# CWE-22: Path Traversal
# ---------------------------------------------------------------------------

CWE_22_VULN = [
    ("path_open_direct.py", "src/web/files.py", dedent("""\
        from flask import request, send_file
        def download():
            filename = request.args.get("file")
            return send_file("/data/uploads/" + filename)
    """)),
    ("path_os_join.py", "src/utils/reader.py", dedent("""\
        import os
        def read_log(log_name):
            path = os.path.join("/var/log/app", log_name)
            with open(path) as f:
                return f.read()
    """)),
    ("path_open_format.py", "src/web/static.py", dedent("""\
        def get_template(name):
            with open(f"templates/{name}") as f:
                return f.read()
    """)),
    ("path_flask_directory.py", "src/web/download.py", dedent("""\
        from flask import request
        import os
        BASE = "/app/exports"
        def get_export():
            path = os.path.join(BASE, request.args["path"])
            with open(path, "rb") as f:
                return f.read()
    """)),
    ("path_zipfile.py", "src/utils/extract.py", dedent("""\
        import zipfile
        def extract(zip_path, dest):
            with zipfile.ZipFile(zip_path) as z:
                z.extractall(dest)
    """)),
    ("path_symlink.py", "src/utils/backup.py", dedent("""\
        import shutil
        def backup_file(user_path, backup_dir):
            shutil.copy(user_path, backup_dir)
    """)),
]

CWE_22_CLEAN = [
    ("path_safe_resolve.py", "src/web/files.py", dedent("""\
        from flask import request, send_file, abort
        from pathlib import Path
        UPLOAD_DIR = Path("/data/uploads").resolve()
        def download():
            filename = request.args.get("file", "")
            target = (UPLOAD_DIR / filename).resolve()
            if not str(target).startswith(str(UPLOAD_DIR)):
                abort(403)
            return send_file(target)
    """)),
    ("path_safe_basename.py", "src/utils/reader.py", dedent("""\
        import os
        def read_log(log_name):
            safe_name = os.path.basename(log_name)
            path = os.path.join("/var/log/app", safe_name)
            with open(path) as f:
                return f.read()
    """)),
    ("path_safe_allowlist.py", "src/web/static.py", dedent("""\
        ALLOWED_TEMPLATES = {"index.html", "about.html", "contact.html"}
        def get_template(name):
            if name not in ALLOWED_TEMPLATES:
                raise ValueError("Template not allowed")
            with open(f"templates/{name}") as f:
                return f.read()
    """)),
    ("path_safe_zipfile.py", "src/utils/extract.py", dedent("""\
        import zipfile
        import os
        def extract(zip_path, dest):
            with zipfile.ZipFile(zip_path) as z:
                for info in z.infolist():
                    target = os.path.realpath(os.path.join(dest, info.filename))
                    if not target.startswith(os.path.realpath(dest)):
                        raise ValueError(f"Path traversal detected: {info.filename}")
                    z.extract(info, dest)
    """)),
]

# ---------------------------------------------------------------------------
# CWE-327: Use of Broken Crypto Algorithm
# ---------------------------------------------------------------------------

CWE_327_VULN = [
    ("crypto_md5_password.py", "src/auth/password.py", dedent("""\
        import hashlib
        def hash_password(password):
            return hashlib.md5(password.encode()).hexdigest()
        def verify_password(stored_hash, password):
            return hashlib.md5(password.encode()).hexdigest() == stored_hash
    """)),
    ("crypto_sha1_token.py", "src/auth/token.py", dedent("""\
        import hashlib
        import time
        def generate_token(user_id):
            data = f"{user_id}:{time.time()}"
            return hashlib.sha1(data.encode()).hexdigest()
    """)),
    ("crypto_des.py", "src/utils/crypto.py", dedent("""\
        from Crypto.Cipher import DES
        KEY = b"12345678"
        def encrypt(data):
            cipher = DES.new(KEY, DES.MODE_ECB)
            return cipher.encrypt(data.ljust(8))
    """)),
    ("crypto_random_seed.py", "src/auth/otp.py", dedent("""\
        import random
        def generate_otp():
            random.seed()
            return str(random.randint(100000, 999999))
    """)),
    ("crypto_weak_key.py", "src/utils/encrypt.py", dedent("""\
        from cryptography.fernet import Fernet
        KEY = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        def encrypt(data):
            return Fernet(KEY).encrypt(data.encode())
    """)),
    ("crypto_no_salt.py", "src/auth/hash.py", dedent("""\
        import hashlib
        def hash_password(password):
            return hashlib.sha256(password.encode()).hexdigest()
    """)),
]

CWE_327_CLEAN = [
    ("crypto_safe_bcrypt.py", "src/auth/password.py", dedent("""\
        import bcrypt
        def hash_password(password):
            return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
        def verify_password(stored_hash, password):
            return bcrypt.checkpw(password.encode(), stored_hash)
    """)),
    ("crypto_safe_secrets.py", "src/auth/token.py", dedent("""\
        import secrets
        def generate_token():
            return secrets.token_urlsafe(32)
    """)),
    ("crypto_safe_aes.py", "src/utils/crypto.py", dedent("""\
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import os
        def encrypt(data, key):
            nonce = os.urandom(12)
            aesgcm = AESGCM(key)
            ct = aesgcm.encrypt(nonce, data, None)
            return nonce + ct
    """)),
    ("crypto_safe_argon2.py", "src/auth/hash.py", dedent("""\
        from argon2 import PasswordHasher
        ph = PasswordHasher()
        def hash_password(password):
            return ph.hash(password)
        def verify_password(stored_hash, password):
            return ph.verify(stored_hash, password)
    """)),
]


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

CWE_REGISTRY = {
    "CWE-89": ("SQL Injection", CWE_89_VULN, CWE_89_CLEAN),
    "CWE-79": ("Cross-Site Scripting", CWE_79_VULN, CWE_79_CLEAN),
    "CWE-78": ("OS Command Injection", CWE_78_VULN, CWE_78_CLEAN),
    "CWE-502": ("Deserialization", CWE_502_VULN, CWE_502_CLEAN),
    "CWE-798": ("Hardcoded Credentials", CWE_798_VULN, CWE_798_CLEAN),
    "CWE-22": ("Path Traversal", CWE_22_VULN, CWE_22_CLEAN),
    "CWE-327": ("Broken Crypto", CWE_327_VULN, CWE_327_CLEAN),
}


def generate_cwe(cwe_id: str, name: str, vuln_cases: list, clean_cases: list):
    """Generate patches for one CWE."""
    cwe_dir = OUTPUT_DIR / cwe_id
    vuln_dir = cwe_dir / "vulnerable"
    clean_dir = cwe_dir / "clean"
    vuln_dir.mkdir(parents=True, exist_ok=True)
    clean_dir.mkdir(parents=True, exist_ok=True)

    count = 0
    for filename, filepath, code in vuln_cases:
        p = patch(filepath, code)
        (vuln_dir / f"{filename.replace('.py', '.patch')}").write_text(p, encoding="utf-8")
        count += 1

    for filename, filepath, code in clean_cases:
        p = patch(filepath, code)
        (clean_dir / f"{filename.replace('.py', '.patch')}").write_text(p, encoding="utf-8")
        count += 1

    return count


def main():
    parser = argparse.ArgumentParser(description="Python CWE Benchmark Generator")
    parser.add_argument("--cwe", help="Generate single CWE (e.g., 89)")
    parser.add_argument("--list", action="store_true", help="List available CWEs")
    args = parser.parse_args()

    if args.list:
        for cwe_id, (name, vuln, clean) in CWE_REGISTRY.items():
            print(f"  {cwe_id:10s} {name:30s} ({len(vuln)} vuln, {len(clean)} clean)")
        print(f"\nTotal: {sum(len(v)+len(c) for _, v, c in CWE_REGISTRY.values())} test cases")
        return

    if args.cwe:
        key = f"CWE-{args.cwe}" if not args.cwe.startswith("CWE-") else args.cwe
        if key not in CWE_REGISTRY:
            print(f"ERROR: Unknown CWE: {key}")
            sys.exit(1)
        targets = {key: CWE_REGISTRY[key]}
    else:
        targets = CWE_REGISTRY

    total = 0
    for cwe_id, (name, vuln, clean) in targets.items():
        n = generate_cwe(cwe_id, name, vuln, clean)
        print(f"  {cwe_id}: {name} -> {n} patches")
        total += n

    print(f"\nGenerated {total} patches in {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
