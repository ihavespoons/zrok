"""
Deliberately vulnerable Flask application for zrok evaluation.
DO NOT deploy this application - it contains intentional security vulnerabilities.
"""
import os
import sqlite3
import subprocess
import hashlib
import pickle
import base64

from flask import Flask, request, render_template_string, redirect, session, jsonify, send_file

app = Flask(__name__)
app.secret_key = "super_secret_key_12345"  # VULN-01: Hardcoded secret key

DATABASE = "app.db"

# VULN-02: Hardcoded database credentials
DB_USER = "admin"
DB_PASS = "password123"
API_KEY = "sk-live-abc123def456ghi789"


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            role TEXT DEFAULT 'user',
            is_admin INTEGER DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            title TEXT,
            content TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # VULN-03: Weak password hashing (MD5, no salt)
    admin_pass = hashlib.md5("admin123".encode()).hexdigest()
    conn.execute(
        "INSERT OR IGNORE INTO users (username, password, email, role, is_admin) VALUES (?, ?, ?, ?, ?)",
        ("admin", admin_pass, "admin@example.com", "admin", 1),
    )
    conn.commit()
    conn.close()


@app.route("/")
def index():
    return render_template_string(
        "<h1>Welcome</h1><p>Hello {{ name }}</p>",
        name=request.args.get("name", "Guest"),
    )


# VULN-04: SQL Injection in login
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    password_hash = hashlib.md5(password.encode()).hexdigest()

    conn = get_db()
    # SQL injection: string formatting instead of parameterized query
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password_hash}'"
    user = conn.execute(query).fetchone()
    conn.close()

    if user:
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]
        return redirect("/dashboard")
    return "Login failed", 401


# VULN-05: SQL Injection in search
@app.route("/search")
def search():
    query = request.args.get("q", "")
    conn = get_db()
    results = conn.execute(
        "SELECT * FROM posts WHERE title LIKE '%" + query + "%'"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in results])


# VULN-06: Stored XSS in posts
@app.route("/post", methods=["POST"])
def create_post():
    if "user_id" not in session:
        return "Unauthorized", 401
    title = request.form.get("title", "")
    content = request.form.get("content", "")

    conn = get_db()
    conn.execute(
        "INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)",
        (session["user_id"], title, content),
    )
    conn.commit()
    conn.close()
    return redirect("/dashboard")


# VULN-07: Reflected XSS
@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    # Directly embedding user input in HTML without escaping
    return f"<html><body><h1>Hello {name}!</h1></body></html>"


# VULN-08: Path traversal in file download
@app.route("/download")
def download():
    filename = request.args.get("file", "")
    filepath = os.path.join("/var/data/uploads", filename)
    return send_file(filepath)


# VULN-09: Command injection
@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    result = subprocess.run(
        f"ping -c 1 {host}", shell=True, capture_output=True, text=True
    )
    return f"<pre>{result.stdout}</pre>"


# VULN-10: Insecure deserialization
@app.route("/load-session", methods=["POST"])
def load_session():
    data = request.form.get("session_data", "")
    try:
        decoded = base64.b64decode(data)
        session_obj = pickle.loads(decoded)
        return jsonify(session_obj)
    except Exception as e:
        return str(e), 400


# VULN-11: Missing authorization check (IDOR)
@app.route("/api/user/<int:user_id>")
def get_user(user_id):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    if user:
        return jsonify(dict(user))
    return "Not found", 404


# VULN-12: Mass assignment
@app.route("/api/user/update", methods=["POST"])
def update_user():
    if "user_id" not in session:
        return "Unauthorized", 401

    conn = get_db()
    data = request.get_json()
    # Allows updating any field including is_admin and role
    for key, value in data.items():
        conn.execute(
            f"UPDATE users SET {key} = ? WHERE id = ?", (value, session["user_id"])
        )
    conn.commit()
    conn.close()
    return jsonify({"status": "updated"})


# VULN-13: Open redirect
@app.route("/redirect")
def open_redirect():
    url = request.args.get("url", "/")
    return redirect(url)


# VULN-14: Sensitive data in error messages
@app.route("/debug")
def debug():
    try:
        conn = sqlite3.connect(DATABASE)
        conn.execute("SELECT * FROM nonexistent_table")
    except Exception as e:
        return f"<pre>Database error: {e}\nDB Path: {DATABASE}\nDB User: {DB_USER}\nDB Pass: {DB_PASS}</pre>"


# VULN-15: No CSRF protection on state-changing operations
@app.route("/api/delete-account", methods=["POST"])
def delete_account():
    if "user_id" not in session:
        return "Unauthorized", 401
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id = ?", (session["user_id"],))
    conn.commit()
    conn.close()
    session.clear()
    return jsonify({"status": "deleted"})


# VULN-16: Information disclosure via debug endpoint
@app.route("/api/debug/env")
def debug_env():
    return jsonify(dict(os.environ))


# VULN-17: Weak session configuration
@app.before_request
def before_request():
    # Sessions are not configured with secure flags
    pass


if __name__ == "__main__":
    init_db()
    # VULN-18: Debug mode enabled in production
    app.run(host="0.0.0.0", port=5000, debug=True)
