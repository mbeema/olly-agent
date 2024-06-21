import json
import logging
import os
import time
import urllib.request
import urllib.error
from datetime import datetime

import psycopg2
from flask import Flask, jsonify, request

ORDER_SERVICE_URL = os.getenv("ORDER_SERVICE_URL", "http://localhost:3001")

app = Flask(__name__)

# Structured JSON logging to file
LOG_DIR = "/var/log/demo-app"
os.makedirs(LOG_DIR, exist_ok=True)

file_handler = logging.FileHandler(os.path.join(LOG_DIR, "app.log"))
file_handler.setFormatter(logging.Formatter(json.dumps({
    "timestamp": "%(asctime)s",
    "level": "%(levelname)s",
    "logger": "%(name)s",
    "message": "%(message)s",
    "pid": str(os.getpid()),
})))
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", "5432")),
    "dbname": os.getenv("DB_NAME", "demo"),
    "user": os.getenv("DB_USER", "demo"),
    "password": os.getenv("DB_PASSWORD", "demo123"),
}


def get_db():
    return psycopg2.connect(**DB_CONFIG)


@app.route("/")
def health():
    app.logger.info("Health check")
    return jsonify({"status": "ok", "timestamp": datetime.utcnow().isoformat()})


@app.route("/users", methods=["GET"])
def list_users():
    app.logger.info("Listing users")
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT id, name, email, created_at FROM users ORDER BY id")
        rows = cur.fetchall()
        users = [
            {"id": r[0], "name": r[1], "email": r[2], "created_at": str(r[3])}
            for r in rows
        ]
        return jsonify(users)
    finally:
        conn.close()


@app.route("/users", methods=["POST"])
def create_user():
    data = request.get_json(force=True)
    name = data.get("name", "")
    email = data.get("email", "")
    app.logger.info(f"Creating user: name={name}, email={email}")

    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (name, email) VALUES (%s, %s) RETURNING id",
            (name, email),
        )
        user_id = cur.fetchone()[0]
        conn.commit()
        return jsonify({"id": user_id, "name": name, "email": email}), 201
    finally:
        conn.close()


@app.route("/users/<int:user_id>", methods=["GET"])
def get_user(user_id):
    app.logger.info(f"Getting user: id={user_id}")
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, name, email, created_at FROM users WHERE id = %s", (user_id,)
        )
        row = cur.fetchone()
        if row is None:
            return jsonify({"error": "not found"}), 404
        return jsonify(
            {"id": row[0], "name": row[1], "email": row[2], "created_at": str(row[3])}
        )
    finally:
        conn.close()


@app.route("/orders", methods=["GET"])
def list_orders():
    """Calls the Go order-service — creates a cross-service trace."""
    app.logger.info("Listing orders (calling order-service)")
    try:
        resp = urllib.request.urlopen(f"{ORDER_SERVICE_URL}/api/orders")
        data = json.loads(resp.read())
        return jsonify(data)
    except urllib.error.URLError as e:
        app.logger.error(f"order-service call failed: {e}")
        return jsonify({"error": "order-service unavailable"}), 502


@app.route("/orders", methods=["POST"])
def create_order():
    """Calls the Go order-service — creates a cross-service trace."""
    data = request.get_json(force=True)
    app.logger.info(f"Creating order (calling order-service): {data}")
    try:
        req = urllib.request.Request(
            f"{ORDER_SERVICE_URL}/api/orders",
            data=json.dumps(data).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        resp = urllib.request.urlopen(req)
        result = json.loads(resp.read())
        return jsonify(result), 201
    except urllib.error.URLError as e:
        app.logger.error(f"order-service call failed: {e}")
        return jsonify({"error": "order-service unavailable"}), 502


@app.route("/slow")
def slow():
    delay = float(request.args.get("delay", "2"))
    app.logger.info(f"Slow endpoint: sleeping {delay}s")
    time.sleep(delay)
    return jsonify({"status": "ok", "delay": delay})


@app.route("/error")
def error_endpoint():
    app.logger.error("Intentional error endpoint hit")
    return jsonify({"error": "internal server error"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
