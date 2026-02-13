import json
import logging
import os
import ssl
import time
import urllib.request
import urllib.error
from datetime import datetime

import psycopg2
from flask import Flask, jsonify, request

ORDER_SERVICE_URL = os.getenv("ORDER_SERVICE_URL", "http://localhost:3001")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")

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


### GenAI Endpoints ###
# These make real OpenAI API calls — Olly intercepts the HTTP traffic via eBPF
# and produces gen_ai.* spans with zero instrumentation.

def _openai_chat(prompt, model="gpt-4o-mini", max_tokens=50):
    """Make a raw HTTP call to OpenAI (no SDK — pure urllib for eBPF visibility)."""
    body = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "temperature": 0.7,
    }).encode()

    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {OPENAI_API_KEY}",
        },
        method="POST",
    )

    # Use default SSL context
    ctx = ssl.create_default_context()
    resp = urllib.request.urlopen(req, context=ctx)
    return json.loads(resp.read())


def _openai_embeddings(text, model="text-embedding-3-small"):
    """Make a raw HTTP call to OpenAI embeddings endpoint."""
    body = json.dumps({
        "model": model,
        "input": text,
    }).encode()

    req = urllib.request.Request(
        "https://api.openai.com/v1/embeddings",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {OPENAI_API_KEY}",
        },
        method="POST",
    )

    ctx = ssl.create_default_context()
    resp = urllib.request.urlopen(req, context=ctx)
    return json.loads(resp.read())


@app.route("/ai/chat", methods=["POST"])
def ai_chat():
    """Chat with OpenAI — Olly sees this as a GenAI span."""
    if not OPENAI_API_KEY:
        return jsonify({"error": "OPENAI_API_KEY not set"}), 503

    data = request.get_json(force=True)
    prompt = data.get("prompt", "Say hello in one sentence.")
    model = data.get("model", "gpt-4o-mini")
    app.logger.info(f"GenAI chat: model={model}, prompt={prompt[:50]}")

    try:
        result = _openai_chat(prompt, model=model)
        answer = result["choices"][0]["message"]["content"]
        usage = result.get("usage", {})
        app.logger.info(
            f"GenAI response: model={result.get('model')}, "
            f"tokens_in={usage.get('prompt_tokens')}, "
            f"tokens_out={usage.get('completion_tokens')}"
        )
        return jsonify({
            "answer": answer,
            "model": result.get("model"),
            "usage": usage,
        })
    except urllib.error.HTTPError as e:
        body = e.read().decode() if e.fp else ""
        app.logger.error(f"OpenAI error {e.code}: {body[:200]}")
        return jsonify({"error": f"OpenAI API error: {e.code}"}), e.code
    except Exception as e:
        app.logger.error(f"GenAI chat failed: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/ai/embeddings", methods=["POST"])
def ai_embeddings():
    """Generate embeddings via OpenAI — Olly sees this as a GenAI span."""
    if not OPENAI_API_KEY:
        return jsonify({"error": "OPENAI_API_KEY not set"}), 503

    data = request.get_json(force=True)
    text = data.get("text", "Hello world")
    app.logger.info(f"GenAI embeddings: text={text[:50]}")

    try:
        result = _openai_embeddings(text)
        usage = result.get("usage", {})
        dims = len(result["data"][0]["embedding"]) if result.get("data") else 0
        app.logger.info(f"GenAI embeddings: dims={dims}, tokens={usage.get('total_tokens')}")
        return jsonify({
            "dimensions": dims,
            "model": result.get("model"),
            "usage": usage,
        })
    except urllib.error.HTTPError as e:
        body = e.read().decode() if e.fp else ""
        app.logger.error(f"OpenAI embeddings error {e.code}: {body[:200]}")
        return jsonify({"error": f"OpenAI API error: {e.code}"}), e.code
    except Exception as e:
        app.logger.error(f"GenAI embeddings failed: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/ai/summarize-orders", methods=["GET"])
def ai_summarize_orders():
    """Multi-step AI agent: fetch orders from DB, then summarize with LLM.
    Creates a trace with: SERVER → CLIENT(postgres) → CLIENT(openai)."""
    if not OPENAI_API_KEY:
        return jsonify({"error": "OPENAI_API_KEY not set"}), 503

    app.logger.info("AI summarize-orders: fetching orders then calling LLM")

    # Step 1: Fetch orders from database
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT product, amount FROM orders ORDER BY created_at DESC LIMIT 10")
        rows = cur.fetchall()
        orders_text = ", ".join(f"{r[0]} (${r[1]})" for r in rows)
    finally:
        conn.close()

    if not orders_text:
        return jsonify({"summary": "No orders found."})

    # Step 2: Summarize with LLM
    try:
        prompt = f"Summarize these recent orders in one sentence: {orders_text}"
        result = _openai_chat(prompt, max_tokens=80)
        summary = result["choices"][0]["message"]["content"]
        usage = result.get("usage", {})
        return jsonify({
            "summary": summary,
            "orders_count": len(rows),
            "model": result.get("model"),
            "usage": usage,
        })
    except Exception as e:
        app.logger.error(f"AI summarize failed: {e}")
        return jsonify({"error": str(e)}), 500


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
