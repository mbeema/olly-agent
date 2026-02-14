import json
import logging
import os
import ssl
import time
import urllib.request
import urllib.error
from datetime import datetime

import psycopg2
import redis
import pymongo
from flask import Flask, jsonify, request

ORDER_SERVICE_URL = os.getenv("ORDER_SERVICE_URL", "http://localhost:3001")
CATALOG_SERVICE_URL = os.getenv("CATALOG_SERVICE_URL", "http://localhost:8081")
MCP_SERVER_URL = os.getenv("MCP_SERVER_URL", "http://localhost:3002/mcp")
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


REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

MONGO_HOST = os.getenv("MONGO_HOST", "localhost")
MONGO_PORT = int(os.getenv("MONGO_PORT", "27017"))
MONGO_DB = os.getenv("MONGO_DB", "demo")

# Redis client (for caching)
redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

# MongoDB client (for product reviews)
mongo_client = pymongo.MongoClient(MONGO_HOST, MONGO_PORT)
mongo_db = mongo_client[MONGO_DB]


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


### Checkout + Inventory Endpoints ###
# These demonstrate cross-service, multi-database tracing:
# Flask → order-service → MySQL (inventory check) + PostgreSQL (order creation)


@app.route("/inventory", methods=["GET"])
def list_inventory():
    """List inventory (calls order-service → MySQL)."""
    app.logger.info("Listing inventory (calling order-service)")
    try:
        resp = urllib.request.urlopen(f"{ORDER_SERVICE_URL}/api/inventory")
        data = json.loads(resp.read())
        return jsonify(data)
    except urllib.error.URLError as e:
        app.logger.error(f"order-service inventory call failed: {e}")
        return jsonify({"error": "order-service unavailable"}), 502


@app.route("/checkout", methods=["POST"])
def checkout():
    """Checkout flow: Flask → order-service/checkout → MySQL (inventory) + PostgreSQL (order).
    Creates a cross-service trace spanning two databases:
    SERVER(Flask) → CLIENT(checkout) → SERVER(order-service) → CLIENT(MySQL) + CLIENT(PostgreSQL)
    """
    data = request.get_json(force=True)
    user_id = data.get("user_id", 1)
    sku = data.get("sku", "WDG-001")
    qty = data.get("qty", 1)
    app.logger.info(f"Checkout: user={user_id}, sku={sku}, qty={qty}")
    try:
        req = urllib.request.Request(
            f"{ORDER_SERVICE_URL}/api/checkout",
            data=json.dumps({"user_id": user_id, "sku": sku, "qty": qty}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        resp = urllib.request.urlopen(req)
        result = json.loads(resp.read())
        app.logger.info(f"Checkout success: order_id={result.get('order_id')}")
        return jsonify(result), 201
    except urllib.error.HTTPError as e:
        body = e.read().decode() if e.fp else ""
        app.logger.error(f"Checkout failed: {e.code} {body[:200]}")
        return jsonify(json.loads(body) if body else {"error": f"HTTP {e.code}"}), e.code
    except urllib.error.URLError as e:
        app.logger.error(f"order-service checkout call failed: {e}")
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


### MCP Endpoints ###
# These make JSON-RPC 2.0 calls to the MCP demo server — Olly intercepts the
# HTTP traffic via eBPF and produces mcp.* spans with zero instrumentation.

_mcp_request_id = 0
_mcp_session_id = None


def _mcp_call(method, params=None):
    """Make a JSON-RPC 2.0 call to the MCP server (Streamable HTTP transport)."""
    global _mcp_request_id, _mcp_session_id
    _mcp_request_id += 1

    body = json.dumps({
        "jsonrpc": "2.0",
        "id": _mcp_request_id,
        "method": method,
        "params": params or {},
    }).encode()

    headers = {"Content-Type": "application/json"}
    if _mcp_session_id:
        headers["Mcp-Session-Id"] = _mcp_session_id

    req = urllib.request.Request(
        MCP_SERVER_URL,
        data=body,
        headers=headers,
        method="POST",
    )
    resp = urllib.request.urlopen(req)

    # Capture session ID from response
    sid = resp.headers.get("Mcp-Session-Id")
    if sid:
        _mcp_session_id = sid

    return json.loads(resp.read())


@app.route("/mcp/init", methods=["POST"])
def mcp_init():
    """Initialize MCP session — produces initialize + notifications/initialized spans."""
    app.logger.info("MCP: initializing session")
    try:
        result = _mcp_call("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "olly-demo-client", "version": "1.0.0"},
        })

        # Send initialized notification (fire-and-forget)
        try:
            notif_body = json.dumps({
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
            }).encode()
            notif_headers = {"Content-Type": "application/json"}
            if _mcp_session_id:
                notif_headers["Mcp-Session-Id"] = _mcp_session_id
            notif_req = urllib.request.Request(
                MCP_SERVER_URL, data=notif_body, headers=notif_headers, method="POST",
            )
            urllib.request.urlopen(notif_req)
        except Exception:
            pass

        return jsonify({"session": _mcp_session_id, "result": result.get("result")})
    except Exception as e:
        app.logger.error(f"MCP init failed: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/mcp/tools", methods=["GET"])
def mcp_tools():
    """List available MCP tools, then call one — produces tools/list + tools/call spans."""
    app.logger.info("MCP: listing and calling tools")
    try:
        # List tools
        list_result = _mcp_call("tools/list")
        tools = list_result.get("result", {}).get("tools", [])

        # Call get_weather tool
        call_result = _mcp_call("tools/call", {
            "name": "get_weather",
            "arguments": {"location": "San Francisco"},
        })

        return jsonify({
            "available_tools": [t.get("name") for t in tools],
            "weather_result": call_result.get("result"),
        })
    except Exception as e:
        app.logger.error(f"MCP tools failed: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/mcp/tools/call", methods=["POST"])
def mcp_tool_call():
    """Call a specific MCP tool — produces a tools/call span."""
    data = request.get_json(force=True)
    tool_name = data.get("tool", "calculate")
    arguments = data.get("arguments", {"expression": "2+2"})
    app.logger.info(f"MCP: calling tool {tool_name}")
    try:
        result = _mcp_call("tools/call", {
            "name": tool_name,
            "arguments": arguments,
        })
        return jsonify(result.get("result"))
    except Exception as e:
        app.logger.error(f"MCP tool call failed: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/mcp/resources", methods=["GET"])
def mcp_resources():
    """List and read MCP resources — produces resources/list + resources/read spans."""
    app.logger.info("MCP: listing and reading resources")
    try:
        # List resources
        list_result = _mcp_call("resources/list")
        resources = list_result.get("result", {}).get("resources", [])

        # Read app config resource
        read_result = _mcp_call("resources/read", {"uri": "config://app"})

        return jsonify({
            "available_resources": [r.get("uri") for r in resources],
            "config": read_result.get("result"),
        })
    except Exception as e:
        app.logger.error(f"MCP resources failed: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/mcp/prompts", methods=["GET"])
def mcp_prompts():
    """List and get MCP prompts — produces prompts/list + prompts/get spans."""
    app.logger.info("MCP: listing and getting prompts")
    try:
        # List prompts
        list_result = _mcp_call("prompts/list")
        prompts = list_result.get("result", {}).get("prompts", [])

        # Get code_review prompt
        get_result = _mcp_call("prompts/get", {
            "name": "code_review",
            "arguments": {"language": "python"},
        })

        return jsonify({
            "available_prompts": [p.get("name") for p in prompts],
            "code_review_prompt": get_result.get("result"),
        })
    except Exception as e:
        app.logger.error(f"MCP prompts failed: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/mcp/agent", methods=["POST"])
def mcp_agent():
    """Multi-step MCP agent: init → list tools → call tool → read resource.
    Creates a trace with: SERVER → CLIENT(initialize) → CLIENT(tools/list) → CLIENT(tools/call) → CLIENT(resources/read)."""
    app.logger.info("MCP: running multi-step agent workflow")
    try:
        steps = []

        # Step 1: Initialize
        init_result = _mcp_call("initialize", {
            "protocolVersion": "2025-03-26",
            "capabilities": {},
            "clientInfo": {"name": "olly-demo-agent", "version": "1.0.0"},
        })
        steps.append({"step": "initialize", "ok": True})

        # Step 2: List tools
        tools_result = _mcp_call("tools/list")
        tool_names = [t.get("name") for t in tools_result.get("result", {}).get("tools", [])]
        steps.append({"step": "tools/list", "tools": tool_names})

        # Step 3: Call lookup_user tool
        user_result = _mcp_call("tools/call", {
            "name": "lookup_user",
            "arguments": {"user_id": 1},
        })
        steps.append({"step": "tools/call lookup_user", "result": user_result.get("result")})

        # Step 4: Read user count resource
        count_result = _mcp_call("resources/read", {"uri": "db://users/count"})
        steps.append({"step": "resources/read db://users/count", "result": count_result.get("result")})

        return jsonify({"steps": steps, "session": _mcp_session_id})
    except Exception as e:
        app.logger.error(f"MCP agent failed: {e}")
        return jsonify({"error": str(e)}), 500


### Full-Chain Endpoint ###
# 5-service linear chain: Python → Go → Java → .NET → Node.js → Redis + PostgreSQL + MySQL


@app.route("/fullchain", methods=["POST"])
def fullchain():
    """Full 5-service chain: Flask → order-service → catalog(Java) → pricing(.NET) → stock(Node) → Redis+PG.
    Creates 12+ spans across 5 languages and 3 databases in a single trace."""
    data = request.get_json(force=True)
    user_id = data.get("user_id", 1)
    sku = data.get("sku", "WDG-001")
    qty = data.get("qty", 1)
    app.logger.info(f"Fullchain: user={user_id}, sku={sku}, qty={qty}")
    try:
        req = urllib.request.Request(
            f"{ORDER_SERVICE_URL}/api/fullchain",
            data=json.dumps({"user_id": user_id, "sku": sku, "qty": qty}).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        resp = urllib.request.urlopen(req)
        result = json.loads(resp.read())
        app.logger.info(f"Fullchain success: order_id={result.get('order_id')}")
        return jsonify(result), 201
    except urllib.error.HTTPError as e:
        body = e.read().decode() if e.fp else ""
        app.logger.error(f"Fullchain failed: {e.code} {body[:200]}")
        return jsonify(json.loads(body) if body else {"error": f"HTTP {e.code}"}), e.code
    except urllib.error.URLError as e:
        app.logger.error(f"Fullchain call failed: {e}")
        return jsonify({"error": "order-service unavailable"}), 502


### Cross-Language Shop Endpoints ###
# These create a 4-hop trace chain: Python → Java → .NET → Node.js → Redis + PostgreSQL


@app.route("/shop")
def shop():
    """Full 4-hop cross-language trace: Flask → Java catalog → .NET pricing → Node stock."""
    sku = request.args.get("sku", "WDG-001")
    app.logger.info(f"Shop lookup: sku={sku}")
    try:
        resp = urllib.request.urlopen(f"{CATALOG_SERVICE_URL}/api/catalog/{sku}")
        data = json.loads(resp.read())
        return jsonify(data)
    except urllib.error.HTTPError as e:
        body = e.read().decode() if e.fp else ""
        app.logger.error(f"Catalog lookup failed: {e.code} {body[:200]}")
        return jsonify(json.loads(body) if body else {"error": f"HTTP {e.code}"}), e.code
    except urllib.error.URLError as e:
        app.logger.error(f"catalog-service call failed: {e}")
        return jsonify({"error": "catalog-service unavailable"}), 502


@app.route("/shop/all")
def shop_all():
    """List all catalog items with pricing and stock (calls Java catalog-service)."""
    app.logger.info("Shop: listing all catalog items")
    try:
        resp = urllib.request.urlopen(f"{CATALOG_SERVICE_URL}/api/catalog")
        data = json.loads(resp.read())
        return jsonify(data)
    except urllib.error.URLError as e:
        app.logger.error(f"catalog-service call failed: {e}")
        return jsonify({"error": "catalog-service unavailable"}), 502


### Redis Endpoints ###
# These use the redis-py client — Olly intercepts Redis wire protocol via eBPF.


@app.route("/cache/<key>", methods=["GET"])
def cache_get(key):
    """Get a cached value from Redis."""
    app.logger.info(f"Redis GET: {key}")
    val = redis_client.get(key)
    if val is None:
        return jsonify({"key": key, "value": None, "hit": False})
    return jsonify({"key": key, "value": val, "hit": True})


@app.route("/cache/<key>", methods=["PUT"])
def cache_set(key):
    """Set a cached value in Redis (with 300s TTL)."""
    data = request.get_json(force=True)
    value = data.get("value", "")
    app.logger.info(f"Redis SET: {key}={value[:50]}")
    redis_client.setex(key, 300, value)
    return jsonify({"key": key, "value": value, "ttl": 300})


@app.route("/cache", methods=["GET"])
def cache_list():
    """List cached keys from Redis."""
    app.logger.info("Redis KEYS listing")
    keys = redis_client.keys("*")
    result = {}
    for k in keys[:20]:  # Limit to 20
        result[k] = redis_client.get(k)
    return jsonify({"keys": result, "total": len(keys)})


@app.route("/cache/counter/<name>", methods=["POST"])
def cache_incr(name):
    """Increment a Redis counter — generates INCR + GET commands."""
    app.logger.info(f"Redis INCR: {name}")
    new_val = redis_client.incr(f"counter:{name}")
    return jsonify({"counter": name, "value": new_val})


### MongoDB Endpoints ###
# These use pymongo — Olly intercepts MongoDB wire protocol via eBPF.


@app.route("/reviews", methods=["GET"])
def list_reviews():
    """List all product reviews from MongoDB."""
    app.logger.info("MongoDB: listing reviews")
    reviews = list(mongo_db.reviews.find({}, {"_id": 0}).sort("created_at", -1).limit(50))
    return jsonify(reviews)


@app.route("/reviews", methods=["POST"])
def create_review():
    """Create a product review in MongoDB."""
    data = request.get_json(force=True)
    review = {
        "product": data.get("product", "Widget"),
        "rating": data.get("rating", 5),
        "comment": data.get("comment", "Great product!"),
        "user": data.get("user", "anonymous"),
        "created_at": datetime.utcnow().isoformat(),
    }
    app.logger.info(f"MongoDB: creating review for {review['product']}")
    mongo_db.reviews.insert_one(review)
    review.pop("_id", None)  # ObjectId not JSON-serializable
    return jsonify(review), 201


@app.route("/reviews/<product>", methods=["GET"])
def reviews_by_product(product):
    """Get reviews for a specific product from MongoDB."""
    app.logger.info(f"MongoDB: reviews for {product}")
    reviews = list(mongo_db.reviews.find(
        {"product": product}, {"_id": 0}
    ).sort("created_at", -1).limit(20))
    avg_rating = mongo_db.reviews.aggregate([
        {"$match": {"product": product}},
        {"$group": {"_id": None, "avg": {"$avg": "$rating"}, "count": {"$sum": 1}}},
    ])
    stats = next(avg_rating, {"avg": 0, "count": 0})
    return jsonify({
        "product": product,
        "reviews": reviews,
        "avg_rating": stats.get("avg", 0),
        "total": stats.get("count", 0),
    })


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
