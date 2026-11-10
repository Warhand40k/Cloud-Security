"""
Microservice Application for Cloud SRE & Security Testbed (Stage 3)
Exposes an e-commerce microservice with Prometheus service metrics and request telemetry.
Runs on http://127.0.0.1:8088 by default.
"""

import time
import json
import random
import os
import threading
from typing import Dict, Any, List
from flask import Flask, request, jsonify, Response
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST

app = Flask(__name__)

# Prometheus Metrics Definitions
HTTP_REQUESTS_TOTAL = Counter(
    "http_requests_total",
    "Total HTTP Requests",
    ["method", "endpoint", "status"]
)
HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "http_request_duration_seconds",
    "HTTP Request Latency in Seconds",
    ["endpoint"],
    buckets=[0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 1.0, 2.5]
)
HTTP_ACTIVE_CONNECTIONS = Gauge(
    "http_active_connections",
    "Current active connections in the microservice"
)
HTTP_REQUEST_BYTES_TOTAL = Counter(
    "http_request_size_bytes_total",
    "Total incoming request payload bytes"
)
HTTP_RESPONSE_BYTES_TOTAL = Counter(
    "http_response_size_bytes_total",
    "Total outgoing response payload bytes"
)

# Mock Product Database
CATALOG_ITEMS = [
    {"id": i, "name": f"Cloud Component {i}", "price": round(random.uniform(9.99, 499.99), 2), "stock": random.randint(10, 500)}
    for i in range(1, 101)
]

# Thread-safe Request Log Buffer for Windowed Telemetry
_telemetry_lock = threading.Lock()
_window_request_logs: List[Dict[str, Any]] = []

@app.before_request
def before_request():
    request.start_time = time.time()
    HTTP_ACTIVE_CONNECTIONS.inc()
    req_bytes = request.content_length or len(request.get_data()) or 120
    HTTP_REQUEST_BYTES_TOTAL.inc(req_bytes)
    request.req_bytes = req_bytes

@app.after_request
def after_request(response):
    HTTP_ACTIVE_CONNECTIONS.dec()
    duration = time.time() - request.start_time
    resp_bytes = len(response.get_data()) or 200
    HTTP_RESPONSE_BYTES_TOTAL.inc(resp_bytes)

    status_str = str(response.status_code)
    endpoint = request.path
    if endpoint.startswith("/api/catalog/"):
        endpoint = "/api/catalog/:id"

    HTTP_REQUESTS_TOTAL.labels(method=request.method, endpoint=endpoint, status=status_str).inc()
    HTTP_REQUEST_DURATION_SECONDS.labels(endpoint=endpoint).observe(duration)

    # Record telemetry event
    with _telemetry_lock:
        _window_request_logs.append({
            "timestamp": request.start_time,
            "method": request.method,
            "path": request.path,
            "status": response.status_code,
            "duration_sec": duration,
            "req_bytes": getattr(request, "req_bytes", 120),
            "resp_bytes": resp_bytes
        })

    return response

# Microservice Business Logic Endpoints
@app.route("/", methods=["GET"])
def index():
    return jsonify({"service": "cloud-ecom-microservice", "version": "1.0.0", "status": "running"})

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy", "database": "connected", "cache": "operational"})

@app.route("/api/catalog", methods=["GET"])
def get_catalog():
    # Simulate DB query delay
    limit = int(request.args.get("limit", 20))
    time.sleep(random.uniform(0.002, 0.008))
    return jsonify({"catalog": CATALOG_ITEMS[:limit], "total": len(CATALOG_ITEMS)})

@app.route("/api/catalog/<int:item_id>", methods=["GET"])
def get_item(item_id):
    time.sleep(random.uniform(0.001, 0.005))
    for item in CATALOG_ITEMS:
        if item["id"] == item_id:
            return jsonify(item)
    return jsonify({"error": "Item not found"}), 404

@app.route("/api/search", methods=["GET"])
def search():
    query = request.args.get("q", "")
    time.sleep(random.uniform(0.005, 0.015))
    results = [item for item in CATALOG_ITEMS if query.lower() in item["name"].lower()]
    return jsonify({"query": query, "matches": results})

@app.route("/api/checkout", methods=["POST"])
def checkout():
    data = request.get_json(silent=True) or {}
    # Simulate transaction processing
    time.sleep(random.uniform(0.010, 0.025))
    if "cart_id" in data or "items" in data or random.random() > 0.1:
        return jsonify({"order_id": f"ORD-{random.randint(10000, 99999)}", "status": "confirmed"}), 201
    return jsonify({"error": "Invalid checkout payload"}), 400

# Prometheus Metrics Exposition Endpoint
@app.route("/metrics", methods=["GET"])
def metrics():
    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)

# Telemetry Flushing Endpoint for Testbed Window Extraction
@app.route("/telemetry/flush_window", methods=["POST"])
def flush_window():
    global _window_request_logs
    with _telemetry_lock:
        logs = _window_request_logs
        _window_request_logs = []
    
    n_reqs = len(logs)
    if n_reqs == 0:
        return jsonify({
            "flow_count": 0,
            "tot_fwd_bytes": 0,
            "tot_bwd_bytes": 0,
            "duration_mean": 0.0,
            "status_200_count": 0,
            "status_4xx_count": 0,
            "status_5xx_count": 0,
            "error_rate": 0.0,
            "p50_latency": 0.0,
            "p95_latency": 0.0,
            "p99_latency": 0.0
        })

    durations = [r["duration_sec"] for r in logs]
    durations.sort()
    fwd_bytes = sum(r["req_bytes"] for r in logs)
    bwd_bytes = sum(r["resp_bytes"] for r in logs)
    s200 = sum(1 for r in logs if 200 <= r["status"] < 300)
    s4xx = sum(1 for r in logs if 400 <= r["status"] < 500)
    s5xx = sum(1 for r in logs if 500 <= r["status"] < 600)

    p50 = durations[int(0.50 * n_reqs)]
    p95 = durations[min(n_reqs - 1, int(0.95 * n_reqs))]
    p99 = durations[min(n_reqs - 1, int(0.99 * n_reqs))]

    return jsonify({
        "flow_count": n_reqs,
        "tot_fwd_bytes": fwd_bytes,
        "tot_bwd_bytes": bwd_bytes,
        "duration_mean": float(sum(durations) / n_reqs),
        "status_200_count": s200,
        "status_4xx_count": s4xx,
        "status_5xx_count": s5xx,
        "error_rate": float((s4xx + s5xx) / n_reqs),
        "p50_latency": float(p50),
        "p95_latency": float(p95),
        "p99_latency": float(p99)
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8088))
    app.run(host="127.0.0.1", port=port, threaded=True)
