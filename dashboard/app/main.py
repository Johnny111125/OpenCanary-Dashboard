#!/usr/bin/env python3
"""
OpenCanary Dashboard - FastAPI Application
Ingests heartbeat/status from OpenCanary honeypots and displays a web UI.
"""

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

# Configuration from environment
API_KEY = os.environ.get("CANARYDASH_API_KEY", "")
STALE_SECONDS = int(os.environ.get("CANARYDASH_STALE_SECONDS", "180"))
DB_PATH = Path(os.environ.get("CANARYDASH_DB_PATH", "/app/data/canarydash.db"))

app = FastAPI(title="OpenCanary Dashboard", version="1.0.0")


def init_db():
    """Initialize the SQLite database."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS node_status (
                node TEXT PRIMARY KEY,
                last_seen_utc TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
        """)
        conn.commit()


@contextmanager
def get_db():
    """Context manager for database connections."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def validate_api_key(x_api_key: str | None) -> None:
    """Validate the API key from request header."""
    if not API_KEY:
        raise HTTPException(status_code=500, detail="Server API key not configured")
    if not x_api_key or x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


def compute_drift(payload: dict) -> dict:
    """Compute port drift between configured and listening ports."""
    ports = payload.get("ports", {})

    # Extract configured ports as set of (proto, port) tuples
    configured_set = set()
    for p in ports.get("configured", []):
        proto = p.get("proto", "tcp").lower()
        port = p.get("port")
        if port is not None:
            configured_set.add((proto, int(port)))

    # Extract listening ports as set of (proto, port) tuples
    listening_set = set()
    for p in ports.get("listening", []):
        proto = p.get("proto", "tcp").lower()
        port = p.get("port")
        if port is not None:
            listening_set.add((proto, int(port)))

    # Compute drift
    missing = configured_set - listening_set
    unexpected = listening_set - configured_set

    return {
        "missing_listeners": [{"proto": p[0], "port": p[1]} for p in sorted(missing)],
        "unexpected_listeners": [{"proto": p[0], "port": p[1]} for p in sorted(unexpected)]
    }


@app.on_event("startup")
async def startup_event():
    """Initialize database on startup."""
    init_db()


@app.post("/api/status")
async def post_status(request: Request, x_api_key: str | None = Header(None)):
    """
    Receive status update from an agent.
    Upserts node data into the database.
    """
    validate_api_key(x_api_key)

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

    node = payload.get("node")
    if not node or not isinstance(node, str):
        raise HTTPException(status_code=400, detail="Missing or invalid 'node' field")

    last_seen_utc = datetime.now(timezone.utc).isoformat()
    payload_json = json.dumps(payload)

    with get_db() as conn:
        conn.execute("""
            INSERT INTO node_status (node, last_seen_utc, payload_json)
            VALUES (?, ?, ?)
            ON CONFLICT(node) DO UPDATE SET
                last_seen_utc = excluded.last_seen_utc,
                payload_json = excluded.payload_json
        """, (node, last_seen_utc, payload_json))
        conn.commit()

    return {"status": "ok", "node": node, "received_at": last_seen_utc}


@app.get("/api/nodes")
async def get_nodes():
    """
    Return list of all nodes with status and drift information.
    """
    now = datetime.now(timezone.utc)
    nodes = []

    with get_db() as conn:
        cursor = conn.execute("SELECT node, last_seen_utc, payload_json FROM node_status ORDER BY node")
        for row in cursor:
            try:
                last_seen = datetime.fromisoformat(row["last_seen_utc"].replace("Z", "+00:00"))
                age_seconds = (now - last_seen).total_seconds()
            except Exception:
                age_seconds = float("inf")

            try:
                payload = json.loads(row["payload_json"])
            except Exception:
                payload = {}

            drift = compute_drift(payload)

            nodes.append({
                "node": row["node"],
                "last_seen_utc": row["last_seen_utc"],
                "age_seconds": round(age_seconds, 1),
                "stale": age_seconds > STALE_SECONDS,
                "payload": payload,
                "drift": drift
            })

    return {"nodes": nodes, "stale_threshold_seconds": STALE_SECONDS}


@app.get("/", response_class=HTMLResponse)
async def index():
    """Serve the dashboard UI."""
    return HTML_PAGE


# HTML template for the dashboard UI
HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenCanary Dashboard</title>
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #1a1a2e;
            color: #eee;
            padding: 20px;
            min-height: 100vh;
        }
        h1 {
            text-align: center;
            margin-bottom: 10px;
            color: #00d4ff;
        }
        .subtitle {
            text-align: center;
            color: #888;
            margin-bottom: 30px;
            font-size: 14px;
        }
        .refresh-info {
            text-align: center;
            color: #666;
            font-size: 12px;
            margin-bottom: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .cards {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(450px, 1fr));
            gap: 20px;
        }
        .card {
            background: #16213e;
            border-radius: 12px;
            padding: 20px;
            border: 1px solid #0f3460;
        }
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            padding-bottom: 15px;
            border-bottom: 1px solid #0f3460;
        }
        .node-name {
            font-size: 20px;
            font-weight: bold;
            color: #00d4ff;
        }
        .status-pill {
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }
        .status-ok {
            background: #00c853;
            color: #000;
        }
        .status-stale {
            background: #ff9800;
            color: #000;
        }
        .status-down {
            background: #f44336;
            color: #fff;
        }
        .info-row {
            display: flex;
            margin-bottom: 10px;
            font-size: 14px;
        }
        .info-label {
            color: #888;
            width: 120px;
            flex-shrink: 0;
        }
        .info-value {
            color: #ddd;
            word-break: break-all;
        }
        .port-list {
            display: flex;
            flex-wrap: wrap;
            gap: 5px;
        }
        .port-tag {
            background: #0f3460;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-family: monospace;
        }
        .port-tag.missing {
            background: #b71c1c;
        }
        .port-tag.unexpected {
            background: #e65100;
        }
        .section-title {
            color: #888;
            font-size: 12px;
            text-transform: uppercase;
            margin-top: 15px;
            margin-bottom: 8px;
        }
        .drift-section {
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid #0f3460;
        }
        .drift-warning {
            color: #ff9800;
            font-size: 12px;
            margin-bottom: 5px;
        }
        .no-nodes {
            text-align: center;
            color: #666;
            padding: 50px;
            font-size: 18px;
        }
        .error-msg {
            text-align: center;
            color: #f44336;
            padding: 20px;
        }
        .timestamp {
            font-family: monospace;
            font-size: 13px;
        }
        .age {
            color: #888;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🍯 OpenCanary Dashboard</h1>
        <p class="subtitle">Honeypot Monitoring System</p>
        <p class="refresh-info">Auto-refresh every 10 seconds | Stale threshold: <span id="stale-threshold">180</span>s</p>
        <div id="cards" class="cards">
            <div class="no-nodes">Loading...</div>
        </div>
    </div>

    <script>
        const SERVICE_NAMES = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 143: 'imap', 443: 'https', 445: 'smb',
            1433: 'mssql', 3306: 'mysql', 3389: 'rdp', 5432: 'postgres',
            5900: 'vnc', 6379: 'redis', 8080: 'http-alt', 27017: 'mongodb'
        };

        function formatPort(p) {
            const proto = (p.proto || 'tcp').toUpperCase();
            const port = p.port;
            const svc = p.service || SERVICE_NAMES[port] || '';
            return svc ? `${proto}/${port} (${svc})` : `${proto}/${port}`;
        }

        function formatTimestamp(iso) {
            try {
                const d = new Date(iso);
                return d.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
            } catch {
                return iso;
            }
        }

        function getStatusInfo(node) {
            const serviceUp = node.payload?.service_up;
            if (node.stale) {
                return { class: 'status-stale', text: 'STALE' };
            }
            if (serviceUp === false) {
                return { class: 'status-down', text: 'SERVICE DOWN' };
            }
            return { class: 'status-ok', text: 'OK' };
        }

        function renderPorts(ports, cssClass = '') {
            if (!ports || ports.length === 0) {
                return '<span style="color:#666">None</span>';
            }
            return ports.map(p =>
                `<span class="port-tag ${cssClass}">${formatPort(p)}</span>`
            ).join('');
        }

        function renderNode(node) {
            const status = getStatusInfo(node);
            const configured = node.payload?.ports?.configured || [];
            const listening = node.payload?.ports?.listening || [];
            const missing = node.drift?.missing_listeners || [];
            const unexpected = node.drift?.unexpected_listeners || [];
            const hasDrift = missing.length > 0 || unexpected.length > 0;

            let driftHtml = '';
            if (hasDrift) {
                driftHtml = `
                    <div class="drift-section">
                        <div class="drift-warning">⚠️ Port Drift Detected</div>
                        ${missing.length > 0 ? `
                            <div class="section-title">Missing Listeners (configured but not listening)</div>
                            <div class="port-list">${renderPorts(missing, 'missing')}</div>
                        ` : ''}
                        ${unexpected.length > 0 ? `
                            <div class="section-title">Unexpected Listeners (listening but not configured)</div>
                            <div class="port-list">${renderPorts(unexpected, 'unexpected')}</div>
                        ` : ''}
                    </div>
                `;
            }

            return `
                <div class="card">
                    <div class="card-header">
                        <span class="node-name">${escapeHtml(node.node)}</span>
                        <span class="status-pill ${status.class}">${status.text}</span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Last Seen:</span>
                        <span class="info-value">
                            <span class="timestamp">${formatTimestamp(node.last_seen_utc)}</span>
                            <span class="age">(${Math.round(node.age_seconds)}s ago)</span>
                        </span>
                    </div>
                    <div class="info-row">
                        <span class="info-label">Service:</span>
                        <span class="info-value">${node.payload?.service_up ? '✅ Running' : '❌ Not Running'}</span>
                    </div>
                    <div class="section-title">Listening Ports</div>
                    <div class="port-list">${renderPorts(listening)}</div>
                    <div class="section-title">Configured Ports</div>
                    <div class="port-list">${renderPorts(configured)}</div>
                    ${driftHtml}
                </div>
            `;
        }

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        async function refresh() {
            try {
                const resp = await fetch('/api/nodes');
                if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
                const data = await resp.json();

                document.getElementById('stale-threshold').textContent = data.stale_threshold_seconds;

                const container = document.getElementById('cards');
                if (!data.nodes || data.nodes.length === 0) {
                    container.innerHTML = '<div class="no-nodes">No nodes reporting yet. Deploy agents to your honeypots.</div>';
                    return;
                }

                container.innerHTML = data.nodes.map(renderNode).join('');
            } catch (err) {
                console.error('Refresh error:', err);
                document.getElementById('cards').innerHTML =
                    `<div class="error-msg">Error loading data: ${escapeHtml(err.message)}</div>`;
            }
        }

        // Initial load and auto-refresh
        refresh();
        setInterval(refresh, 10000);
    </script>
</body>
</html>
"""
