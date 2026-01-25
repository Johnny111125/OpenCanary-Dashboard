# OpenCanary Dashboard

<img width="1612" height="833" alt="image" src="https://github.com/user-attachments/assets/c6f69aa1-1b12-4b0c-ace6-650590d2706c" />

A Dockerized dashboard that ingests heartbeat/status from OpenCanary honeypots and displays a real-time web UI.

## Features

- Real-time monitoring of multiple OpenCanary honeypots
- Staleness detection (configurable threshold)
- Service status monitoring (systemd is-active)
- Port drift detection (configured vs. listening)
- Simple web UI with auto-refresh
- SQLite persistence with Docker volume
- Shared API key authentication

## Prerequisites

- Linux host with Docker and Docker Compose installed
- Network access from honeypots to the dashboard host on port 8088 (configurable)

## Quick Start

### 1. Clone or create the directory

```bash
mkdir -p /opt/canarydash && cd /opt/canarydash
# Copy dashboard files here (docker-compose.yml, Dockerfile, app/)
```

### 2. Set the API key

Create a `.env` file or export the environment variable:

```bash
# Generate a secure API key
export CANARYDASH_API_KEY=$(openssl rand -hex 32)
echo "CANARYDASH_API_KEY=$CANARYDASH_API_KEY" > .env
echo "Save this key for agent configuration: $CANARYDASH_API_KEY"
```

### 3. Start the dashboard

```bash
docker compose up -d
```

### 4. Verify it's running

```bash
# Check container status
docker compose ps

# Check logs
docker compose logs -f

# Open in browser
echo "Dashboard URL: http://$(hostname -I | awk '{print $1}'):8088"
```

### 5. Test the API

```bash
# Test with a sample payload
curl -X POST http://localhost:8088/api/status \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $CANARYDASH_API_KEY" \
  -d '{
    "node": "test-honeypot",
    "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%SZ)'",
    "service_up": true,
    "ports": {
      "configured": [{"proto": "tcp", "port": 22, "service": "ssh"}],
      "listening": [{"proto": "tcp", "port": 22, "service": "ssh"}]
    }
  }'

# Verify node appears
curl http://localhost:8088/api/nodes
```

## Configuration

Environment variables (set in `.env` or `docker-compose.yml`):

| Variable | Default | Description |
|----------|---------|-------------|
| `CANARYDASH_API_KEY` | (required) | Shared secret for agent authentication |
| `CANARYDASH_PORT` | `8088` | Port to expose the dashboard on |
| `CANARYDASH_STALE_SECONDS` | `180` | Seconds before a node is marked stale |

## API Endpoints

### POST /api/status

Receive status updates from agents.

**Headers:**
- `X-API-Key`: Required. Must match `CANARYDASH_API_KEY`
- `Content-Type: application/json`

**Body:**
```json
{
  "node": "honeypot-01",
  "timestamp": "2024-01-15T10:30:00Z",
  "service_up": true,
  "ports": {
    "configured": [
      {"proto": "tcp", "port": 22, "service": "ssh"},
      {"proto": "tcp", "port": 80, "service": "http"}
    ],
    "listening": [
      {"proto": "tcp", "port": 22, "service": "ssh"},
      {"proto": "tcp", "port": 80, "service": "http"}
    ]
  },
  "last_event_ts": null
}
```

### GET /api/nodes

Returns all nodes with status, age, and drift information.

**Response:**
```json
{
  "nodes": [
    {
      "node": "honeypot-01",
      "last_seen_utc": "2024-01-15T10:30:00+00:00",
      "age_seconds": 45.2,
      "stale": false,
      "payload": { ... },
      "drift": {
        "missing_listeners": [],
        "unexpected_listeners": []
      }
    }
  ],
  "stale_threshold_seconds": 180
}
```

### GET /

Web UI dashboard (auto-refreshes every 10 seconds).

## Data Persistence

SQLite database is stored in a Docker volume (`canarydash_data`). To backup:

```bash
docker compose exec dashboard cat /app/data/canarydash.db > backup.db
```

To reset all data:

```bash
docker compose down -v
docker compose up -d
```

## Updating

```bash
cd /opt/canarydash
docker compose down
# Update files as needed
docker compose build --no-cache
docker compose up -d
```

## Troubleshooting

### Dashboard not accessible

```bash
# Check if container is running
docker compose ps

# Check container logs
docker compose logs dashboard

# Verify port binding
ss -tlnp | grep 8088
```

### Agents not connecting

```bash
# Test from honeypot
curl -v -X POST http://DASHBOARD_IP:8088/api/status \
  -H "X-API-Key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"node":"test"}'
```

### Check firewall

```bash
# On dashboard host, allow incoming on 8088
sudo ufw allow 8088/tcp
# or
sudo firewall-cmd --add-port=8088/tcp --permanent && sudo firewall-cmd --reload
```
