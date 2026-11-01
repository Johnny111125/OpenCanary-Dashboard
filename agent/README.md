# OpenCanary Dashboard Agent

A lightweight Python agent that collects honeypot status and reports to the OpenCanary Dashboard.

## Features

- Collects hostname, service status, listening ports, and configured ports
- Reports via HTTP POST to the dashboard every 60 seconds
- Uses only Python stdlib (no pip dependencies)
- Runs as a systemd timer service
- Robust error handling and timeout management

## Prerequisites

- Debian/Ubuntu-like Linux system
- Python 3.8+ (pre-installed on most modern systems)
- systemd
- `ss` command (from iproute2 package, usually pre-installed)
- Network access to the dashboard server

## Installation

### 1. Create the agent directory

```bash
sudo mkdir -p /opt/canarydash
```

### 2. Copy the agent script

```bash
sudo cp report.py /opt/canarydash/report.py
sudo chmod +x /opt/canarydash/report.py
```

### 3. Create the configuration file

```bash
sudo cp canarydash.env.example /etc/canarydash.env
sudo chmod 600 /etc/canarydash.env
```

Edit `/etc/canarydash.env` with your dashboard URL and API key:

```bash
sudo nano /etc/canarydash.env
```

Required settings:
```
CANARYDASH_URL=http://YOUR_DASHBOARD_IP:8088
CANARYDASH_API_KEY=your-api-key-from-dashboard
```

### 4. Install systemd units

```bash
sudo cp canarydash-report.service /etc/systemd/system/
sudo cp canarydash-report.timer /etc/systemd/system/
```

### 5. Enable and start the timer

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now canarydash-report.timer
```

## Verification

### Check timer status

```bash
systemctl list-timers | grep canarydash
```

Expected output shows next and last trigger times.

### Run manually to test

```bash
sudo systemctl start canarydash-report.service
sudo journalctl -u canarydash-report.service -n 20
```

### Check recent logs

```bash
journalctl -u canarydash-report.service --since "10 minutes ago"
```

### Test agent directly

```bash
# Load environment and run
sudo bash -c 'source /etc/canarydash.env && /opt/canarydash/report.py'
```

## Configuration Options

Edit `/etc/canarydash.env`:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CANARYDASH_URL` | Yes | - | Dashboard URL (e.g., `http://192.168.1.100:8088`) |
| `CANARYDASH_API_KEY` | Yes | - | API key matching the dashboard |
| `CANARYDASH_NODE` | No | hostname | Override the reported node name |
| `CANARYDASH_SERVICE_UNITS` | No | `opencanary,opencanaryd` | Comma-separated systemd units to check |
| `CANARYDASH_CONFIG_PATHS` | No | (see below) | Comma-separated paths to search for config |
| `CANARYDASH_TIMEOUT` | No | `10` | HTTP request timeout in seconds |

Default config paths searched:
- `/etc/opencanaryd/opencanary.conf`
- `/etc/opencanary/opencanary.conf`
- `/root/.opencanary.conf`
- `/home/opencanary/.opencanary.conf`

## Adjusting the Interval

The default reporting interval is 60 seconds. To change it, edit the timer:

```bash
sudo systemctl edit canarydash-report.timer
```

Add:
```ini
[Timer]
OnUnitInactiveSec=
OnUnitInactiveSec=120
```

Then reload:
```bash
sudo systemctl daemon-reload
```

## Troubleshooting

### Agent not reporting

1. Check if timer is active:
   ```bash
   systemctl status canarydash-report.timer
   ```

2. Check service logs:
   ```bash
   journalctl -u canarydash-report.service -n 50
   ```

3. Test network connectivity:
   ```bash
   curl -v http://DASHBOARD_IP:8088/api/nodes
   ```

### "Connection refused" error

- Verify dashboard is running
- Check firewall on dashboard host allows port 8088
- Verify URL in `/etc/canarydash.env` is correct

### "Invalid or missing API key" error

- Verify `CANARYDASH_API_KEY` in `/etc/canarydash.env` matches the dashboard's key
- Check for extra whitespace or quotes in the env file

### Service status shows false incorrectly

- Check the systemd unit name matches your OpenCanary installation
- Verify with: `systemctl is-active opencanary` or `systemctl is-active opencanaryd`
- Set correct unit name in `CANARYDASH_SERVICE_UNITS`

### Listening ports not detected

- Verify `ss` command is available: `which ss`
- Test manually: `ss -lntupH`
- Some minimal systems may need: `apt install iproute2`

### Configured ports not detected

- Verify OpenCanary config file exists at one of the searched paths
- Check file permissions (agent runs as root)
- Test: `cat /etc/opencanaryd/opencanary.conf | python3 -m json.tool`

## Uninstallation

```bash
sudo systemctl disable --now canarydash-report.timer
sudo rm /etc/systemd/system/canarydash-report.{service,timer}
sudo systemctl daemon-reload
sudo rm -rf /opt/canarydash
sudo rm /etc/canarydash.env
```

## Quick Install Script

For convenience, here's a one-liner (after copying files to the honeypot):

```bash
sudo mkdir -p /opt/canarydash && \
sudo cp report.py /opt/canarydash/ && \
sudo chmod +x /opt/canarydash/report.py && \
sudo cp canarydash.env.example /etc/canarydash.env && \
sudo chmod 600 /etc/canarydash.env && \
sudo cp canarydash-report.{service,timer} /etc/systemd/system/ && \
sudo systemctl daemon-reload && \
echo "Edit /etc/canarydash.env with your settings, then run:" && \
echo "sudo systemctl enable --now canarydash-report.timer"
```
