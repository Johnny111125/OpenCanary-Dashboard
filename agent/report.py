#!/usr/bin/env python3
"""
OpenCanary Dashboard Agent
Collects honeypot status and reports to the dashboard server.
Uses only Python stdlib (no external dependencies).
"""

import http.client
import json
import os
import re
import socket
import subprocess
import sys
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Configuration from environment
CANARYDASH_URL = os.environ.get("CANARYDASH_URL", "")
CANARYDASH_API_KEY = os.environ.get("CANARYDASH_API_KEY", "")
CANARYDASH_NODE = os.environ.get("CANARYDASH_NODE", "")
CANARYDASH_SERVICE_UNITS = os.environ.get("CANARYDASH_SERVICE_UNITS", "opencanary,opencanaryd")
CANARYDASH_CONFIG_PATHS = os.environ.get(
    "CANARYDASH_CONFIG_PATHS",
    "/etc/opencanaryd/opencanary.conf,/etc/opencanary/opencanary.conf,/root/.opencanary.conf,/home/opencanary/.opencanary.conf"
)
CANARYDASH_TIMEOUT = int(os.environ.get("CANARYDASH_TIMEOUT", "10"))


def get_hostname() -> str:
    """Get the node hostname, with optional override."""
    if CANARYDASH_NODE:
        return CANARYDASH_NODE
    return socket.gethostname()


def run_command(cmd: list[str], timeout: int = 10) -> tuple[int, str, str]:
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"
    except Exception as e:
        return -1, "", str(e)


def check_service_status() -> bool:
    """Check if OpenCanary service is active using systemctl."""
    units = [u.strip() for u in CANARYDASH_SERVICE_UNITS.split(",") if u.strip()]

    for unit in units:
        returncode, stdout, _ = run_command(["systemctl", "is-active", unit])
        if returncode == 0 and stdout.strip() == "active":
            return True

    return False


def parse_ss_output(output: str) -> list[dict]:
    """
    Parse output from 'ss -lntupH' to extract listening ports.
    Format varies but typically: Netid State Recv-Q Send-Q Local:Port Peer:Port Process
    With -H (no header), we get lines directly.
    """
    ports = []
    seen = set()

    for line in output.strip().split("\n"):
        if not line.strip():
            continue

        parts = line.split()
        if len(parts) < 5:
            continue

        # First field is typically protocol (tcp, udp)
        proto_raw = parts[0].lower()
        if proto_raw in ("tcp", "udp", "tcp6", "udp6"):
            proto = "tcp" if "tcp" in proto_raw else "udp"
        else:
            continue

        # Find the local address:port field (usually 4th or 5th field)
        local_addr = None
        for part in parts[3:6]:
            if ":" in part:
                local_addr = part
                break

        if not local_addr:
            continue

        # Extract port from address (handle IPv6 [addr]:port and IPv4 addr:port)
        port = None
        if local_addr.startswith("["):
            # IPv6: [::]:22 or [::1]:22
            match = re.search(r"\]:(\d+)$", local_addr)
            if match:
                port = int(match.group(1))
        else:
            # IPv4: 0.0.0.0:22 or 127.0.0.1:22 or *:22
            match = re.search(r":(\d+)$", local_addr)
            if match:
                port = int(match.group(1))

        if port is None:
            continue

        # Try to extract process name from the last field
        process = None
        if len(parts) > 5:
            # Process info often looks like: users:(("sshd",pid=1234,fd=3))
            proc_field = parts[-1]
            proc_match = re.search(r'\(\("([^"]+)"', proc_field)
            if proc_match:
                process = proc_match.group(1)

        # Deduplicate by (proto, port)
        key = (proto, port)
        if key not in seen:
            seen.add(key)
            entry = {"proto": proto, "port": port}
            if process:
                entry["process"] = process
            ports.append(entry)

    return sorted(ports, key=lambda x: (x["proto"], x["port"]))


def get_listening_ports() -> list[dict]:
    """Get list of listening TCP/UDP ports using ss."""
    # -l: listening, -n: numeric, -t: tcp, -u: udp, -p: processes, -H: no header
    returncode, stdout, stderr = run_command(["ss", "-lntupH"])

    if returncode != 0:
        # Try without -H flag (older ss versions)
        returncode, stdout, stderr = run_command(["ss", "-lntup"])
        if returncode != 0:
            print(f"Warning: ss command failed: {stderr}", file=sys.stderr)
            return []
        # Remove header line
        lines = stdout.strip().split("\n")
        if lines and lines[0].startswith("Netid"):
            stdout = "\n".join(lines[1:])

    return parse_ss_output(stdout)


def parse_opencanary_config(config_path: str) -> list[dict]:
    """
    Parse OpenCanary config file to extract configured services/ports.
    Returns list of {proto, port, service} dicts.
    """
    ports = []

    try:
        with open(config_path, "r") as f:
            config = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"Warning: Could not parse config {config_path}: {e}", file=sys.stderr)
        return []

    # OpenCanary config uses keys like "ssh.enabled", "ssh.port"
    # Common services and their default ports
    service_defaults = {
        "ftp": 21,
        "ssh": 22,
        "telnet": 23,
        "http": 80,
        "https": 443,
        "httpproxy": 8080,
        "smb": 445,
        "mysql": 3306,
        "mssql": 1433,
        "vnc": 5900,
        "redis": 6379,
        "rdp": 3389,
        "sip": 5060,
        "snmp": 161,
        "ntp": 123,
        "tftp": 69,
        "tcpbanner": 8888,
        "git": 9418,
        "portscan": None,  # Not a listening service
    }

    for service, default_port in service_defaults.items():
        enabled_key = f"{service}.enabled"
        port_key = f"{service}.port"

        # Check if service is enabled
        if config.get(enabled_key, False):
            # Get port (use default if not specified)
            port = config.get(port_key, default_port)

            if port is not None:
                # Determine protocol (most are TCP, some are UDP)
                proto = "udp" if service in ("snmp", "ntp", "tftp", "sip") else "tcp"

                ports.append({
                    "proto": proto,
                    "port": int(port),
                    "service": service
                })

    # Handle special case for tcpbanner with multiple ports
    if config.get("tcpbanner.enabled", False):
        banner_config = config.get("tcpbanner", {})
        if isinstance(banner_config, dict):
            # tcpbanner can have multiple ports defined
            max_banners = banner_config.get("maxnum", 10)
            for i in range(1, max_banners + 1):
                port = banner_config.get(f"{i}.port")
                if port:
                    ports.append({
                        "proto": "tcp",
                        "port": int(port),
                        "service": f"tcpbanner-{i}"
                    })

    return sorted(ports, key=lambda x: (x["proto"], x["port"]))


def get_configured_ports() -> list[dict]:
    """Find and parse OpenCanary config to get configured ports."""
    config_paths = [p.strip() for p in CANARYDASH_CONFIG_PATHS.split(",") if p.strip()]

    for path in config_paths:
        if Path(path).is_file():
            ports = parse_opencanary_config(path)
            if ports:
                return ports

    return []


def build_payload() -> dict:
    """Build the complete status payload."""
    return {
        "node": get_hostname(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service_up": check_service_status(),
        "ports": {
            "configured": get_configured_ports(),
            "listening": get_listening_ports()
        },
        "last_event_ts": None  # Future-ready field
    }


def send_payload(payload: dict) -> bool:
    """Send payload to the dashboard server using stdlib http.client."""
    if not CANARYDASH_URL:
        print("Error: CANARYDASH_URL not set", file=sys.stderr)
        return False

    if not CANARYDASH_API_KEY:
        print("Error: CANARYDASH_API_KEY not set", file=sys.stderr)
        return False

    # Parse URL
    parsed = urllib.parse.urlparse(CANARYDASH_URL)
    host = parsed.hostname
    port = parsed.port
    scheme = parsed.scheme.lower()

    if not host:
        print(f"Error: Invalid URL: {CANARYDASH_URL}", file=sys.stderr)
        return False

    # Determine port and connection class
    if scheme == "https":
        port = port or 443
        conn_class = http.client.HTTPSConnection
    else:
        port = port or 80
        conn_class = http.client.HTTPConnection

    # Build path
    path = parsed.path.rstrip("/") + "/api/status"

    # Serialize payload
    body = json.dumps(payload).encode("utf-8")

    headers = {
        "Content-Type": "application/json",
        "X-API-Key": CANARYDASH_API_KEY,
        "Content-Length": str(len(body))
    }

    try:
        conn = conn_class(host, port, timeout=CANARYDASH_TIMEOUT)
        conn.request("POST", path, body=body, headers=headers)
        response = conn.getresponse()
        response_body = response.read().decode("utf-8")

        if response.status == 200:
            print(f"Success: {response_body}")
            return True
        else:
            print(f"Error: HTTP {response.status} - {response_body}", file=sys.stderr)
            return False

    except socket.timeout:
        print(f"Error: Connection timed out after {CANARYDASH_TIMEOUT}s", file=sys.stderr)
        return False
    except ConnectionRefusedError:
        print(f"Error: Connection refused to {host}:{port}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"Error: {type(e).__name__}: {e}", file=sys.stderr)
        return False
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main() -> int:
    """Main entry point."""
    # Validate required configuration
    if not CANARYDASH_URL:
        print("Error: CANARYDASH_URL environment variable not set", file=sys.stderr)
        print("Set it in /etc/canarydash.env or export it", file=sys.stderr)
        return 1

    if not CANARYDASH_API_KEY:
        print("Error: CANARYDASH_API_KEY environment variable not set", file=sys.stderr)
        return 1

    # Build and send payload
    payload = build_payload()

    # Debug output
    print(f"Node: {payload['node']}")
    print(f"Service up: {payload['service_up']}")
    print(f"Listening ports: {len(payload['ports']['listening'])}")
    print(f"Configured ports: {len(payload['ports']['configured'])}")

    if send_payload(payload):
        return 0
    else:
        return 1


if __name__ == "__main__":
    sys.exit(main())
