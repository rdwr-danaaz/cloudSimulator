#!/usr/bin/env python3
"""Standalone installer for the SOC-X Recommendation Simulator.

Installs and runs the simulator on a fresh Linux (Ubuntu/Debian) Docker host
over SSH. Unlike ``deploy/install.py`` (which also wires the simulator into a
local ADE container), this script just stands up the simulator so that any
Protection Engine / ADE elsewhere can be pointed at ``https://<host>:<port>``.

What it does on the target:
  1. Waits for cloud-init / apt locks to clear
  2. Installs prerequisites + Docker Engine (official get.docker.com script)
  3. Clones (or updates) the project from GitHub
  4. Generates a self-signed TLS cert whose SAN includes the host IP so remote
     clients can validate HTTPS against the IP they connect to
  5. Builds and starts the container via ``docker compose``
  6. Opens the host port in ufw (if ufw is active) and verifies /health

Usage:
    python deploy/install_standalone.py --host 10.205.102.81 --user socx \
        --password 'secret' [--port 8080] \
        [--repo https://github.com/rdwr-danaaz/cloudSimulator.git]
"""
from __future__ import annotations

import argparse
import sys

try:
    import paramiko
except ImportError:  # pragma: no cover
    sys.exit("paramiko is required: pip install -r deploy/requirements-deploy.txt")


REMOTE_SCRIPT = r"""
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
SUDO_PASS='__SUDO_PASS__'
HOST_IP='__HOST_IP__'
HOST_PORT='__HOST_PORT__'
REPO='__REPO__'
SUDO() { echo "$SUDO_PASS" | sudo -S -p '' "$@"; }

echo '### [1/8] Waiting for cloud-init / apt locks to clear...'
SUDO cloud-init status --wait >/dev/null 2>&1 || true
for i in $(seq 1 60); do
  if SUDO fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 \
     || SUDO fuser /var/lib/apt/lists/lock >/dev/null 2>&1; then
    echo "  apt/dpkg busy, waiting ($i)"; sleep 5
  else
    break
  fi
done

echo '### [2/8] apt update + prerequisites...'
SUDO apt-get update -y
SUDO apt-get install -y ca-certificates curl gnupg git openssl

echo '### [3/8] Installing Docker Engine (if missing)...'
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
  SUDO sh /tmp/get-docker.sh
else
  echo '  docker already present'
fi
SUDO docker --version

echo '### [4/8] Enabling docker service + adding user to docker group...'
SUDO systemctl enable --now docker
SUDO usermod -aG docker "$USER" || true

echo '### [5/8] Fetching project...'
cd "$HOME"
if [ -d cloudSimulator/.git ]; then
  cd cloudSimulator && git pull --ff-only || true
else
  git clone "$REPO"
  cd cloudSimulator
fi

echo "### [6/8] Generating TLS cert (SAN includes $HOST_IP)..."
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout certs/server.key -out certs/server.crt \
  -subj "/CN=socx-sim" \
  -addext "subjectAltName=DNS:socx-sim,DNS:localhost,IP:127.0.0.1,IP:${HOST_IP}" 2>/dev/null
echo '  SAN:'; openssl x509 -in certs/server.crt -noout -text | grep -A1 'Subject Alternative Name' | tail -1 | sed 's/^/    /'

echo '### [7/8] Building & starting the container...'
SUDO docker compose up -d --build

echo '### [8/8] Firewall + verification...'
if SUDO ufw status 2>/dev/null | grep -q 'Status: active'; then
  SUDO ufw allow "${HOST_PORT}"/tcp || true
  echo "  opened ufw ${HOST_PORT}/tcp"
else
  echo '  ufw inactive - no firewall change needed'
fi
sleep 6
SUDO docker compose ps
echo '--- health ---'
curl -ks "https://localhost:8080/health" && echo
echo '--- sample recommendation (100.98.89.0/24) ---'
curl -ks -X POST "https://localhost:8080/api/sdcc/genai/core/analysis/peacetime/_getRecommendation" \
  -H 'Content-Type: application/json' \
  -d '{"tag":"test","networks":["100.98.89.0/24"]}' | head -c 200 && echo
echo 'DONE_OK'
"""


def run(host: str, user: str, password: str, port: int, repo: str) -> int:
    script = (
        REMOTE_SCRIPT
        .replace("__SUDO_PASS__", password)
        .replace("__HOST_IP__", host)
        .replace("__HOST_PORT__", str(port))
        .replace("__REPO__", repo)
    )

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print(f"[*] Connecting to {user}@{host} ...")
    client.connect(host, username=user, password=password, timeout=30)

    stdin, stdout, _ = client.exec_command("bash -s", get_pty=True)
    stdin.write(script)
    stdin.channel.shutdown_write()

    ok = False
    for line in iter(stdout.readline, ""):
        line = line.rstrip("\n")
        if line:
            print(line)
        if "DONE_OK" in line:
            ok = True
    exit_status = stdout.channel.recv_exit_status()
    client.close()

    if ok and exit_status == 0:
        print("\n[✓] Simulator installed and running.")
        print(f"    URL: https://{host}:{port}/health")
        return 0
    print(f"\n[✗] Install did not complete cleanly (exit={exit_status}).")
    return 1


def main() -> int:
    ap = argparse.ArgumentParser(description="Install the SOC-X simulator on a standalone Docker host.")
    ap.add_argument("--host", required=True, help="Target host IP/name")
    ap.add_argument("--user", required=True, help="SSH username (must have sudo)")
    ap.add_argument("--password", required=True, help="SSH/sudo password")
    ap.add_argument("--port", type=int, default=8080, help="Host port to expose (default 8080)")
    ap.add_argument("--repo", default="https://github.com/rdwr-danaaz/cloudSimulator.git",
                    help="Git repo URL to clone")
    args = ap.parse_args()
    return run(args.host, args.user, args.password, args.port, args.repo)


if __name__ == "__main__":
    raise SystemExit(main())


