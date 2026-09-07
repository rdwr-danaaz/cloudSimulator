#!/usr/bin/env python3
"""Lean redeploy: git pull + docker compose up -d --build on an existing host.

Assumes the simulator was already installed once (Docker present, repo cloned
at ~/cloudSimulator). Streams remote output live. Usage:

    python deploy/pull_and_rebuild.py --host 10.205.102.81 --user socx --password radware
"""
from __future__ import annotations

import argparse
import sys

import paramiko

REMOTE_SCRIPT = r"""
set -e
SUDO_PASS='__SUDO_PASS__'
SUDO() { echo "$SUDO_PASS" | sudo -S -p '' "$@"; }
cd "$HOME/cloudSimulator"
echo '### git pull'
git pull --ff-only
echo '### docker compose up -d --build'
SUDO docker compose up -d --build
sleep 5
SUDO docker compose ps
echo '--- health ---'
curl -ks https://localhost:8080/health && echo
echo 'DONE_OK'
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    args = ap.parse_args()

    script = REMOTE_SCRIPT.replace("__SUDO_PASS__", args.password)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print(f"[*] Connecting to {args.user}@{args.host} ...", flush=True)
    client.connect(args.host, username=args.user, password=args.password, timeout=30)

    stdin, stdout, _ = client.exec_command("bash -s", get_pty=True)
    stdin.write(script)
    stdin.channel.shutdown_write()

    ok = False
    for line in iter(stdout.readline, ""):
        line = line.rstrip("\n")
        if line:
            print(line, flush=True)
        if "DONE_OK" in line:
            ok = True
    rc = stdout.channel.recv_exit_status()
    client.close()
    print(f"[exit {rc}] ok={ok}", flush=True)
    return 0 if (ok and rc == 0) else 1


if __name__ == "__main__":
    raise SystemExit(main())

