#!/usr/bin/env python3
"""Pull the simulator's live runtime data (templates + configured CCs) from the
running container on the VM into the local repo's data/ folder, so the exact
state configured through the UI/API is captured in git.

    python deploy/pull_live_data.py --host 10.205.102.81 --user socx --password radware

Reads /app/data/*.json out of the running ``socx-sim`` container via
``docker exec`` and writes them to ./data/ locally.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import paramiko

CONTAINER = "socx-sim"
FILES = ["response_template.json", "configured_ccs.json"]
MARKER = "__SOCX_FILE__"


def run(client: paramiko.SSHClient, cmd: str) -> tuple[int, bytes]:
    stdin, stdout, stderr = client.exec_command(cmd)
    data = stdout.read()
    rc = stdout.channel.recv_exit_status()
    return rc, data


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--container", default=CONTAINER)
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent.parent / "data"))
    args = ap.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    print(f"[*] Connecting to {args.user}@{args.host} ...", flush=True)
    client.connect(args.host, username=args.user, password=args.password, timeout=30)

    # sudo wrapper (docker may need root); password via -S
    sudo = f"echo '{args.password}' | sudo -S -p '' "

    rc = 0
    for name in FILES:
        remote_cat = f"docker exec {args.container} cat /app/data/{name}"
        # try without sudo first, fall back to sudo
        code, data = run(client, remote_cat)
        if code != 0 or not data.strip():
            code, data = run(client, sudo + remote_cat)
        if code != 0 or not data.strip():
            print(f"[!] could not read {name} (rc={code})", flush=True)
            rc = 1
            continue
        dest = out_dir / name
        dest.write_bytes(data)
        print(f"[+] wrote {dest} ({len(data)} bytes)", flush=True)

    client.close()
    return rc


if __name__ == "__main__":
    raise SystemExit(main())

