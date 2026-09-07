#!/usr/bin/env python3
"""Run a remote diagnostic/command over SSH and stream output (ASCII-safe)."""
from __future__ import annotations
import argparse, sys
import paramiko

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--cmdfile", required=True)
    args = ap.parse_args()
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(args.host, username=args.user, password=args.password, timeout=30)
    with open(args.cmdfile, "r", encoding="utf-8") as fh:
        script = fh.read().replace("__PW__", args.password)
    stdin, stdout, _ = c.exec_command("bash -s", get_pty=True)
    stdin.write(script + "\necho __RC_$?__\n")
    stdin.channel.shutdown_write()
    for line in iter(stdout.readline, ""):
        sys.stdout.buffer.write(line.encode("utf-8", "replace"))
        sys.stdout.buffer.flush()
    stdout.channel.recv_exit_status()
    c.close()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())


