#!/usr/bin/env python3
"""One-off: pull latest + rebuild the simulator on its standalone host, then verify."""
import sys, paramiko

HOST = "10.205.102.81"
USER = "socx"
PASS = "radware"

SCRIPT = r"""
set -e
cd ~/cloudSimulator
echo '### git pull'
git pull --ff-only
echo '### rebuild'
echo '__P__' | sudo -S -p '' docker compose up -d --build
sleep 6
echo '### ps'
echo '__P__' | sudo -S -p '' docker compose ps
echo '### health'
curl -ks https://localhost:8080/health && echo
echo '### ui head'
curl -ks -o /dev/null -w 'ui_http=%{http_code}\n' https://localhost:8080/ui
echo DONE_OK
""".replace("__P__", PASS)

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
print(f"[*] Connecting to {USER}@{HOST} ...")
c.connect(HOST, username=USER, password=PASS, timeout=30,
          allow_agent=False, look_for_keys=False)
stdin, stdout, _ = c.exec_command("bash -s", get_pty=True)
stdin.write(SCRIPT); stdin.channel.shutdown_write()
ok = False
for line in iter(stdout.readline, ""):
    line = line.rstrip("\n")
    if line:
        print(line)
    if "DONE_OK" in line:
        ok = True
rc = stdout.channel.recv_exit_status()
c.close()
sys.exit(0 if ok and rc == 0 else 1)

