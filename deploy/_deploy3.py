#!/usr/bin/env python3
import sys, paramiko
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
HOST, USER, PASS = "10.205.102.81", "socx", "radware"
SCRIPT = r"""
cd ~/cloudSimulator
echo '### rebuild'
echo '__P__' | sudo -S -p '' docker compose up -d --build > /tmp/build.log 2>&1
echo "build_exit=$?"
tail -2 /tmp/build.log
sleep 6
echo '### ps'
echo '__P__' | sudo -S -p '' docker compose ps --format '{{.Name}} :: {{.Status}}'
echo '### commit'; git --no-pager log --oneline -1
echo -n '### health: '; curl -ks https://localhost:8080/health; echo
echo -n '### ui_http: '; curl -ks -o /dev/null -w '%{http_code}\n' https://localhost:8080/ui
echo DONE_OK
""".replace("__P__", PASS)
c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(HOST, username=USER, password=PASS, timeout=30, allow_agent=False, look_for_keys=False)
_i, o, e = c.exec_command("bash -s"); _i.write(SCRIPT); _i.channel.shutdown_write()
out = o.read().decode("utf-8", "replace"); err = e.read().decode("utf-8", "replace")
c.close()
print(out)
for line in err.splitlines():
    if line.strip() and "password for" not in line.lower():
        print("[stderr]", line)
print("[OK]" if "DONE_OK" in out else "[X] did not finish cleanly")

