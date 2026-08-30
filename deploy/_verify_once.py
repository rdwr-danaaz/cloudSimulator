import sys, paramiko
HOST, USER, PASS = "10.205.102.81", "socx", "radware"
S = r"""
cd ~/cloudSimulator
echo '### commit:'; git --no-pager log --oneline -1
echo '### ps:'; echo '__P__' | sudo -S -p '' docker compose ps --format '{{.Name}} {{.Status}}'
echo -n '### health: '; curl -ks https://localhost:8080/health; echo
echo -n '### ui: '; curl -ks -o /dev/null -w '%{http_code}\n' https://localhost:8080/ui
echo DONE_OK
""".replace("__P__", PASS)
c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(HOST, username=USER, password=PASS, timeout=30, allow_agent=False, look_for_keys=False)
_i, o, _e = c.exec_command("bash -s", get_pty=True); _i.write(S); _i.channel.shutdown_write()
for line in iter(o.readline, ""):
    if line.strip(): print(line.rstrip())
c.close()

