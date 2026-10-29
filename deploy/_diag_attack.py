import paramiko, sys
c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect('10.205.102.81', username='socx', password='radware', timeout=30)

def run(cmd):
    _, out, err = c.exec_command(cmd, timeout=60)
    o = out.read().decode('utf-8', 'replace'); e = err.read().decode('utf-8', 'replace')
    return o, e

# 1. container status + health
o, _ = run("echo radware | sudo -S -p '' docker ps --format '{{.Names}} {{.Status}}' 2>/dev/null")
print("CONTAINERS:\n", o)

# 2. last 40 lines of app logs
o, _ = run("echo radware | sudo -S -p '' docker logs --tail 40 socx-sim 2>&1")
print("LOGS:\n", o)

# 3. health from inside the container host
o, e = run("curl -ks https://localhost:8080/health; echo; echo RC=$?")
print("HEALTH:", repr(o), "ERR:", repr(e))

# 4. does UI contain the new tab?
o, _ = run("curl -ks https://localhost:8080/ui | grep -c 'Remediation Recommendations'")
print("TAB_COUNT:", o.strip())

c.close()

