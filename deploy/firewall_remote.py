import paramiko

c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect("10.205.50.10", username="root", password="radware", timeout=15)


def run(cmd: str) -> None:
    _i, o, e = c.exec_command(cmd)
    out = o.read().decode(errors="replace")
    err = e.read().decode(errors="replace")
    print(f"$ {cmd}")
    if out.strip():
        print(out)
    if err.strip():
        print(f"[stderr] {err}")
    print("-" * 60)


# Open firewall only if ufw is active; otherwise nothing to do (Docker publishes the port directly)
run("if command -v ufw >/dev/null 2>&1; then ufw status | head -1; else echo 'ufw not installed'; fi")
run("if command -v ufw >/dev/null 2>&1 && ufw status | grep -qi active; then ufw allow 8088/tcp && echo RULE_ADDED; else echo 'no ufw rule needed'; fi")
run("hostname -I")

c.close()

