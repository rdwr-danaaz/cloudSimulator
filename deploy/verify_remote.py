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


run('docker ps --filter name=socx-sim --format "{{.Names}} | {{.Status}} | {{.Ports}}"')
run("curl -s http://localhost:8088/health")
run(
    "curl -s http://localhost:8088/api/sdcc/genai/core/analysis/peacetime/_getRecommendation "
    "-H 'Content-Type: application/json' "
    "-d '{\"tag\":\"test_yehuda\",\"networks\":[\"100.98.89.0/24\"]}'"
)
run(
    "curl -s http://localhost:8088/socx_sim/api/sdcc/genai/core/analysis/peacetime/_getRecommendation "
    "-H 'Content-Type: application/json' "
    "-d '{\"tag\":\"test_yehuda\",\"networks\":[\"100.98.89.0/24\"]}' | head -c 200"
)

c.close()

