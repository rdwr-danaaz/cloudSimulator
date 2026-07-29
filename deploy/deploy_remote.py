import os
import sys
import time
import paramiko

HOST = "10.205.50.10"
USER = "root"
PASS = "radware"

REMOTE_DIR = "/root/socx-sim"
IMAGE = "socx-sim:latest"
CONTAINER = "socx-sim"
CANDIDATE_PORTS = [8088, 9090, 18080, 8090, 8081]

LOCAL_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILES = [
    "cloud_mock_server.py",
    "permanent_responses.py",
    "main.py",
    "requirements.txt",
    "Dockerfile",
    "docker-compose.yml",
    ".dockerignore",
]
REC_FILE = os.path.join("recommendations", ".keep")


def run(client: paramiko.SSHClient, cmd: str, timeout: int = 600) -> int:
    print(f"\n$ {cmd}")
    chan = client.get_transport().open_session()
    chan.settimeout(timeout)
    chan.get_pty()
    chan.exec_command(cmd)
    buf = b""
    while True:
        if chan.recv_ready():
            data = chan.recv(4096)
            if not data:
                break
            buf += data
            sys.stdout.write(data.decode(errors="replace"))
            sys.stdout.flush()
        if chan.exit_status_ready() and not chan.recv_ready():
            break
        time.sleep(0.05)
    # drain remaining
    while chan.recv_ready():
        sys.stdout.write(chan.recv(4096).decode(errors="replace"))
    rc = chan.recv_exit_status()
    print(f"[exit {rc}]")
    return rc


def pick_port(client: paramiko.SSHClient) -> int:
    for port in CANDIDATE_PORTS:
        cmd = f"(ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null) | grep ':{port} ' >/dev/null && echo USED || echo FREE"
        _in, out, _err = client.exec_command(cmd)
        if out.read().decode().strip().endswith("FREE"):
            return port
    raise RuntimeError("No free candidate port found")


def main() -> int:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, username=USER, password=PASS, timeout=15, banner_timeout=30)

    port = pick_port(client)
    print(f"Selected host port: {port}")

    # 1. Create remote dirs
    run(client, f"mkdir -p {REMOTE_DIR}/recommendations")

    # 2. Upload files via SFTP
    sftp = client.open_sftp()
    for rel in FILES:
        local = os.path.join(LOCAL_ROOT, rel)
        remote = f"{REMOTE_DIR}/{rel}"
        print(f"upload {rel}")
        sftp.put(local, remote)
    # recommendations/.keep
    local_keep = os.path.join(LOCAL_ROOT, REC_FILE)
    sftp.put(local_keep, f"{REMOTE_DIR}/recommendations/.keep")
    sftp.close()

    # 3. Build image
    rc = run(client, f"cd {REMOTE_DIR} && docker build -t {IMAGE} .")
    if rc != 0:
        print("Build failed")
        return rc

    # 4. Remove old container if any
    run(client, f"docker rm -f {CONTAINER} 2>/dev/null || true")

    # 5. Run container
    rc = run(client, f"docker run -d --name {CONTAINER} --restart unless-stopped -p {port}:8080 {IMAGE}")
    if rc != 0:
        print("Run failed")
        return rc

    # 6. Wait and test
    time.sleep(3)
    run(client, f"docker ps --filter name={CONTAINER}")
    run(client, f"curl -s http://localhost:{port}/health")
    run(
        client,
        "curl -s http://localhost:%d/api/sdcc/genai/core/analysis/peacetime/_getRecommendation "
        "-H 'Content-Type: application/json' "
        "-d '{\"tag\":\"test_yehuda\",\"networks\":[\"100.98.89.0/24\"]}'" % port,
    )

    print(f"\n\nDEPLOYMENT COMPLETE. Host port = {port}")
    print(f"Root:     http://{HOST}:{port}/api/sdcc/genai/core/analysis/peacetime/_getRecommendation")
    print(f"Prefixed: http://{HOST}:{port}/socx_sim/api/sdcc/genai/core/analysis/peacetime/_getRecommendation")

    client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

