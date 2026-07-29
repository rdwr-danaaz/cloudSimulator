"""Redeploy the socx-sim container with HTTPS, attached to ADE's docker network.

Why: ADE (config_kvision-anomaly-detection-engine_1) runs on the 'vision'
docker network and calls the SOC-X cloud over https://. The simulator must
therefore:
  1. Serve HTTPS (self-signed cert baked into the image).
  2. Be reachable by the ADE container on the 'vision' network by name.

This script:
  - Uploads the app files.
  - Builds the (now TLS-enabled) image.
  - Recreates the container on the 'vision' network, published on the host too.
  - Verifies HTTPS reachability from inside the ADE container by service name.
"""
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
NETWORK = "vision"                 # ADE's network
ADE = "config_kvision-anomaly-detection-engine_1"
HOST_PORT = 8088                   # still published on the host for convenience
INTERNAL_PORT = 8080               # container TLS port

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


def run(client: paramiko.SSHClient, cmd: str, timeout: int = 600) -> int:
    print(f"\n$ {cmd}")
    chan = client.get_transport().open_session()
    chan.settimeout(timeout)
    chan.get_pty()
    chan.exec_command(cmd)
    while True:
        if chan.recv_ready():
            sys.stdout.write(chan.recv(4096).decode(errors="replace"))
            sys.stdout.flush()
        if chan.exit_status_ready() and not chan.recv_ready():
            break
        time.sleep(0.05)
    while chan.recv_ready():
        sys.stdout.write(chan.recv(4096).decode(errors="replace"))
    rc = chan.recv_exit_status()
    print(f"[exit {rc}]")
    return rc


def main() -> int:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, username=USER, password=PASS, timeout=15, banner_timeout=30)

    run(client, f"mkdir -p {REMOTE_DIR}/recommendations")

    sftp = client.open_sftp()
    for rel in FILES:
        local = os.path.join(LOCAL_ROOT, rel)
        if os.path.exists(local):
            print(f"upload {rel}")
            sftp.put(local, f"{REMOTE_DIR}/{rel}")
    keep = os.path.join(LOCAL_ROOT, "recommendations", ".keep")
    if os.path.exists(keep):
        sftp.put(keep, f"{REMOTE_DIR}/recommendations/.keep")
    # Upload the stable TLS cert/key (baked into the image via COPY certs/)
    run(client, f"mkdir -p {REMOTE_DIR}/certs")
    for name in ("server.crt", "server.key"):
        local_cert = os.path.join(LOCAL_ROOT, "certs", name)
        if os.path.exists(local_cert):
            print(f"upload certs/{name}")
            sftp.put(local_cert, f"{REMOTE_DIR}/certs/{name}")
    sftp.close()

    if run(client, f"cd {REMOTE_DIR} && docker build -t {IMAGE} .") != 0:
        print("Build failed")
        return 1

    run(client, f"docker rm -f {CONTAINER} 2>/dev/null || true")

    # Run on the ADE network so it is reachable by name; also publish on host.
    rc = run(
        client,
        f"docker run -d --name {CONTAINER} --restart unless-stopped "
        f"--network {NETWORK} -p {HOST_PORT}:{INTERNAL_PORT} {IMAGE}",
    )
    if rc != 0:
        print("Run failed")
        return 1

    time.sleep(4)
    run(client, f"docker ps --filter name={CONTAINER}")

    # Verify HTTPS from inside the ADE container by service name
    run(
        client,
        f"docker exec {ADE} sh -c \"curl -sk -o /dev/null -w 'ADE->https://{CONTAINER}:{INTERNAL_PORT} = %{{http_code}}\\n' "
        f"https://{CONTAINER}:{INTERNAL_PORT}/health --max-time 8 || echo FAILED\"",
    )
    run(
        client,
        f"docker exec {ADE} sh -c \"curl -sk https://{CONTAINER}:{INTERNAL_PORT}/api/sdcc/genai/core/analysis/peacetime/_getRecommendation "
        f"-H 'Content-Type: application/json' "
        f"-d '{{\\\"tag\\\":\\\"85_1\\\",\\\"networks\\\":[\\\"100.98.85.0/24\\\"]}}' --max-time 8 | head -c 200\"",
    )

    print(f"\nDEPLOYMENT COMPLETE. ADE should use hostname: {CONTAINER}:{INTERNAL_PORT} (https)")
    client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())


