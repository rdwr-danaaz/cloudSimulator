import sys
import paramiko

HOST = "10.205.50.10"
USER = "root"
PASS = "radware"


def main() -> int:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, username=USER, password=PASS, timeout=15, banner_timeout=30)

    cmds = [
        ("whoami", "whoami"),
        ("os-release", "cat /etc/os-release | grep -E '^(NAME|VERSION)=' || true"),
        ("arch", "uname -m"),
        ("docker", "command -v docker && docker --version || echo 'NO_DOCKER'"),
        ("compose", "docker compose version 2>/dev/null || echo 'NO_COMPOSE'"),
        ("internet", "curl -m 8 -fsSL https://download.docker.com/ -o /dev/null && echo NET_OK || echo NET_FAIL"),
        ("port8080", "(ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null) | grep ':8080 ' && echo PORT_IN_USE || echo PORT_FREE"),
    ]
    for label, cmd in cmds:
        stdin, stdout, stderr = client.exec_command(cmd, timeout=30)
        out = stdout.read().decode(errors="replace").strip()
        err = stderr.read().decode(errors="replace").strip()
        print(f"=== {label} ===")
        if out:
            print(out)
        if err:
            print(f"[stderr] {err}")
        print()

    client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

