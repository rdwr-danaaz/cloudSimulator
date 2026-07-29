"""Configure ADE socx cloud hostnames to point at the socx-sim docker.

Steps automated (from the provided runbook):
  1. Move to the ADE properties folder.
  2. Edit "ade.config.properties".
  3. Set:
       socx.positive.cloud.hostname   = <socx_sim docker>
       socx.remediation.cloud.hostname = <socx_sim docker>

Safe behavior:
  - Creates a timestamped backup before editing.
  - Updates the keys in place if present, otherwise appends them.
  - Prints a before/after diff of the affected lines.

Usage:
    python deploy/configure_ade_hostname.py            # apply changes
    python deploy/configure_ade_hostname.py --dry-run  # show what would change only
"""
import sys
import paramiko

HOST = "10.205.50.10"
USER = "root"
PASS = "radware"

PROPS_DIR = "/var/lib/docker/docker-root/volumes/config_anomaly-detection-engine-etc/_data"
PROPS_FILE = f"{PROPS_DIR}/ade.config.properties"

# The ADE container reaches the simulator over the shared 'vision' docker
# network by container name (not the host IP, which is blocked by docker
# network isolation). ADE always calls https://<value>/api/..., and the sim
# serves TLS on 8080.
SOCX_SIM = "socx-sim:8080"
KEYS = {
    "socx.positive.cloud.hostname": SOCX_SIM,
    "socx.remediation.cloud.hostname": SOCX_SIM,
}

DRY_RUN = "--dry-run" in sys.argv


def run(client: paramiko.SSHClient, cmd: str) -> tuple[int, str, str]:
    _in, out, err = client.exec_command(cmd)
    rc = out.channel.recv_exit_status()
    return rc, out.read().decode(errors="replace"), err.read().decode(errors="replace")


def main() -> int:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, username=USER, password=PASS, timeout=15, banner_timeout=30)

    # 0. Confirm file exists
    rc, _, _ = run(client, f"test -f {PROPS_FILE}")
    if rc != 0:
        print(f"ERROR: {PROPS_FILE} not found on {HOST}")
        # Help locate it in case the volume name differs
        _, found, _ = run(
            client,
            "find /var/lib/docker -name ade.config.properties 2>/dev/null",
        )
        if found.strip():
            print("Found candidate(s):\n" + found)
        client.close()
        return 1

    # 1. Show current relevant lines
    print("=== BEFORE ===")
    _, before, _ = run(
        client,
        f"grep -nE 'socx\\.(positive|remediation)\\.cloud\\.hostname' {PROPS_FILE} || echo '(keys not present)'",
    )
    print(before.strip())

    if DRY_RUN:
        print("\n[dry-run] No changes applied.")
        client.close()
        return 0

    # 2. Timestamped backup
    _, ts, _ = run(client, "date +%Y%m%d_%H%M%S")
    backup = f"{PROPS_FILE}.bak_{ts.strip()}"
    run(client, f"cp -p {PROPS_FILE} {backup}")
    print(f"\nBackup created: {backup}")

    # 3. Update or append each key
    for key, value in KEYS.items():
        line = f"{key} = {value}"
        # If the key exists (optionally commented), replace the whole line; else append.
        script = (
            f"if grep -qE '^[[:space:]]*#?[[:space:]]*{key}[[:space:]]*=' {PROPS_FILE}; then "
            f"sed -i -E 's|^[[:space:]]*#?[[:space:]]*{key}[[:space:]]*=.*|{line}|' {PROPS_FILE}; "
            f"else printf '%s\\n' '{line}' >> {PROPS_FILE}; fi"
        )
        rc, _, err = run(client, script)
        status = "updated" if rc == 0 else f"FAILED ({err.strip()})"
        print(f"  {key} -> {value}  [{status}]")

    # 4. Show result
    print("\n=== AFTER ===")
    _, after, _ = run(
        client,
        f"grep -nE 'socx\\.(positive|remediation)\\.cloud\\.hostname' {PROPS_FILE}",
    )
    print(after.strip())

    print("\nDone. Restart the ADE service/container for changes to take effect if required.")
    client.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())


