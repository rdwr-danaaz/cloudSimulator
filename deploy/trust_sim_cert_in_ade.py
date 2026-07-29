"""Trust the socx-sim self-signed cert in the ADE container's Java truststore.

ADE (Java 17) validates TLS certificates, so the simulator's self-signed cert
must be imported into the JVM cacerts, otherwise getRecommendation fails with
'PKIX path building failed'.

Note: this persists across `docker restart` but NOT across container recreation
(docker rm / compose up). Re-run after recreating the ADE container.
"""
import time
import paramiko

HOST = "10.205.50.10"
c = paramiko.SSHClient()
c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(HOST, username="root", password="radware", timeout=15)

ADE = "config_kvision-anomaly-detection-engine_1"
SIM = "socx-sim"
CACERTS = "/usr/lib/jvm/jdk-17.0.5-bellsoft-x86_64/lib/security/cacerts"
ALIAS = "socx-sim"


def run(cmd: str, timeout: int = 120) -> int:
    _i, o, e = c.exec_command(cmd, timeout=timeout)
    out = o.read().decode(errors="replace")
    err = e.read().decode(errors="replace")
    rc = o.channel.recv_exit_status()
    print(f"$ {cmd}")
    if out.strip():
        print(out.strip())
    if err.strip():
        print(f"[stderr] {err.strip()}")
    print(f"[exit {rc}]")
    print("-" * 70)
    return rc


# 1. Extract the cert from the sim container to the host
run(f"docker cp {SIM}:/app/certs/server.crt /root/socx-sim/server.crt")
# 2. Copy it into the ADE container
run(f"docker cp /root/socx-sim/server.crt {ADE}:/tmp/socx-sim.crt")
# 3. Remove any previous alias, then import
run(f"docker exec {ADE} keytool -delete -alias {ALIAS} -keystore {CACERTS} -storepass changeit 2>/dev/null || true")
run(f"docker exec {ADE} keytool -importcert -noprompt -alias {ALIAS} -file /tmp/socx-sim.crt -keystore {CACERTS} -storepass changeit")
# 4. Restart ADE to reload the truststore
run(f"docker restart {ADE}")

print("Waiting 75s for ADE to restart and call the cloud...")
time.sleep(75)

run(
    f"docker logs --since 120s {ADE} 2>&1 | grep -E "
    f"'Full REST API: https://socx-sim|Received recommendation|recommendations returned|Cloud connectivity|PKIX|closed prematurely|Processing recommendation DTO|success' "
    f"| tail -40"
)
c.close()

