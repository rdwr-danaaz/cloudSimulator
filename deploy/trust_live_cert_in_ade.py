"""Trust the *live* simulator cert that ADE is actually dialing, in ADE's Java truststore.

Fixes:
    javax.net.ssl.SSLHandshakeException: PKIX path building failed:
    sun.security.provider.certpath.SunCertPathBuilderException:
    unable to find valid certification path to requested target

...seen when the ADE (Java 17) calls the SOC-X simulator over HTTPS and does not
trust its self-signed certificate.

Unlike ``trust_sim_cert_in_ade.py`` (which imports the committed
``certs/server.crt`` and assumes the simulator runs *on the CC*), this script
pulls the certificate the endpoint is REALLY serving. That makes it work even
when the simulator runs on a separate host/IP -- e.g. ADE configured with
``socx.*.cloud.hostname = 10.205.102.81:8080`` while ADE itself runs on the CC
at 10.205.50.10.

It also prints the served cert's Subject Alternative Names and warns if the IP
ADE dials is missing from them (that would cause a hostname-verification failure
AFTER trust is fixed).

Usage:
    python deploy/trust_live_cert_in_ade.py
    python deploy/trust_live_cert_in_ade.py --cloud-host 10.205.102.81 --cloud-port 8080
    python deploy/trust_live_cert_in_ade.py --ade-host 10.205.50.10

Requires: paramiko  (pip install -r deploy/requirements-deploy.txt)
"""
from __future__ import annotations

import argparse
import sys
import time

import paramiko

# --------------------------------------------------------------------------- #
# Defaults (override on the command line)
# --------------------------------------------------------------------------- #
ADE_HOST = "10.205.50.10"      # Cyber Controller running the ADE container
ADE_USER = "root"
ADE_PASS = "radware"

CLOUD_HOST = "10.205.102.81"   # host part of socx.*.cloud.hostname (the sim endpoint)
CLOUD_PORT = 8080

ADE_MATCH = "anomaly-detection-engine"  # substring to find the ADE container
ALIAS = "socx-sim"
STOREPASS = "changeit"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--ade-host", default=ADE_HOST, help="SSH host of the CC/ADE machine")
    p.add_argument("--ade-user", default=ADE_USER)
    p.add_argument("--ade-pass", default=ADE_PASS)
    p.add_argument("--cloud-host", default=CLOUD_HOST, help="Sim endpoint ADE dials (host/IP)")
    p.add_argument("--cloud-port", type=int, default=CLOUD_PORT)
    p.add_argument("--ade-match", default=ADE_MATCH)
    p.add_argument("--no-restart", action="store_true", help="Do not restart ADE afterwards")
    return p.parse_args()


class SSH:
    def __init__(self, host: str, user: str, password: str):
        self.c = paramiko.SSHClient()
        self.c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.c.connect(host, username=user, password=password, timeout=20, banner_timeout=30)

    def run(self, cmd: str, timeout: int = 180, echo: bool = True) -> tuple[int, str]:
        _i, o, e = self.c.exec_command(cmd, timeout=timeout)
        out = o.read().decode(errors="replace")
        err = e.read().decode(errors="replace")
        rc = o.channel.recv_exit_status()
        if echo:
            print(f"$ {cmd}")
            if out.strip():
                print(out.strip())
            if err.strip():
                print(f"[stderr] {err.strip()}")
            print(f"[exit {rc}]\n" + "-" * 70)
        return rc, out

    def out(self, cmd: str) -> str:
        return self.run(cmd, echo=False)[1].strip()

    def close(self) -> None:
        self.c.close()


def main() -> int:
    a = parse_args()
    s = SSH(a.ade_host, a.ade_user, a.ade_pass)
    try:
        # 1. Find the ADE container, its truststore and keytool.
        ade = s.out(f"docker ps --format '{{{{.Names}}}}' | grep -i '{a.ade_match}' | head -1")
        if not ade:
            print(f"ERROR: no running container matching '{a.ade_match}'. Check `docker ps`.")
            return 2
        cacerts = s.out(f"docker exec {ade} sh -c 'find / -name cacerts 2>/dev/null | head -1'")
        if not cacerts:
            print("ERROR: could not locate Java 'cacerts' inside the ADE container.")
            return 2
        java_home = s.out(f"docker exec {ade} sh -c 'echo $JAVA_HOME'")
        keytool = f"{java_home}/bin/keytool" if java_home else "keytool"
        print(f"ADE container : {ade}")
        print(f"truststore    : {cacerts}")
        print(f"keytool       : {keytool}")
        print(f"cloud endpoint: {a.cloud_host}:{a.cloud_port}\n" + "=" * 70)

        # 2. Fetch the certificate the endpoint is ACTUALLY serving (host openssl).
        fetch = (
            f"echo | openssl s_client -connect {a.cloud_host}:{a.cloud_port} "
            f"-servername {a.cloud_host} 2>/dev/null | "
            f"openssl x509 -outform PEM > /tmp/socx-live.crt; "
            f"test -s /tmp/socx-live.crt && echo OK || echo EMPTY"
        )
        status = s.out(fetch)
        if "OK" not in status:
            print(
                f"ERROR: could not retrieve a certificate from {a.cloud_host}:{a.cloud_port}.\n"
                "  - Is the simulator running and reachable from the CC?\n"
                "  - Try from the CC:  openssl s_client -connect "
                f"{a.cloud_host}:{a.cloud_port}"
            )
            return 2

        # 3. Show the cert's SANs and warn if the dialed IP/host is missing.
        san = s.out(
            "openssl x509 -in /tmp/socx-live.crt -noout -ext subjectAltName 2>/dev/null "
            "|| openssl x509 -in /tmp/socx-live.crt -noout -text | grep -A1 'Subject Alternative Name'"
        )
        subject = s.out("openssl x509 -in /tmp/socx-live.crt -noout -subject")
        print(f"Served cert {subject}")
        print(f"Subject Alternative Names:\n{san}\n" + "-" * 70)
        if a.cloud_host not in san:
            print(
                f"WARNING: '{a.cloud_host}' is NOT in the certificate SANs above.\n"
                "  Importing it fixes the PKIX trust error, but Java hostname\n"
                "  verification may then fail. To fully fix this, either:\n"
                f"    (a) regenerate the sim cert with 'IP:{a.cloud_host}' in the SAN\n"
                "        (deploy/install.py uses the target host IP for the SAN), or\n"
                "    (b) point ADE at a hostname/IP that IS in the SAN (e.g. run the\n"
                "        sim on ADE's docker network and use 'socx-sim:8080').\n" + "-" * 70
            )

        # 4. Import into the ADE truststore (replace any stale alias first).
        s.run(f"docker cp /tmp/socx-live.crt {ade}:/tmp/{ALIAS}.crt")
        s.run(
            f"docker exec {ade} {keytool} -delete -alias {ALIAS} "
            f"-keystore {cacerts} -storepass {STOREPASS} 2>/dev/null || true",
            echo=False,
        )
        rc, _ = s.run(
            f"docker exec {ade} {keytool} -importcert -noprompt -alias {ALIAS} "
            f"-file /tmp/{ALIAS}.crt -keystore {cacerts} -storepass {STOREPASS}"
        )
        if rc != 0:
            print("ERROR: keytool import failed.")
            return 2

        # 5. Restart ADE so it reloads the truststore, then tail the relevant logs.
        if a.no_restart:
            print("Skipping ADE restart (--no-restart). Restart ADE for changes to apply.")
            return 0
        s.run(f"docker restart {ade}")
        print("Waiting 75s for ADE to restart and call the cloud...")
        time.sleep(75)
        s.run(
            f"docker logs --since 120s {ade} 2>&1 | grep -E "
            "'Full REST API: https|Received recommendation|recommendations returned|"
            "Cloud connectivity|PKIX|closed prematurely|Processing recommendation DTO|"
            "No subject alternative|success' | tail -40"
        )
        print("\nDone. If PKIX errors are gone and you see recommendations, the fix worked.")
        return 0
    finally:
        s.close()


if __name__ == "__main__":
    sys.exit(main())

