#!/usr/bin/env python3
"""Plug-and-play installer for the SOC-X Recommendation Simulator.

One command deploys the simulator to any target machine and wires it into the
Radware ADE (anomaly-detection-engine) automatically:

  1. Connects to the target over SSH.
  2. Auto-detects the ADE container, its docker network, its Java truststore
     and its ade.config.properties file (all overridable via config/CLI).
  3. Uploads the app, generates a stable self-signed TLS cert (SAN = container
     name + host), builds the image and runs the container on ADE's network.
  4. Configures ADE:
        socx.positive.cloud.hostname   = <container>:<internal_port>
        socx.remediation.cloud.hostname = <container>:<internal_port>
     (timestamped backup is taken first).
  5. Imports the simulator cert into ADE's Java truststore so TLS is trusted.
  6. Restarts the ADE container so the new config takes effect.
  7. Verifies health + a sample recommendation from inside the ADE container.

Usage:
    python install.py                     # uses deploy/install_config.json
    python install.py --config my.json    # custom config
    python install.py --ssh-host 1.2.3.4 --ssh-password secret
    python install.py --uninstall         # remove the simulator + revert config
    python install.py --verify-only       # just run the end-to-end checks

Requires: paramiko  (pip install paramiko)
Nothing is required on the target except Docker and a running ADE container.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Optional

import paramiko

LOCAL_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CONFIG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "install_config.json")

# Application files uploaded to the target (build context).
APP_FILES = [
    "cloud_mock_server.py",
    "permanent_responses.py",
    "main.py",
    "requirements.txt",
    "Dockerfile",
    "docker-compose.yml",
    ".dockerignore",
]

PROP_KEYS = ("socx.positive.cloud.hostname", "socx.remediation.cloud.hostname")
CERT_ALIAS = "socx-sim"


# --------------------------------------------------------------------------- #
# Small SSH helper
# --------------------------------------------------------------------------- #
class Remote:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        connect_kwargs = dict(
            hostname=cfg["ssh_host"],
            port=int(cfg.get("ssh_port", 22)),
            username=cfg["ssh_user"],
            timeout=20,
            banner_timeout=30,
        )
        if cfg.get("ssh_key_file"):
            connect_kwargs["key_filename"] = os.path.expanduser(cfg["ssh_key_file"])
        else:
            connect_kwargs["password"] = cfg.get("ssh_password")
        self.client.connect(**connect_kwargs)

    def run(self, cmd: str, echo: bool = True, timeout: int = 900) -> tuple[int, str]:
        """Run a command, streaming output. Returns (exit_code, combined_output)."""
        if echo:
            print(f"\n$ {cmd}")
        chan = self.client.get_transport().open_session()
        chan.settimeout(timeout)
        chan.get_pty()
        chan.exec_command(cmd)
        buf = []
        while True:
            if chan.recv_ready():
                data = chan.recv(4096).decode(errors="replace")
                buf.append(data)
                if echo:
                    sys.stdout.write(data)
                    sys.stdout.flush()
            if chan.exit_status_ready() and not chan.recv_ready():
                break
            time.sleep(0.03)
        while chan.recv_ready():
            data = chan.recv(4096).decode(errors="replace")
            buf.append(data)
            if echo:
                sys.stdout.write(data)
        rc = chan.recv_exit_status()
        if echo:
            print(f"[exit {rc}]")
        return rc, "".join(buf)

    def out(self, cmd: str) -> str:
        """Run quietly and return stripped stdout."""
        _rc, txt = self.run(cmd, echo=False)
        return txt.strip()

    def put_dir(self, files: list[str], remote_dir: str) -> None:
        sftp = self.client.open_sftp()
        for rel in files:
            local = os.path.join(LOCAL_ROOT, rel)
            if os.path.exists(local):
                print(f"  upload {rel}")
                sftp.put(local, f"{remote_dir}/{rel}")
        sftp.close()

    def close(self) -> None:
        self.client.close()


# --------------------------------------------------------------------------- #
# Config loading & auto-detection
# --------------------------------------------------------------------------- #
def load_config(path: str, overrides: dict) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        cfg = json.load(fh)
    cfg.pop("_comment", None)
    for k, v in overrides.items():
        if v is not None:
            cfg[k] = v
    # Derived defaults
    if not cfg.get("socx_hostname"):
        cfg["socx_hostname"] = f"{cfg['container']}:{cfg['internal_port']}"
    return cfg


def detect_ade(r: Remote, cfg: dict) -> dict:
    """Fill in ade_container / ade_network / ade_properties_path / cacerts / keytool."""
    ade = cfg.get("ade_container") or ""
    if not ade:
        match = cfg.get("ade_container_match", "anomaly-detection-engine")
        ade = r.out(f"docker ps --format '{{{{.Names}}}}' | grep -i '{match}' | head -1")
    if not ade:
        raise SystemExit(
            "ERROR: could not find the ADE container. Set 'ade_container' in the "
            "config or check that ADE is running (docker ps)."
        )
    cfg["ade_container"] = ade
    print(f"  ADE container    : {ade}")

    net = cfg.get("ade_network") or ""
    if not net:
        net = r.out(
            f"docker inspect -f '{{{{range $k,$v := .NetworkSettings.Networks}}}}{{{{$k}}}} {{{{end}}}}' {ade}"
        ).split()
        net = net[0] if net else ""
    if not net:
        raise SystemExit("ERROR: could not determine ADE's docker network.")
    cfg["ade_network"] = net
    print(f"  ADE network      : {net}")

    props = cfg.get("ade_properties_path") or ""
    default_props = (
        "/var/lib/docker/docker-root/volumes/"
        "config_anomaly-detection-engine-etc/_data/ade.config.properties"
    )
    if not props:
        if r.out(f"test -f {default_props} && echo yes") == "yes":
            props = default_props
        else:
            props = r.out("find /var/lib/docker -name ade.config.properties 2>/dev/null | head -1")
    if not props:
        raise SystemExit(
            "ERROR: could not find ade.config.properties. Set 'ade_properties_path'."
        )
    cfg["ade_properties_path"] = props
    print(f"  ADE properties   : {props}")

    cacerts = r.out(f"docker exec {ade} sh -c 'find / -name cacerts 2>/dev/null | head -1'")
    if not cacerts:
        raise SystemExit("ERROR: could not find the Java 'cacerts' truststore in ADE.")
    cfg["_cacerts"] = cacerts
    java_home = r.out(f"docker exec {ade} sh -c 'echo $JAVA_HOME'")
    keytool = f"{java_home}/bin/keytool" if java_home else "keytool"
    cfg["_keytool"] = keytool
    print(f"  ADE truststore   : {cacerts}")
    return cfg


# --------------------------------------------------------------------------- #
# Install steps
# --------------------------------------------------------------------------- #
def ensure_cert(r: Remote, cfg: dict) -> None:
    """Generate a stable self-signed cert on the target if missing (or forced)."""
    rd = cfg["remote_dir"]
    r.run(f"mkdir -p {rd}/certs {rd}/recommendations")
    exists = r.out(f"test -f {rd}/certs/server.crt && test -f {rd}/certs/server.key && echo yes")
    if exists == "yes" and not cfg.get("regenerate_cert"):
        print("  cert: reusing existing certs/server.{crt,key}")
        return
    san = f"DNS:{cfg['container']},DNS:localhost,IP:127.0.0.1,IP:{cfg['ssh_host']}"
    print("  cert: generating self-signed certificate")
    rc, _ = r.run(
        f"openssl req -x509 -nodes -newkey rsa:2048 -days 3650 "
        f"-keyout {rd}/certs/server.key -out {rd}/certs/server.crt "
        f"-subj '/CN={cfg['container']}' -addext 'subjectAltName={san}'"
    )
    if rc != 0:
        raise SystemExit("ERROR: openssl cert generation failed on the target.")


def deploy_container(r: Remote, cfg: dict) -> None:
    rd, image, container = cfg["remote_dir"], cfg["image"], cfg["container"]
    print("\n== Uploading application files ==")
    r.run(f"mkdir -p {rd}/recommendations")
    r.put_dir(APP_FILES, rd)
    r.run(f"[ -f {LOCAL_ROOT}/recommendations/.keep ] || true", echo=False)
    # ensure recommendations/.keep exists remotely
    r.run(f"touch {rd}/recommendations/.keep", echo=False)

    ensure_cert(r, cfg)

    print("\n== Building image ==")
    rc, _ = r.run(f"cd {rd} && docker build -t {image} .")
    if rc != 0:
        raise SystemExit("ERROR: docker build failed.")

    print("\n== (Re)starting container ==")
    r.run(f"docker rm -f {container} 2>/dev/null || true")
    rc, _ = r.run(
        f"docker run -d --name {container} --restart unless-stopped "
        f"--network {cfg['ade_network']} -p {cfg['host_port']}:{cfg['internal_port']} {image}"
    )
    if rc != 0:
        raise SystemExit("ERROR: docker run failed.")
    time.sleep(4)
    r.run(f"docker ps --filter name={container}")


def configure_ade_properties(r: Remote, cfg: dict) -> None:
    props = cfg["ade_properties_path"]
    value = cfg["socx_hostname"]
    print("\n== Configuring ADE properties ==")
    ts = r.out("date +%Y%m%d_%H%M%S")
    r.run(f"cp -p {props} {props}.bak_{ts}")
    print(f"  backup: {props}.bak_{ts}")
    for key in PROP_KEYS:
        line = f"{key} = {value}"
        script = (
            f"if grep -qE '^[[:space:]]*#?[[:space:]]*{key}[[:space:]]*=' {props}; then "
            f"sed -i -E 's|^[[:space:]]*#?[[:space:]]*{key}[[:space:]]*=.*|{line}|' {props}; "
            f"else printf '%s\\n' '{line}' >> {props}; fi"
        )
        r.run(script, echo=False)
        print(f"  set {key} = {value}")


def trust_cert_in_ade(r: Remote, cfg: dict) -> None:
    ade, rd = cfg["ade_container"], cfg["remote_dir"]
    cacerts, keytool = cfg["_cacerts"], cfg["_keytool"]
    passwd = cfg.get("truststore_password", "changeit")
    print("\n== Importing cert into ADE truststore ==")
    r.run(f"docker cp {rd}/certs/server.crt {ade}:/tmp/{CERT_ALIAS}.crt")
    r.run(
        f"docker exec {ade} {keytool} -delete -alias {CERT_ALIAS} "
        f"-keystore {cacerts} -storepass {passwd} 2>/dev/null || true",
        echo=False,
    )
    rc, _ = r.run(
        f"docker exec {ade} {keytool} -importcert -noprompt -alias {CERT_ALIAS} "
        f"-file /tmp/{CERT_ALIAS}.crt -keystore {cacerts} -storepass {passwd}"
    )
    if rc != 0:
        raise SystemExit("ERROR: keytool import failed.")


def restart_ade(r: Remote, cfg: dict) -> None:
    if not cfg.get("restart_ade", True):
        print("\n== Skipping ADE restart (restart_ade=false) ==")
        return
    print("\n== Restarting ADE (this can take ~60-90s) ==")
    r.run(f"docker restart {cfg['ade_container']}")


def verify(r: Remote, cfg: dict) -> bool:
    ade, container, port = cfg["ade_container"], cfg["container"], cfg["internal_port"]
    url = f"https://{container}:{port}"
    print("\n== Verifying from inside ADE ==")
    health = r.out(
        f"docker exec {ade} sh -c \"curl -sk -o /dev/null -w '%{{http_code}}' "
        f"{url}/health --max-time 8 || echo 000\""
    )
    print(f"  {url}/health -> HTTP {health}")
    rec = r.out(
        f"docker exec {ade} sh -c \"curl -sk {url}/api/sdcc/genai/core/analysis/"
        f"peacetime/_getRecommendation -H 'Content-Type: application/json' "
        f"-d '{{\\\"tag\\\":\\\"install_check\\\",\\\"networks\\\":[\\\"100.98.89.0/24\\\"]}}' "
        f"--max-time 8 | head -c 80\""
    )
    ok = health == "200" and "account_id" in rec
    print(f"  recommendation sample: {rec[:60]}...")
    print("  RESULT:", "OK" if ok else "FAILED")
    return ok


def uninstall(r: Remote, cfg: dict) -> None:
    print("\n== Uninstalling simulator ==")
    r.run(f"docker rm -f {cfg['container']} 2>/dev/null || true")
    r.run(f"docker rmi {cfg['image']} 2>/dev/null || true")
    # Best-effort: detect ADE to revert config + remove cert alias
    try:
        detect_ade(r, cfg)
    except SystemExit:
        print("  (ADE not detected; skipping config revert)")
        return
    props = cfg["ade_properties_path"]
    print("  reverting ADE properties (commenting out socx.*.cloud.hostname)")
    for key in PROP_KEYS:
        r.run(
            f"sed -i -E 's|^([[:space:]]*{key}[[:space:]]*=.*)|# \\1|' {props}",
            echo=False,
        )
    r.run(
        f"docker exec {cfg['ade_container']} {cfg['_keytool']} -delete -alias {CERT_ALIAS} "
        f"-keystore {cfg['_cacerts']} -storepass {cfg.get('truststore_password','changeit')} "
        f"2>/dev/null || true",
        echo=False,
    )
    restart_ade(r, cfg)
    print("  Uninstall complete.")


# --------------------------------------------------------------------------- #
# Entrypoint
# --------------------------------------------------------------------------- #
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="SOC-X simulator plug-and-play installer")
    p.add_argument("--config", default=DEFAULT_CONFIG, help="Path to install_config.json")
    p.add_argument("--ssh-host", dest="ssh_host")
    p.add_argument("--ssh-user", dest="ssh_user")
    p.add_argument("--ssh-password", dest="ssh_password")
    p.add_argument("--ssh-key-file", dest="ssh_key_file")
    p.add_argument("--container", dest="container")
    p.add_argument("--host-port", dest="host_port", type=int)
    p.add_argument("--ade-container", dest="ade_container")
    p.add_argument("--ade-network", dest="ade_network")
    p.add_argument("--socx-hostname", dest="socx_hostname")
    p.add_argument("--no-restart-ade", dest="restart_ade", action="store_false", default=None)
    p.add_argument("--regenerate-cert", dest="regenerate_cert", action="store_true", default=None)
    p.add_argument("--uninstall", action="store_true", help="Remove sim and revert ADE config")
    p.add_argument("--verify-only", action="store_true", help="Only run verification checks")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    overrides = {
        k: getattr(args, k)
        for k in (
            "ssh_host", "ssh_user", "ssh_password", "ssh_key_file", "container",
            "host_port", "ade_container", "ade_network", "socx_hostname",
            "restart_ade", "regenerate_cert",
        )
    }
    cfg = load_config(args.config, overrides)

    print("=" * 70)
    print("SOC-X Simulator installer")
    print(f"  target host      : {cfg['ssh_user']}@{cfg['ssh_host']}:{cfg.get('ssh_port',22)}")
    print(f"  container        : {cfg['container']}  (host port {cfg['host_port']})")
    print(f"  ADE hostname val : {cfg['socx_hostname']}")
    print("=" * 70)

    r = Remote(cfg)
    try:
        print("\n== Detecting ADE environment ==")
        detect_ade(r, cfg)

        if args.verify_only:
            return 0 if verify(r, cfg) else 2

        if args.uninstall:
            uninstall(r, cfg)
            return 0

        deploy_container(r, cfg)
        configure_ade_properties(r, cfg)
        trust_cert_in_ade(r, cfg)
        restart_ade(r, cfg)

        # Give ADE a moment before verifying
        if cfg.get("restart_ade", True):
            print("\nWaiting 20s for ADE to come back up...")
            time.sleep(20)
        ok = verify(r, cfg)

        print("\n" + "=" * 70)
        print("INSTALLATION COMPLETE" if ok else "INSTALLATION FINISHED WITH WARNINGS")
        print(f"  Simulator (host):   https://{cfg['ssh_host']}:{cfg['host_port']}/health")
        print(f"  ADE reaches it at:  https://{cfg['socx_hostname']}/  (docker network '{cfg['ade_network']}')")
        print("=" * 70)
        return 0 if ok else 2
    finally:
        r.close()


if __name__ == "__main__":
    sys.exit(main())


