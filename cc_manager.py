"""Configure one or more Cyber Controllers (ADE) to use this simulator.

Tab 1 of the UI drives this module. Given a CC's SSH details and the address
this simulator is reachable at, it:

  1. Points the ADE at the simulator by setting, in ``ade.config.properties``:
        socx.positive.cloud.hostname    = <sim host:port>
        socx.remediation.cloud.hostname = <sim host:port>
     (a timestamped backup is taken first).
  2. Imports the simulator's live TLS certificate into the ADE container's Java
     truststore (fixes 'PKIX path building failed').
  3. Restarts the ADE container so both changes take effect.

Every configured CC is recorded in ``data/configured_ccs.json`` so the UI can
list all controllers currently pointed at this simulator. Because the response
template is global and the destination is derived per request, many CCs can use
the simulator at the same time.

paramiko is imported lazily so the rest of the app (and the test suite) does not
require it just to import this module.
"""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_DATA_DIR = Path(__file__).parent / "data"
_REGISTRY_FILE = _DATA_DIR / "configured_ccs.json"
_LOCK = threading.Lock()

ADE_MATCH = "anomaly-detection-engine"
ALIAS = "socx-sim"
STOREPASS = "changeit"


# --------------------------------------------------------------------------- #
# Registry helpers
# --------------------------------------------------------------------------- #
def _read_registry() -> list[dict[str, Any]]:
    if _REGISTRY_FILE.exists():
        try:
            return json.loads(_REGISTRY_FILE.read_text(encoding="utf-8"))
        except Exception:
            return []
    return []


def _write_registry(items: list[dict[str, Any]]) -> None:
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    _REGISTRY_FILE.write_text(json.dumps(items, indent=2), encoding="utf-8")


def list_ccs() -> list[dict[str, Any]]:
    with _LOCK:
        return _read_registry()


def _upsert_cc(entry: dict[str, Any]) -> None:
    with _LOCK:
        items = _read_registry()
        items = [c for c in items if c.get("cc_host") != entry["cc_host"]]
        items.append(entry)
        _write_registry(items)


def remove_cc(cc_host: str) -> bool:
    with _LOCK:
        items = _read_registry()
        new = [c for c in items if c.get("cc_host") != cc_host]
        _write_registry(new)
        return len(new) != len(items)


# --------------------------------------------------------------------------- #
# SSH configuration
# --------------------------------------------------------------------------- #
class _Result:
    def __init__(self) -> None:
        self.log: list[str] = []
        self.ok = False

    def line(self, msg: str) -> None:
        self.log.append(msg)


def configure_cc(
    cc_host: str,
    ssh_user: str,
    ssh_pass: str,
    sim_hostport: str,
    ssh_port: int = 22,
    restart: bool = True,
) -> dict[str, Any]:
    """Configure a single CC. Returns {ok, log, entry}."""
    import paramiko  # lazy

    res = _Result()

    def emit(msg: str) -> None:
        res.line(msg)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        emit(f"Connecting to {cc_host}:{ssh_port} as {ssh_user} ...")
        client.connect(
            cc_host,
            port=ssh_port,
            username=ssh_user,
            password=ssh_pass,
            timeout=20,
            banner_timeout=30,
        )
    except Exception as exc:
        emit(f"ERROR: SSH connection failed: {exc}")
        return {"ok": False, "log": res.log, "entry": None}

    def run(cmd: str, echo: bool = True) -> tuple[int, str]:
        _i, o, e = client.exec_command(cmd, timeout=180)
        out = o.read().decode(errors="replace")
        err = e.read().decode(errors="replace")
        rc = o.channel.recv_exit_status()
        if echo:
            emit(f"$ {cmd}")
            if out.strip():
                emit(out.strip())
            if err.strip():
                emit(f"[stderr] {err.strip()}")
        return rc, out

    try:
        # 1. Locate ade.config.properties
        props = run(
            "find /var/lib/docker -name ade.config.properties 2>/dev/null | head -1",
            echo=False,
        )[1].strip()
        if not props:
            emit("ERROR: ade.config.properties not found on this host.")
            return {"ok": False, "log": res.log, "entry": None}
        emit(f"Found properties: {props}")

        # 2. Backup + set the two hostname keys
        # One-time PRISTINE backup so Reset can restore the true original config,
        # regardless of how many times configure runs afterwards.
        orig_backup = f"{props}.socxsim-orig"
        run(f"test -f {orig_backup} || cp -p {props} {orig_backup}", echo=False)
        ts = run("date +%Y%m%d_%H%M%S", echo=False)[1].strip()
        run(f"cp -p {props} {props}.bak_{ts}")
        for key in ("socx.positive.cloud.hostname", "socx.remediation.cloud.hostname"):
            line = f"{key} = {sim_hostport}"
            script = (
                f"if grep -qE '^[[:space:]]*#?[[:space:]]*{key}[[:space:]]*=' {props}; then "
                f"sed -i -E 's|^[[:space:]]*#?[[:space:]]*{key}[[:space:]]*=.*|{line}|' {props}; "
                f"else printf '%s\\n' '{line}' >> {props}; fi"
            )
            rc, _ = run(script, echo=False)
            emit(f"  set {key} -> {sim_hostport}  [{'ok' if rc == 0 else 'FAILED'}]")

        # 3. Find ADE container, truststore, keytool
        ade = run(
            f"docker ps --format '{{{{.Names}}}}' | grep -i '{ADE_MATCH}' | head -1",
            echo=False,
        )[1].strip()
        if not ade:
            emit(f"ERROR: no running container matching '{ADE_MATCH}'.")
            return {"ok": False, "log": res.log, "entry": None}
        emit(f"ADE container: {ade}")
        # Prefer $JAVA_HOME (fast) over scanning the whole filesystem for cacerts.
        java_home = run(
            f"docker exec {ade} sh -c 'echo $JAVA_HOME'", echo=False
        )[1].strip()
        cacerts = ""
        if java_home:
            cand = f"{java_home}/lib/security/cacerts"
            found = run(
                f"docker exec {ade} sh -c 'test -f {cand} && echo {cand}'",
                echo=False,
            )[1].strip()
            cacerts = found
        if not cacerts:
            cacerts = run(
                f"docker exec {ade} sh -c 'find /usr /opt -name cacerts 2>/dev/null | head -1'",
                echo=False,
            )[1].strip()
        keytool = f"{java_home}/bin/keytool" if java_home else "keytool"
        if not cacerts:
            emit("ERROR: could not locate Java cacerts inside the ADE container.")
            return {"ok": False, "log": res.log, "entry": None}
        emit(f"truststore: {cacerts}")

        # 4. Fetch the simulator's live cert and import it
        sim_host = sim_hostport.split(":")[0]
        sim_port = sim_hostport.split(":")[1] if ":" in sim_hostport else "8080"
        fetch = (
            f"echo | openssl s_client -connect {sim_host}:{sim_port} "
            f"-servername {sim_host} 2>/dev/null "
            f"| openssl x509 -outform PEM > /tmp/socx-sim.crt; "
            f"test -s /tmp/socx-sim.crt && echo OK || echo EMPTY"
        )
        if "OK" not in run(fetch, echo=False)[1]:
            emit(
                f"ERROR: could not retrieve a certificate from {sim_host}:{sim_port}. "
                "Is the simulator running and reachable from this CC?"
            )
            return {"ok": False, "log": res.log, "entry": None}
        emit(f"Fetched simulator cert from {sim_host}:{sim_port}")
        run(f"docker cp /tmp/socx-sim.crt {ade}:/tmp/{ALIAS}.crt", echo=False)
        run(
            f"docker exec {ade} {keytool} -delete -alias {ALIAS} "
            f"-keystore {cacerts} -storepass {STOREPASS} 2>/dev/null || true",
            echo=False,
        )
        rc, _ = run(
            f"docker exec {ade} {keytool} -importcert -noprompt -alias {ALIAS} "
            f"-file /tmp/{ALIAS}.crt -keystore {cacerts} -storepass {STOREPASS}"
        )
        if rc != 0:
            emit("ERROR: keytool import failed.")
            return {"ok": False, "log": res.log, "entry": None}
        emit("Certificate imported into ADE truststore.")

        # 5. Restart ADE
        if restart:
            run(f"docker restart {ade}")
            emit("ADE restarted. It will pick up the new cloud hostname and cert.")
        else:
            emit("Skipped ADE restart (restart the ADE container to apply).")

        res.ok = True
        entry = {
            "cc_host": cc_host,
            "ssh_user": ssh_user,
            "ssh_port": ssh_port,
            "sim_hostport": sim_hostport,
            "ade_container": ade,
            "props_file": props,
            "orig_backup": orig_backup,
            "configured_at": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "status": "configured",
        }
        _upsert_cc(entry)
        return {"ok": True, "log": res.log, "entry": entry}
    except Exception as exc:
        emit(f"ERROR: configuration aborted: {type(exc).__name__}: {exc}")
        return {"ok": False, "log": res.log, "entry": None}
    finally:
        client.close()


def reset_cc(
    cc_host: str,
    ssh_user: str,
    ssh_pass: str,
    ssh_port: int = 22,
    restart: bool = True,
) -> dict[str, Any]:
    """Restore a CC to its original state and forget it.

    Steps:
      1. Restore ade.config.properties from the pristine backup (or clear the
         two socx.*.cloud.hostname keys if no backup exists).
      2. Remove the imported simulator cert alias from the ADE truststore.
      3. Restart the ADE container.
      4. Remove the CC from the simulator's registry.

    Returns {ok, log}.
    """
    import paramiko  # lazy

    res = _Result()

    def emit(msg: str) -> None:
        res.line(msg)

    # Look up what we recorded when configuring (props path, orig backup).
    known = next((c for c in list_ccs() if c.get("cc_host") == cc_host), {})

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        emit(f"Connecting to {cc_host}:{ssh_port} as {ssh_user} ...")
        client.connect(
            cc_host,
            port=ssh_port,
            username=ssh_user,
            password=ssh_pass,
            timeout=20,
            banner_timeout=30,
        )
    except Exception as exc:
        emit(f"ERROR: SSH connection failed: {exc}")
        return {"ok": False, "log": res.log}

    def run(cmd: str, echo: bool = True) -> tuple[int, str]:
        _i, o, e = client.exec_command(cmd, timeout=180)
        out = o.read().decode(errors="replace")
        err = e.read().decode(errors="replace")
        rc = o.channel.recv_exit_status()
        if echo:
            emit(f"$ {cmd}")
            if out.strip():
                emit(out.strip())
            if err.strip():
                emit(f"[stderr] {err.strip()}")
        return rc, out

    try:
        # 1. Locate properties (prefer the path recorded at configure time)
        props = known.get("props_file") or run(
            "find /var/lib/docker -name ade.config.properties 2>/dev/null | head -1",
            echo=False,
        )[1].strip()
        if not props:
            emit("WARNING: ade.config.properties not found; skipping config revert.")
        else:
            orig_backup = known.get("orig_backup") or f"{props}.socxsim-orig"
            sim = (known.get("sim_hostport") or "").strip()
            if run(f"test -f {orig_backup} && echo yes || echo no", echo=False)[1].strip() == "yes":
                run(f"cp -p {orig_backup} {props}")
                emit(f"Restored ADE config from backup {orig_backup}")
            # Always ensure the simulator hostname is gone. The backup may itself
            # already point at the simulator (e.g. the CC was configured before
            # the UI captured a backup), so restoring alone isn't enough.
            keys = ("socx.positive.cloud.hostname", "socx.remediation.cloud.hostname")
            for key in keys:
                key_pat = key.replace(".", r"\.")
                if sim:
                    sim_pat = sim.replace(".", r"\.")
                    # Delete only lines for this key that point at the simulator.
                    run(
                        f"sed -i -E '\\|^[[:space:]]*{key_pat}[[:space:]]*=[[:space:]]*"
                        f"{sim_pat}[[:space:]]*$|d' {props}",
                        echo=False,
                    )
                else:
                    # Unknown sim address: remove the key entirely (we manage it).
                    run(
                        f"sed -i -E '/^[[:space:]]*{key_pat}[[:space:]]*=/d' {props}",
                        echo=False,
                    )
            remaining = run(
                f"grep -nE 'socx\\.(positive|remediation)\\.cloud\\.hostname' {props} "
                f"|| echo '(no simulator hostname remaining)'",
                echo=False,
            )[1].strip()
            emit(f"Simulator cloud hostname removed from ADE config. Current: {remaining}")

        # 2. Remove the imported simulator cert from the ADE truststore
        ade = known.get("ade_container") or run(
            f"docker ps --format '{{{{.Names}}}}' | grep -i '{ADE_MATCH}' | head -1",
            echo=False,
        )[1].strip()
        if ade:
            java_home = run(
                f"docker exec {ade} sh -c 'echo $JAVA_HOME'", echo=False
            )[1].strip()
            cacerts = ""
            if java_home:
                cand = f"{java_home}/lib/security/cacerts"
                cacerts = run(
                    f"docker exec {ade} sh -c 'test -f {cand} && echo {cand}'",
                    echo=False,
                )[1].strip()
            if not cacerts:
                cacerts = run(
                    f"docker exec {ade} sh -c 'find /usr /opt -name cacerts 2>/dev/null | head -1'",
                    echo=False,
                )[1].strip()
            keytool = f"{java_home}/bin/keytool" if java_home else "keytool"
            if cacerts:
                rc, _ = run(
                    f"docker exec {ade} {keytool} -delete -alias {ALIAS} "
                    f"-keystore {cacerts} -storepass {STOREPASS}"
                )
                emit(
                    "Removed simulator cert from ADE truststore."
                    if rc == 0
                    else "Simulator cert alias not present (already clean)."
                )
            # 3. Restart ADE
            if restart:
                run(f"docker restart {ade}")
                emit("ADE restarted with its original configuration.")
        else:
            emit("WARNING: ADE container not found; skipped cert removal/restart.")

        # 4. Forget the CC
        remove_cc(cc_host)
        emit(f"Removed {cc_host} from the simulator registry.")
        res.ok = True
        return {"ok": True, "log": res.log}
    except Exception as exc:
        emit(f"ERROR: reset aborted: {type(exc).__name__}: {exc}")
        return {"ok": False, "log": res.log}
    finally:
        client.close()








