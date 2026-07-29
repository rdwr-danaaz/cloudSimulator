# SOC-X Recommendation Simulator (cloudSimulator)

A lightweight FastAPI service that simulates the SOC-X cloud
`_getRecommendation` API used by the **anomaly-detection-engine (ADE)**. It
returns deterministic, pinned rule sets for specific networks (and generated
rules otherwise), served over **HTTPS**, and ships with a one-command installer
that wires it into ADE automatically.

## Features

- FastAPI mock of `.../analysis/peacetime/_getRecommendation`
- Served at both `/` and `/socx_sim/` on the same port
- HTTPS with a self-signed cert (SANs for the docker service name + host)
- Pinned, per-network responses in `permanent_responses.py`
- Dynamic `timestamp` and `metadata.interval` on every response
- **Plug-and-play installer** (`deploy/install.py`) that:
  - auto-detects the ADE container, its docker network, truststore and
    `ade.config.properties`
  - builds + runs the simulator on ADE's network
  - configures ADE's `socx.*.cloud.hostname` (with backup)
  - imports the cert into ADE's Java truststore
  - restarts ADE and verifies end-to-end

## Repository layout

| Path | Purpose |
|------|---------|
| `main.py` | ASGI entrypoint; mounts the mock app at `/` and `/socx_sim/` |
| `cloud_mock_server.py` | FastAPI app implementing `_getRecommendation` |
| `permanent_responses.py` | Pinned per-network rule responses |
| `Dockerfile` / `docker-compose.yml` | Container build & run |
| `certs/server.crt` | Committed self-signed cert (key is generated/kept locally) |
| `deploy/install.py` | One-command installer + ADE integration |
| `deploy/install_config.example.json` | Config template (copy to `install_config.json`) |
| `deploy/generate_install_guide.py` | Generates `INSTALL_GUIDE.docx` |

## Quick start (local, Docker)

```bash
docker compose up --build
# HTTPS on https://localhost:8080/health  (self-signed cert)
```

Sample request:

```bash
curl -k -X POST https://localhost:8080/api/sdcc/genai/core/analysis/peacetime/_getRecommendation \
  -H "Content-Type: application/json" \
  -d '{"tag":"test","networks":["100.98.89.0/24"]}'
```

## Deploy to a machine running ADE

```bash
pip install -r deploy/requirements-deploy.txt
cp deploy/install_config.example.json deploy/install_config.json
# edit deploy/install_config.json  -> set ssh_host, ssh_user, ssh_password/ssh_key_file
python deploy/install.py
```

Useful modes:

```bash
python deploy/install.py --verify-only     # re-run verification checks
python deploy/install.py --no-restart-ade  # skip ADE restart
python deploy/install.py --uninstall       # remove container + revert ADE config
```

## Adding a new pinned network

Edit `permanent_responses.py`, add an entry keyed by the subnet (e.g.
`100.98.84.0/24`) following the existing structure, then redeploy. `timestamp`
and `metadata.interval` are filled in automatically at request time.

## Security notes

- `deploy/install_config.json` (real SSH credentials) is **gitignored** — use the
  provided `*.example.json` template.
- `certs/server.key` (private key) is **gitignored**. Fresh clones generate a
  self-signed cert at build time; real deployments generate a per-target cert via
  `deploy/install.py`.

## Installation guide

A full step-by-step Word guide is generated at `INSTALL_GUIDE.docx`:

```bash
python deploy/generate_install_guide.py
```

