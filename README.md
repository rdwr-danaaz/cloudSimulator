# SOC-X Recommendation Simulator (cloudSimulator)

[![CI](https://github.com/rdwr-danaaz/cloudSimulator/actions/workflows/ci.yml/badge.svg)](https://github.com/rdwr-danaaz/cloudSimulator/actions/workflows/ci.yml)

A lightweight FastAPI service that simulates the SOC-X cloud
`_getRecommendation` API used by the **anomaly-detection-engine (ADE)**. It
returns deterministic, pinned rule sets for specific networks (and generated
rules otherwise), served over **HTTPS**, and ships with a one-command installer
that wires it into ADE automatically.

> ### 📘 Which document should I follow to install?
> - **This `README.md` is the canonical source of truth** — use it if you're
>   working with the code or the repo. Start at
>   [Deploy to a new machine running ADE](#deploy-to-a-new-machine-running-ade-step-by-step).
> - **`INSTALL_GUIDE.docx`** is a polished, shareable Word version of the same
>   steps, meant for operators/customers who want an offline document to follow
>   or print. It is **generated from this repo** (see
>   [Installation guide](#installation-guide)), so it always mirrors these steps.
>
> Both describe the same installation; pick the format that suits you.

## Features

- FastAPI mock of `.../analysis/peacetime/_getRecommendation`
- Served at both `/` and `/socx_sim/` on the same port
- HTTPS with a self-signed cert (SANs for the docker service name + host)
- Pinned, per-network responses in `permanent_responses.py`
- Dynamic `timestamp` and `metadata.interval` on every response
- **Web UI at `/ui`** with two tabs:
  - **Cyber Controller Setup** — point a CC's ADE at this simulator over SSH
    (sets `socx.*.cloud.hostname`, imports the TLS cert, restarts ADE) and lists
    every connected CC. Multiple CCs can use one simulator simultaneously.
  - **Recommendation Template** — edit the JSON returned for non-pinned
    requests. The **destination network always matches the incoming request**;
    every other field (TTL, protocol, ports, geo, ASN…) is optional. Includes a
    live preview.
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
| `cloud_mock_server.py` | FastAPI app implementing `_getRecommendation` + UI/API |
| `response_template.py` | Global, editable recommendation template (dst = request net) |
| `cc_manager.py` | Configures Cyber Controllers over SSH + keeps a CC registry |
| `static/ui.html` | Two-tab web UI served at `/ui` |
| `permanent_responses.py` | Pinned per-network rule responses |
| `Dockerfile` / `docker-compose.yml` | Container build & run |
| `certs/server.crt` | Committed self-signed cert (key is generated/kept locally) |
| `deploy/install.py` | One-command installer + ADE integration |
| `deploy/install_standalone.py` | Installs the simulator on its own host (no ADE on it) |
| `deploy/trust_live_cert_in_ade.py` | Trusts a **remote** simulator's live cert in an ADE truststore |
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

## Web UI (`/ui`)

Open `https://<sim-host>:8080/ui` in a browser (accept the self-signed cert). The
UI has a **vertical tab** sidebar and a status header showing the simulator's
online state, version, and auto-detected endpoint (with a copy button).

**Tab 1 — Cyber Controller.** Enter just the CC host + SSH credentials — the
**simulator address is auto-detected** (from the address you're browsing on), so
you don't type it (an override lives under *Advanced*). On submit the simulator
SSHes into the CC, sets `socx.positive.cloud.hostname` /
`socx.remediation.cloud.hostname`, imports the simulator's TLS cert into the ADE
Java truststore, and restarts ADE. Every configured CC is listed; because the
response is built per-request, many CCs can share one simulator at the same time.
Each row has a **Reset** button that restores that CC to its original state
(reverts the ADE config from a pristine backup, removes the imported certificate,
restarts ADE, forgets the CC) and a **Remove** that only drops it from the list.

**Tab 2 — Recommendation.** Edit the JSON returned for any request that isn't a
pinned network, with an *active/inactive* badge. `destinationIPs` is always
overwritten with the requesting network, so the destination always matches the
request. All other fields (TTL, protocol, ports, packet size, geo, ASN, fragment,
action) are optional. Use **Preview** to see the exact response a CC would
receive. State is persisted under `data/` (mounted as a docker volume).

## Deploy to a new machine running ADE (step by step)

The installer is plug-and-play: point it at a host running the
anomaly-detection-engine and it does the rest (build, run on ADE's docker
network, configure ADE, import the TLS cert into ADE's Java truststore, restart
ADE, and verify end-to-end).

1. **Install the deploy tooling** (on your workstation, not the target):

   ```bash
   pip install -r deploy/requirements-deploy.txt
   ```

2. **Create your target config** from the committed template:

   ```bash
   cp deploy/install_config.example.json deploy/install_config.json
   ```

3. **Edit `deploy/install_config.json`** — set at least:
   - `ssh_host` — the ADE machine's IP/hostname
   - `ssh_user` and `ssh_password` (or `ssh_key_file`)
   - leave auto-detected fields blank to let the installer discover them

   > This file is **gitignored** because it holds credentials — never commit it.

4. **Run the installer:**

   ```bash
   python deploy/install.py
   ```

Useful modes:

```bash
python deploy/install.py --verify-only     # re-run verification checks
python deploy/install.py --no-restart-ade  # skip ADE restart
python deploy/install.py --uninstall       # remove container + revert ADE config
python deploy/install.py --config other.json   # target a different machine
```

## Standalone deployment (simulator on its own host)

Sometimes the simulator runs on a **separate VM** and one or more ADEs point at
it across the network (e.g. simulator on `10.205.102.81`, a CC/ADE on
`10.205.50.10`). Two steps are involved:

1. **Install the simulator on its own host** (installs Docker, clones the repo,
   generates a cert whose SAN includes the host IP, and runs the container):

   ```bash
   python deploy/install_standalone.py --host 10.205.102.81 --user socx --password '***' --port 8080
   ```

   The simulator is then live at
   `https://<host>:8080/api/sdcc/genai/core/analysis/peacetime/_getRecommendation`.

2. **Point each ADE at it and trust its certificate.** Set the ADE's
   `socx.*.cloud.hostname` to `<sim-host>:8080`, then import the simulator's
   self-signed cert into that ADE's Java truststore (otherwise the ADE fails the
   TLS handshake with `PKIX path building failed`):

   ```bash
   python deploy/trust_live_cert_in_ade.py \
       --ade-host 10.205.50.10 --ade-pass '***' \
       --cloud-host 10.205.102.81 --cloud-port 8080
   ```

   This auto-detects the ADE container and truststore, fetches the cert the
   endpoint is **actually serving** (from the ADE host), imports it into the ADE
   container's `cacerts`, restarts the ADE, and tails the logs to confirm the
   cloud call succeeds. It also prints the cert's SANs and warns if the dialed
   IP is missing from them.

   > The trust survives `docker restart` but **not** ADE container recreation
   > (`docker rm` / `compose up` / upgrades). Re-run the script after recreating
   > the ADE container. Importing one cert under a unique alias does not disable
   > TLS validation or affect anything else on the CC.

## Testing

The repo ships a self-contained test suite that does **not** depend on any
machine-specific data in `recommendations/`, so it runs on a fresh clone:

```bash
pip install -r requirements.txt -r requirements-dev.txt
pytest tests/test_ci.py -q
```

## Continuous integration

Every push / PR to `main` runs [`.github/workflows/ci.yml`](.github/workflows/ci.yml),
which has two jobs:

- **test** — installs deps and runs `pytest tests/test_ci.py`
- **docker-build** — builds the image and smoke-tests `GET /health` over HTTPS
  inside the container

The build generates a self-signed cert automatically when `certs/server.key`
is absent (as on a fresh checkout), so CI works without any secrets.

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

## License

Released under the [MIT License](LICENSE).














