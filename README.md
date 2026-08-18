# SOC-X Recommendation Simulator (cloudSimulator)

[![CI](https://github.com/rdwr-danaaz/cloudSimulator/actions/workflows/ci.yml/badge.svg)](https://github.com/rdwr-danaaz/cloudSimulator/actions/workflows/ci.yml)

A lightweight FastAPI service that simulates the SOC-X cloud
`_getRecommendation` API used by the **anomaly-detection-engine (ADE)**. It
returns deterministic, pinned rule sets for specific networks (and generated
rules otherwise), served over **HTTPS**. It runs on its own Linux host and any
Cyber Controller (ADE) on the network can be pointed at it.

> ### 📘 Which document should I follow to install?
> - **This `README.md` is the canonical source of truth.** To stand the
>   simulator up on its own server, follow
>   [Install on a standalone Linux machine](#install-on-a-standalone-linux-machine-step-by-step).
> - If instead you want the simulator to run **directly on an ADE host** and
>   auto-wire itself into that local ADE, see
>   [Alternative: install directly on an ADE host](#alternative-install-directly-on-an-ade-host).

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

Before configuring, click **Test connection** to run read-only preflight checks
that make **no changes**: SSH login, Docker present, ADE container running, ADE
config + Java truststore found, and that the CC can actually **reach the
simulator** over TLS. Configure itself runs these checks first and **aborts
before touching anything** if one fails, so a CC is never left half-configured;
it also verifies the hostname and cert are in place at the end.

**Tab 2 — Recommendation.** Edit the JSON returned for any request that isn't a
pinned network, with an *active/inactive* badge. `destinationIPs` is always
overwritten with the requesting network, so the destination always matches the
request. All other fields are optional, but blank `fragment`/`action` default to
`none`/`allow` (ADE rejects null values). Use **Preview** to see the exact
response a CC would receive. State is persisted under `data/` (docker volume).

**Tab 3 — Recommendations.** Browse every existing rule set — the pinned
per-network responses and any seeded tags — in a friendly table. **View JSON**
opens a full JSON viewer (with copy), and **Copy to Template** loads a set into
Tab 2 as a starting point (the destination is re-matched per request).

## Install on a standalone Linux machine (step by step)

This is the recommended deployment: the simulator runs on its **own Linux VM /
server**, and one or more Cyber Controllers (ADEs) elsewhere on the network are
pointed at `https://<sim-host>:8080`. The simulator does **not** need to run on
an ADE.

### Prerequisites

**Target Linux machine (where the simulator will run):**

| Requirement | Recommended |
|-------------|-------------|
| OS | Ubuntu 20.04/22.04 LTS or Debian 11/12 (x86-64). The installer uses `apt`. |
| CPU / RAM | 2 vCPU / 2 GB RAM (1 vCPU / 1 GB works for light use) |
| Disk | ~5 GB free (Docker Engine + image + logs) |
| Privileges | An SSH login whose user has **sudo** (Docker is installed with it) |
| Inbound network | TCP **8080** (or your chosen port) reachable from every ADE that will use the simulator |
| Outbound network | Internet access to `get.docker.com`, `download.docker.com`, and `github.com` for the one-time install (or pre-install Docker + copy the repo for an air-gapped host) |
| Static address | A stable IP/hostname the ADEs can reach (it is baked into the TLS cert's SAN) |

**Workstation that runs the installer (your laptop — not the target):**

- Python **3.9+** and `pip`
- Network/SSH access to the target machine
- Install the deploy tooling once:

  ```bash
  pip install -r deploy/requirements-deploy.txt
  ```

> Docker, git, openssl and curl do **not** need to be pre-installed on the
> target — the installer installs them. You only need SSH + a sudo user.

### Option A — Automated remote install (recommended)

From your workstation, run the standalone installer. It SSHes into the target
and does everything end-to-end: waits for cloud-init/apt locks, installs Docker
Engine, clones the repo, generates a TLS cert whose **SAN includes the host IP**,
builds and starts the container, opens the firewall port (if `ufw` is active),
and verifies `/health`.

```bash
python deploy/install_standalone.py \
    --host 10.205.102.81 \
    --user socx \
    --password '***' \
    --port 8080
```

Flags:

- `--host` — target IP/hostname (also used for the cert SAN)
- `--user` / `--password` — SSH login with sudo
- `--port` — host port to expose (default `8080`)
- `--repo` — git URL to clone (defaults to this repository)

On success it prints the live URL. Verify from anywhere:

```bash
curl -k https://10.205.102.81:8080/health
```

Then open the UI at `https://10.205.102.81:8080/ui` (accept the self-signed
cert).

### Option B — Manual install on the box

If you prefer to run the steps yourself (e.g. an air-gapped host), SSH into the
target and run:

```bash
# 1) Docker Engine (skip if already installed)
sudo apt-get update -y
sudo apt-get install -y ca-certificates curl gnupg git openssl
curl -fsSL https://get.docker.com | sudo sh
sudo systemctl enable --now docker

# 2) Get the project
cd "$HOME"
git clone https://github.com/rdwr-danaaz/cloudSimulator.git
cd cloudSimulator

# 3) Generate a TLS cert whose SAN includes THIS host's IP
HOST_IP=10.205.102.81
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout certs/server.key -out certs/server.crt \
  -subj "/CN=socx-sim" \
  -addext "subjectAltName=DNS:socx-sim,DNS:localhost,IP:127.0.0.1,IP:${HOST_IP}"

# 4) Build & start
sudo docker compose up -d --build

# 5) (If ufw is active) open the port, then verify
sudo ufw allow 8080/tcp || true
curl -k https://localhost:8080/health
```

To expose a different host port, edit the left side of the `ports` mapping in
`docker-compose.yml` (e.g. `"9443:8080"`) and open that port instead.

### Point your Cyber Controllers (ADEs) at the simulator

Once the simulator is up, connect each ADE to it. The easiest way is the **web
UI → Tab 1 (Cyber Controller)**: enter the CC host + SSH credentials and click
**Configure** — the simulator sets the ADE's `socx.*.cloud.hostname`, imports
its TLS cert into the ADE Java truststore, and restarts ADE (use **Test
connection** first for read-only preflight checks).

To do the same from the CLI (e.g. to script it), trust the simulator's live cert
in an ADE and point it at the endpoint:

```bash
python deploy/trust_live_cert_in_ade.py \
    --ade-host 10.205.50.10 --ade-pass '***' \
    --cloud-host 10.205.102.81 --cloud-port 8080
```

This auto-detects the ADE container and truststore, fetches the cert the
endpoint is **actually serving**, imports it into the ADE container's `cacerts`,
restarts the ADE, and tails the logs to confirm the cloud call succeeds. Without
it the ADE fails the TLS handshake with `PKIX path building failed`.

> The trust survives `docker restart` but **not** ADE container recreation
> (`docker rm` / `compose up` / upgrades). Re-run the script (or the UI
> Configure) after recreating the ADE container. Importing one cert under a
> unique alias does not disable TLS validation or affect anything else on the CC.

### Day-2 operations

```bash
# On the simulator host, from ~/cloudSimulator:
sudo docker compose ps                 # status
sudo docker compose logs -f socx-sim   # tail logs
git pull && sudo docker compose up -d --build   # update to latest
sudo docker compose down               # stop (data volume is preserved)
```

State (the editable recommendation template + configured-CC registry) persists
in the `socx-sim-data` Docker volume across restarts and rebuilds.

## Alternative: install directly on an ADE host

Use this only if you want the simulator to run **on the ADE machine itself** and
auto-wire into that local ADE container. The installer is plug-and-play: point
it at a host running the anomaly-detection-engine and it does the rest (build,
run on ADE's docker network, configure ADE, import the TLS cert into ADE's Java
truststore, restart ADE, and verify end-to-end).

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
















