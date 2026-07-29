# SOC-X Recommendation Simulator — Docker

A self-contained mock of the SOC-X cloud recommendation API. It answers:

```
POST /api/sdcc/genai/core/analysis/peacetime/_getRecommendation
```

For configured networks (e.g. `100.98.89.0/24`) it returns a **fixed, permanent**
rule set defined in `permanent_responses.py`. Only `timestamp` and
`metadata.interval` are computed at request time:

- `timestamp` – current UTC time
- `interval.start_time` – start of the 3-hour block of the day the request falls in
  (e.g. 10:xx → 09:00, 16:xx → 15:00)
- `interval.end_time` – `start_time + 2:59:59`

The service is exposed **two ways at once**:

- Root:      `http://<host>:<port>/api/sdcc/genai/core/analysis/peacetime/_getRecommendation`
- Prefixed:  `http://<host>:<port>/socx_sim/api/sdcc/genai/core/analysis/peacetime/_getRecommendation`

Default port: **8080**.

---

## Build

```bash
docker build -t socx-sim:latest .
```

## Run

```bash
docker run -d --name socx-sim -p 8080:8080 socx-sim:latest
```

Use a different host port by changing the left side of `-p`, e.g. expose on 9000:

```bash
docker run -d --name socx-sim -p 9000:8080 socx-sim:latest
```

Or run it on a different internal port too (both sides):

```bash
docker run -d --name socx-sim -e PORT=9000 -p 9000:9000 socx-sim:latest
```

### docker compose

```bash
docker compose up -d --build
```

---

## Test it

```bash
curl -s http://localhost:8080/api/sdcc/genai/core/analysis/peacetime/_getRecommendation \
  -H "Content-Type: application/json" \
  -d '{"tag":"test_yehuda","networks":["100.98.89.0/24"]}'
```

Same result via the prefixed path:

```bash
curl -s http://localhost:8080/socx_sim/api/sdcc/genai/core/analysis/peacetime/_getRecommendation \
  -H "Content-Type: application/json" \
  -d '{"tag":"test_yehuda","networks":["100.98.89.0/24"]}'
```

Health check:

```bash
curl http://localhost:8080/health
```

Interactive UI (auto-generation / pinning for non-permanent tags):

```
http://localhost:8080/ui
```

---

## Adding more permanent network responses

Edit `permanent_responses.py` and add another entry to `PERMANENT_NETWORK_RULES`,
keyed by the network CIDR, then rebuild the image:

```python
PERMANENT_NETWORK_RULES = {
    "100.98.89.0/24": [ ... ],
    "10.20.30.0/24":  [ ... ],   # <-- new network
}
```

```bash
docker build -t socx-sim:latest .
docker rm -f socx-sim && docker run -d --name socx-sim -p 8080:8080 socx-sim:latest
```

---

## HTTPS note

The container serves plain **HTTP**. If a client requires `https://`, terminate TLS
in front of it (nginx/Caddy/Traefik) or bind uvicorn with certs. Simplest option is a
reverse proxy that forwards `https://<host>/socx_sim/...` to `http://socx-sim:8080/socx_sim/...`.

