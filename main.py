"""ASGI entrypoint for the SOC-X simulator container.

Serves the cloud mock server in two ways at the same time:

  * At the root path, e.g.
        http://<host>:<port>/api/sdcc/genai/core/analysis/peacetime/_getRecommendation
  * Under the /socx_sim prefix, e.g.
        http://<host>:<port>/socx_sim/api/sdcc/genai/core/analysis/peacetime/_getRecommendation

Run with:
    uvicorn main:root_app --host 0.0.0.0 --port 8080
"""
from __future__ import annotations

from fastapi import FastAPI

from cloud_mock_server import app as socx_app

root_app = FastAPI(title="SOC-X Simulator (container entrypoint)")

# Mount the prefixed path first so it is matched before the catch-all root mount.
root_app.mount("/socx_sim", socx_app)
root_app.mount("/", socx_app)

