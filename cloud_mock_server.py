from __future__ import annotations
import hashlib, json, os, socket
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Iterator
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, field_validator

from permanent_responses import permanent_rules_for, PERMANENT_NETWORK_RULES
import response_template
import cc_manager
import netvalidate
import netgen

# Largest scale-test set that may be materialized in memory and served through
# _getRecommendation. Larger sets should use the streaming download endpoint.
SCALE_MAX_SERVE = int(os.environ.get("SCALE_MAX_SERVE", "50000"))
# Hard ceiling for a single streaming download (protects the box from a typo).
SCALE_MAX_DOWNLOAD = int(os.environ.get("SCALE_MAX_DOWNLOAD", "2000000"))

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(
    title="SOC-X Cloud Recommendation Simulator",
    version="2.0.0",
    description="Simulates _getRecommendation. Open /ui to configure.",
)

rules_store: dict[str, list[dict[str, Any]]] = {}

# Scale-test specs keyed by tag, so a materialized scale set can be regenerated
# for the streaming download without keeping the whole list in memory.
scale_specs: dict[str, dict[str, Any]] = {}


@app.exception_handler(RequestValidationError)
async def _validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Return a single, human-readable validation message instead of the raw
    pydantic error list, so the UI can show a clear error to the user."""
    parts: list[str] = []
    for err in exc.errors():
        loc = ".".join(str(x) for x in err.get("loc", []) if x not in ("body", "query"))
        msg = err.get("msg", "invalid value")
        msg = msg.replace("Value error, ", "")
        parts.append(f"{loc}: {msg}" if loc else msg)
    return JSONResponse(status_code=422, content={"detail": "; ".join(parts) or "Invalid request."})


generation_config: dict[str, Any] = {
    "rules_per_network": 3,
    "sourceIPs": [],
    "sourcePorts": [],
    "destinationPorts": [],
    "protocols": ["6", "17"],
    "tcpFlags": [],
    "packetSize": ["128"],
    "sourceGeo": ["US"],
    "sourceASN": ["7018"],
    "fragment": "none",
    "action": "allow",
}

RECOMMENDATIONS_DIR = Path(__file__).parent / "recommendations"
_ACCOUNT_ID = "67d6a0d9c39077bed7e1f23e"


def _load_recommendations_from_disk() -> None:
    if not RECOMMENDATIONS_DIR.exists():
        return
    for jf in RECOMMENDATIONS_DIR.glob("*.json"):
        try:
            data = json.loads(jf.read_text(encoding="utf-8"))
            for pe in data.get("PolicyList", []):
                tag = pe.get("Policy", "")
                for feat in pe.get("FeatureList", []):
                    if feat.get("Feature") != "PREVENTIVE_FILTERS_PROTECTION":
                        continue
                    for params in feat.get("ParametersList", []):
                        raw = params.get("rules", [])
                        if tag and raw:
                            rules_store.setdefault(tag, []).extend(raw)
        except Exception as exc:
            print(f"[simulator] WARNING: {jf.name}: {exc}")

_load_recommendations_from_disk()


class GetRecommendationRequest(BaseModel):
    tag: str = Field(min_length=1)
    networks: list[str] = Field(min_length=1)

    @field_validator("networks")
    @classmethod
    def _validate_networks(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError(
                "at least one destination network is required, "
                "e.g. [\"1.1.1.1/32\"]."
            )
        for n in v:
            # Each destination must be a valid IPv4/IPv6 subnet (CIDR).
            netvalidate.validate_cidr(n, field="destination network")
        return v

class GenerationConfigRequest(BaseModel):
    rules_per_network: int = Field(default=3, ge=1, le=50)
    sourceIPs: list[str] = Field(default_factory=list)
    sourcePorts: list[str] = Field(default_factory=list)
    destinationPorts: list[str] = Field(default_factory=list)
    protocols: list[str] = Field(default_factory=list)
    tcpFlags: list[str] = Field(default_factory=list)
    packetSize: list[str] = Field(default_factory=list)
    sourceGeo: list[str] = Field(default_factory=list)
    sourceASN: list[str] = Field(default_factory=list)
    fragment: str = "none"
    action: str = "allow"

class SeedRequest(BaseModel):
    tag: str
    rules: list[dict[str, Any]] = Field(default_factory=list)

class GenerateRequest(BaseModel):
    tag: str
    count: int = Field(default=3, ge=1, le=50)

class TemplateRequest(BaseModel):
    enabled: bool = True
    networks: list[str] = Field(default_factory=lambda: ["100.98.10.0/24"])
    rules: list[dict[str, Any]] = Field(default_factory=list)

class TemplatePreviewRequest(BaseModel):
    networks: list[str] = Field(default_factory=lambda: ["100.98.10.0/24"])
    rules: list[dict[str, Any]] | None = None

class TemplateUpsertRequest(BaseModel):
    name: str = ""
    enabled: bool = True
    networks: list[str] = Field(default_factory=list)
    rules: list[dict[str, Any]] = Field(default_factory=list)

class ScaleRequest(BaseModel):
    destination_network: str = Field(min_length=1)
    count: int = Field(ge=1)
    mode: str = "dst-seq"                      # dst-seq | src-seq | random
    source_network: str | None = None
    host_prefix: int | None = None
    protocol: list[str] = Field(default_factory=list)
    source_ports: list[str] = Field(default_factory=list)
    destination_ports: list[str] = Field(default_factory=list)
    action: str = "allow"
    tag: str = "scale"

class ConfigureCCRequest(BaseModel):
    cc_host: str = Field(min_length=1)
    ssh_user: str = "root"
    ssh_pass: str = ""
    ssh_port: int = 22
    sim_hostport: str = ""  # optional: auto-detected server-side when blank
    restart: bool = True

class ResetCCRequest(BaseModel):
    cc_host: str = Field(min_length=1)
    ssh_user: str = "root"
    ssh_pass: str = ""
    ssh_port: int = 22
    restart: bool = True


def _iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

def _interval_for_now() -> dict[str, str]:
    now = datetime.now(timezone.utc)
    h = (now.hour // 3) * 3
    start = now.replace(hour=h, minute=0, second=0, microsecond=0)
    end = start + timedelta(hours=3) - timedelta(seconds=1)
    return {"start_time": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "end_time":   end.strftime("%Y-%m-%dT%H:%M:%SZ")}

def _rule_id(network: str, index: int) -> str:
    return "rule_" + hashlib.sha256(f"{network}:{index}".encode()).hexdigest()

def _generate(networks: list[str]) -> list[dict[str, Any]]:
    cfg = generation_config
    rules = []
    for net in networks:
        for i in range(cfg["rules_per_network"]):
            rules.append({
                "ruleId": _rule_id(net, i),
                "sourceIPs": list(cfg["sourceIPs"]),
                "destinationIPs": [net],
                "sourcePorts": list(cfg["sourcePorts"]),
                "destinationPorts": list(cfg["destinationPorts"]),
                "protocol": list(cfg["protocols"]),
                "tcpFlags": list(cfg["tcpFlags"]),
                "packetSize": list(cfg["packetSize"]),
                "fragment": cfg["fragment"],
                "sourceGeo": list(cfg["sourceGeo"]),
                "sourceASN": list(cfg["sourceASN"]),
                "action": cfg["action"],
                "status": "success",
            })
    return rules

def _normalize(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "ruleId": raw.get("ruleId", ""),
        "sourceIPs": raw.get("sourceIPs", raw.get("sourceIps", [])),
        "destinationIPs": raw.get("destinationIPs", raw.get("destinationIps", [])),
        "sourcePorts": raw.get("sourcePorts", []),
        "destinationPorts": raw.get("destinationPorts", []),
        "protocol": raw.get("protocol", raw.get("protocols", [])),
        "tcpFlags": raw.get("tcpFlags", []),
        "packetSize": raw.get("packetSize", []),
        "fragment": raw.get("fragment", raw.get("fragmented", "none") or "none"),
        "sourceGeo": raw.get("sourceGeo", []),
        "sourceASN": raw.get("sourceASN", raw.get("sourceAsn", [])),
        "action": raw.get("action", "allow"),
        "status": "success",
    }


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/sdcc/genai/core/analysis/peacetime/_getRecommendation")
def get_recommendation(request: GetRecommendationRequest) -> dict[str, Any]:
    permanent = permanent_rules_for(request.networks)
    if permanent is not None:
        rules = permanent
    else:
        raw = rules_store.get(request.tag)
        if raw is not None:
            rules = [_normalize(r) for r in raw]
        else:
            # User-edited templates: dst network always matches the request.
            # build_rules returns [] when no enabled template matches, so we
            # fall back to auto-generation in that case.
            tpl_rules = response_template.build_rules(request.networks)
            rules = tpl_rules if tpl_rules else _generate(request.networks)
    return {
        "account_id": _ACCOUNT_ID,
        "rules": rules,
        "metadata": {
            "tag": request.tag,
            "networks": [{"subnet": n, "status": "success"} for n in request.networks],
            "interval": _interval_for_now(),
        },
        "timestamp": _iso_now(),
    }


# --------------------------------------------------------------------------- #
# UI (two tabs: CC setup + recommendation template) served from static/ui.html
# --------------------------------------------------------------------------- #
@app.get("/ui", response_class=HTMLResponse)
def ui() -> HTMLResponse:
    html = (STATIC_DIR / "ui.html")
    if html.exists():
        return HTMLResponse(html.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>UI file missing</h1>", status_code=500)


def _detect_ip() -> str:
    """Best-effort primary outbound IP of this host (for the sim address hint)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return ""


def _resolve_sim_hostport(supplied: str, request: Request) -> str:
    """Return the address CCs should call: explicit override, else auto-detected."""
    sim = (supplied or "").strip()
    if sim:
        return sim
    port = os.environ.get("PORT", "8080")
    sim = request.headers.get("host", "") or (
        f"{_detect_ip()}:{port}" if _detect_ip() else ""
    )
    if not sim:
        raise HTTPException(
            status_code=400,
            detail="Could not determine the simulator address; set it under Advanced.",
        )
    return sim


@app.get("/ui/siminfo")
def siminfo(request: Request) -> dict[str, Any]:
    """Report how CCs should reach this simulator, so the UI can auto-fill it."""
    port = os.environ.get("PORT", "8080")
    host_header = request.headers.get("host", "")  # what the browser used
    detected_ip = _detect_ip()
    # Prefer the address the operator is already using to reach the UI; that is
    # almost always reachable from the CC too. Fall back to the detected IP.
    suggested = host_header or (f"{detected_ip}:{port}" if detected_ip else "")
    return {
        "version": app.version,
        "port": port,
        "host_header": host_header,
        "detected_ip": detected_ip,
        "suggested_sim_hostport": suggested,
    }


# --- Tab 2: recommendation template -----------------------------------------
@app.get("/ui/template")
def get_template() -> dict[str, Any]:
    return response_template.get_template()
@app.post("/ui/template")
def set_template(body: TemplateRequest) -> dict[str, Any]:
    try:
        saved = response_template.set_template(
            {"enabled": body.enabled, "networks": body.networks, "rules": body.rules}
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"saved": True, "template": saved}


@app.post("/ui/template/preview")
def preview_template(body: TemplatePreviewRequest) -> dict[str, Any]:
    networks = body.networks or ["100.98.10.0/24"]
    if body.rules is not None:
        # Preview arbitrary (unsaved) rules without persisting them.
        out: list[dict[str, Any]] = []
        for net in networks:
            for i, rt in enumerate(body.rules):
                rule = {"ruleId": rt.get("ruleId") or f"rule_preview_{i}",
                        "destinationIPs": [net]}
                for k, v in rt.items():
                    if k in ("ruleId", "destinationIPs"):
                        continue
                    if v not in (None, "", []):
                        rule[k] = v
                # ADE requires non-null fragment/action (see response_template).
                rule.setdefault("fragment", "none")
                rule.setdefault("action", "allow")
                rule["status"] = "success"
                out.append(rule)
        rules = out
    else:
        rules = response_template.build_rules(networks)
    return {"networks": networks, "rules": rules}


# --- Tab 2 (multi-template): manage many recommendation templates -----------
@app.get("/ui/templates")
def list_templates() -> dict[str, Any]:
    return {"templates": response_template.list_templates()}


@app.post("/ui/templates", status_code=201)
def create_template(body: TemplateUpsertRequest) -> dict[str, Any]:
    try:
        tpl = response_template.add_template(body.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"created": True, "template": tpl}


@app.put("/ui/templates/{template_id}")
def edit_template(template_id: str, body: TemplateUpsertRequest) -> dict[str, Any]:
    try:
        tpl = response_template.update_template(template_id, body.model_dump())
    except KeyError:
        raise HTTPException(status_code=404, detail=f"Template '{template_id}' not found")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return {"saved": True, "template": tpl}


@app.delete("/ui/templates/{template_id}")
def remove_template(template_id: str) -> dict[str, Any]:
    if not response_template.delete_template(template_id):
        raise HTTPException(status_code=404, detail=f"Template '{template_id}' not found")
    return {"removed": template_id}


# --- Scale testing: generate many unique recommendations --------------------
def _spec_from_request(body: ScaleRequest, *, max_count: int | None = None) -> dict[str, Any]:
    try:
        return netgen.build_spec(
            destination_network=body.destination_network,
            count=body.count,
            mode=body.mode,
            source_network=body.source_network,
            host_prefix=body.host_prefix,
            protocol=body.protocol,
            source_ports=body.source_ports,
            destination_ports=body.destination_ports,
            action=body.action,
            tag=body.tag,
            max_count=max_count,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/ui/scale/preview")
def scale_preview(body: ScaleRequest) -> dict[str, Any]:
    """Validate a scale spec and return a small sample plus capacity info.

    Builds only a handful of rules, never the full set, so it stays instant.
    """
    spec = _spec_from_request(body)
    sample = netgen.sample_rules(spec, 5)
    # Rough per-rule size estimate (compact JSON) for a heads-up on payload size.
    est_bytes = len(json.dumps(sample[0])) * spec["count"] if sample else 0
    return {
        "ok": True,
        "mode": spec["mode"],
        "count": spec["count"],
        "capacity": spec["capacity"],
        "host_prefix": spec["host_prefix"],
        "destination_network": spec["destination_network"],
        "source_network": spec["source_network"],
        "serve_limit": SCALE_MAX_SERVE,
        "download_limit": SCALE_MAX_DOWNLOAD,
        "estimated_bytes": est_bytes,
        "sample": sample,
    }


@app.post("/ui/scale/generate")
def scale_generate(body: ScaleRequest) -> dict[str, Any]:
    """Materialize a scale set and serve it under ``tag`` via _getRecommendation.

    Bounded by SCALE_MAX_SERVE to protect memory; for larger sets use the
    streaming download instead.
    """
    spec = _spec_from_request(body, max_count=SCALE_MAX_SERVE)
    rules = list(netgen.iter_rules(spec))
    rules_store[spec["tag"]] = rules
    scale_specs[spec["tag"]] = spec
    # Sanity: confirm there are no duplicate destination/source pairs.
    dst_seen = {tuple(r["destinationIPs"]) for r in rules}
    src_seen = {tuple(r["sourceIPs"]) for r in rules}
    unique_ids = len({r["ruleId"] for r in rules}) == len(rules)
    return {
        "generated": len(rules),
        "tag": spec["tag"],
        "mode": spec["mode"],
        "unique_rule_ids": unique_ids,
        "unique_destinations": len(dst_seen),
        "unique_sources": len(src_seen),
        "served_at_tag": spec["tag"],
        "hint": f"A Cyber Controller querying tag '{spec['tag']}' now receives "
                f"{len(rules)} rules. Use Download for larger sets.",
    }


@app.post("/ui/scale/download")
def scale_download(body: ScaleRequest) -> StreamingResponse:
    """Stream the full scale set as a downloadable JSON file (memory-safe)."""
    spec = _spec_from_request(body, max_count=SCALE_MAX_DOWNLOAD)

    def _stream() -> Iterator[str]:
        head = {"tag": spec["tag"], "mode": spec["mode"], "count": spec["count"]}
        yield '{"tag": %s, "mode": %s, "count": %d, "rules": [' % (
            json.dumps(head["tag"]), json.dumps(head["mode"]), head["count"])
        first = True
        for rule in netgen.iter_rules(spec):
            yield ("" if first else ",") + json.dumps(rule)
            first = False
        yield "]}"

    fname = f"scale_{spec['tag']}_{spec['mode']}_{spec['count']}.json"
    return StreamingResponse(
        _stream(), media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'})


# --- Tab 3: browse existing recommendations ---------------------------------
@app.get("/ui/recommendations")
def list_recommendations() -> dict[str, Any]:
    """Return all existing rule sets so users can browse and reuse them.

    - 'template':  every editable template (Tab 2) that currently has rules
    - 'permanent': pinned per-network responses (permanent_responses.py)
    - 'seeded':    tag-based rule sets loaded from recommendations/ or /admin/seed
    """
    template_group = []
    for tpl in response_template.list_templates():
        if not tpl.get("rules"):
            continue
        state = "active" if tpl.get("enabled") else "inactive"
        nets = tpl.get("networks", [])
        scope = ", ".join(nets) if nets else "any network"
        template_group.append({
            "kind": "template",
            "key": f"{tpl.get('name', 'Template')} \u2014 {state} ({scope})",
            "networks": nets,
            "count": len(tpl["rules"]),
            "rules": tpl["rules"],
        })
    permanent = [
        {"kind": "permanent", "key": net, "networks": [net],
         "count": len(rules), "rules": rules}
        for net, rules in PERMANENT_NETWORK_RULES.items()
    ]
    seeded = [
        {"kind": "seeded", "key": tag, "networks": [],
         "count": len(rules), "rules": [_normalize(r) for r in rules]}
        for tag, rules in rules_store.items()
    ]
    return {"groups": template_group + permanent + seeded}


# --- Tab 1: Cyber Controller configuration ----------------------------------
@app.get("/ui/cc")
def list_cc() -> list[dict[str, Any]]:
    return cc_manager.list_ccs()


@app.post("/ui/cc/configure")
def configure_cc(body: ConfigureCCRequest, request: Request) -> dict[str, Any]:
    sim_hostport = _resolve_sim_hostport(body.sim_hostport, request)
    result = cc_manager.configure_cc(
        cc_host=body.cc_host,
        ssh_user=body.ssh_user,
        ssh_pass=body.ssh_pass,
        sim_hostport=sim_hostport,
        ssh_port=body.ssh_port,
        restart=body.restart,
    )
    return result


@app.post("/ui/cc/test")
def test_cc(body: ConfigureCCRequest, request: Request) -> dict[str, Any]:
    """Read-only preflight: validate a CC before configuring (makes no changes)."""
    sim_hostport = _resolve_sim_hostport(body.sim_hostport, request)
    try:
        return cc_manager.preflight_cc(
            cc_host=body.cc_host,
            ssh_user=body.ssh_user,
            ssh_pass=body.ssh_pass,
            sim_hostport=sim_hostport,
            ssh_port=body.ssh_port,
        )
    except Exception as exc:  # never 500 the UI
        return {"ok": False, "checks": [
            {"name": "Preflight", "ok": False, "detail": f"{type(exc).__name__}: {exc}"}]}


@app.delete("/ui/cc/{cc_host}")
def delete_cc(cc_host: str) -> dict[str, Any]:
    removed = cc_manager.remove_cc(cc_host)
    if not removed:
        raise HTTPException(status_code=404, detail=f"CC '{cc_host}' not registered")
    return {"removed": cc_host}


@app.post("/ui/cc/reset")
def reset_cc(body: ResetCCRequest) -> dict[str, Any]:
    return cc_manager.reset_cc(
        cc_host=body.cc_host,
        ssh_user=body.ssh_user,
        ssh_pass=body.ssh_pass,
        ssh_port=body.ssh_port,
        restart=body.restart,
    )


@app.get("/ui/config")
def get_config() -> dict[str, Any]:
    return dict(generation_config)

@app.post("/ui/config")
def set_config(body: GenerationConfigRequest) -> dict[str, Any]:
    generation_config["rules_per_network"] = body.rules_per_network
    generation_config["sourceIPs"] = body.sourceIPs
    generation_config["sourcePorts"] = body.sourcePorts
    generation_config["destinationPorts"] = body.destinationPorts
    if body.protocols:      generation_config["protocols"] = body.protocols
    generation_config["tcpFlags"] = body.tcpFlags
    if body.packetSize:     generation_config["packetSize"] = body.packetSize
    if body.sourceGeo:      generation_config["sourceGeo"] = body.sourceGeo
    if body.sourceASN:      generation_config["sourceASN"] = body.sourceASN
    generation_config["fragment"] = body.fragment
    generation_config["action"] = body.action
    return {"saved": True, "config": dict(generation_config)}

@app.post("/ui/generate")
def generate_preview(body: GenerateRequest) -> dict[str, Any]:
    old = generation_config["rules_per_network"]
    generation_config["rules_per_network"] = body.count
    rules = _generate(["<network-from-request>"])
    generation_config["rules_per_network"] = old
    return {"tag": body.tag, "rules": rules}

@app.get("/admin/tags")
def list_tags() -> dict[str, Any]:
    return {tag: len(rules) for tag, rules in rules_store.items()}

@app.post("/admin/reload")
def reload_from_disk() -> dict[str, Any]:
    rules_store.clear(); _load_recommendations_from_disk()
    return {"loaded_tags": list(rules_store.keys())}

@app.post("/admin/seed", status_code=201)
def seed_rules(body: SeedRequest) -> dict[str, Any]:
    rules_store[body.tag] = body.rules
    return {"seeded": body.tag, "rule_count": len(body.rules)}

@app.delete("/admin/seed/{tag}")
def clear_seed(tag: str) -> dict[str, str]:
    if tag not in rules_store:
        raise HTTPException(status_code=404, detail=f"No seed found for tag '{tag}'")
    del rules_store[tag]
    return {"cleared": tag}
