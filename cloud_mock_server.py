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

_ACCOUNT_ID = "67d6a0d9c39077bed7e1f23e"

# Per-Cyber-Controller recommendation sets, keyed by the CC's PRIMARY IP.
# One set per CC (regenerating replaces it). Each set is bound to a single
# destination network and may also list a SECONDARY CC IP for HA (primary +
# secondary controllers), so a request from either IP resolves to the same set.
#   cc_sets[cc_ip] = {
#       "cc_ip", "secondary_ip", "destination_network",
#       "mode", "count", "created_at", "rules": [...]
#   }
cc_sets: dict[str, dict[str, Any]] = {}


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


def _cc_set_for(caller_ip: str) -> dict[str, Any] | None:
    """Return the recommendation set assigned to ``caller_ip`` (primary OR
    secondary IP), or None. Supports HA: either controller IP matches."""
    if not caller_ip:
        return None
    for s in cc_sets.values():
        if caller_ip == s.get("cc_ip") or caller_ip == (s.get("secondary_ip") or ""):
            return s
    return None


class GetRecommendationRequest(BaseModel):
    # A Cyber Controller sends ONLY the destination network(s). Recommendations
    # are routed by the CALLING CC's IP, which the simulator auto-detects from
    # the connection. An optional 'cc_ip' may be supplied to override the
    # detected address (useful for testing tools and behind NAT/proxies).
    networks: list[str] = Field(min_length=1)
    cc_ip: str | None = None
    # The ADE sends a 'tag' (e.g. the device policy id) and REQUIRES it echoed
    # back, non-empty, in the response metadata (its
    # SocxPositiveRecommendationMetadataResponseData.validate() rejects a
    # null/empty tag). It is NOT used for routing (routing is by CC IP); we only
    # accept it and echo it back so the ADE accepts the response.
    tag: str | int | None = None

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

class TemplateRequest(BaseModel):
    enabled: bool = True
    networks: list[str] = Field(default_factory=list)  # empty = catch-all
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
    mode: str = "dst-seq"          # dst-seq | dst-rand | src-seq | src-rand
    source_network: str | None = None
    host_prefix: int | None = None
    protocol: list[str] = Field(default_factory=list)
    source_ports: list[str] = Field(default_factory=list)
    destination_ports: list[str] = Field(default_factory=list)
    action: str = "allow"
    cc_ip: str | None = None            # target CC (primary) for generate/assign
    secondary_ip: str | None = None     # optional HA secondary CC IP

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
        "ttl": raw.get("ttl", []),
        "fragment": raw.get("fragment", raw.get("fragmented", "none") or "none"),
        "sourceGeo": raw.get("sourceGeo", []),
        "sourceASN": raw.get("sourceASN", raw.get("sourceAsn", [])),
        "action": raw.get("action", "allow"),
        "status": "success",
    }


def _learning_rule(net: str) -> dict[str, Any]:
    """The default response for a destination network that has no configured
    recommendation yet: a single 'ANY -> dst' rule in the 'learning' state,
    with a freshly randomized Rule ID. NEVER auto-generates traffic rules."""
    import secrets
    return {
        "ruleId": "rule_" + secrets.token_hex(32),
        "sourceIPs": [],
        "destinationIPs": [net],
        "sourcePorts": [],
        "destinationPorts": [],
        "protocol": [],
        "tcpFlags": [],
        "packetSize": [],
        "ttl": [],
        "fragment": "none",
        "sourceGeo": [],
        "sourceASN": [],
        "action": "allow",
        "status": "learning",
    }


def _caller_ip(request: GetRecommendationRequest, http: Request) -> str:
    """The IP used to route recommendations: an explicit override in the body,
    else the detected source IP of the connection (honoring X-Forwarded-For if
    the simulator is fronted by a reverse proxy)."""
    if request.cc_ip and request.cc_ip.strip():
        return request.cc_ip.strip()
    xff = http.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return http.client.host if http.client else ""


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/sdcc/genai/core/analysis/peacetime/_getRecommendation")
def get_recommendation(request: GetRecommendationRequest, http: Request) -> dict[str, Any]:
    """Resolve recommendations per destination network, routed by the calling
    Cyber Controller's IP. Order per network:
        1. Permanent pin (shared, by network)
        2. This CC's assigned set (by CC IP), for its destination network
        3. Template enabled for the network (shared, by network)
        4. Otherwise a single 'learning' default rule.
    No traffic rules are ever auto-generated.
    """
    caller = _caller_ip(request, http)
    cc_set = _cc_set_for(caller)
    rules: list[dict[str, Any]] = []
    net_status: list[dict[str, str]] = []
    for net in request.networks:
        pinned = permanent_rules_for([net])
        if pinned:
            rules.extend(pinned)
            net_status.append({"subnet": net, "status": "success"})
            continue
        if cc_set and net == cc_set.get("destination_network"):
            rules.extend(cc_set.get("rules", []))
            net_status.append({"subnet": net, "status": "success"})
            continue
        tpl_rules = response_template.build_rules([net])
        if tpl_rules:
            rules.extend(tpl_rules)
            net_status.append({"subnet": net, "status": "success"})
            continue
        # Nothing configured for this network -> single learning placeholder.
        rules.append(_learning_rule(net))
        net_status.append({"subnet": net, "status": "learning"})
    # The ADE requires a non-empty 'tag' echoed back in the response metadata,
    # or it rejects the whole response ("tag must not be null or empty"). Echo
    # the tag the ADE sent; fall back to a non-empty placeholder if absent.
    echo_tag = str(request.tag) if request.tag not in (None, "") else "default"
    return {
        "account_id": _ACCOUNT_ID,
        "rules": rules,
        "metadata": {
            "tag": echo_tag,
            "networks": net_status,
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


# --- Scale testing: generate many unique recommendations, assigned to a CC --
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
            max_count=max_count,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


def _validate_ip(value: str, field: str) -> str:
    import ipaddress
    s = (value or "").strip()
    if not s:
        raise HTTPException(status_code=400, detail=f"{field} is required.")
    try:
        ipaddress.ip_address(s)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"{field} '{s}' is not a valid IP address.")
    return s


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
    """Materialize a scale set and ASSIGN it to a Cyber Controller by IP.

    The set is served to that CC (primary or secondary IP) when it requests the
    set's destination network. One set per CC (this replaces any previous set
    for the same primary IP). Bounded by SCALE_MAX_SERVE to protect memory.
    """
    cc_ip = _validate_ip(body.cc_ip or "", "CC IP")
    secondary = None
    if body.secondary_ip and body.secondary_ip.strip():
        secondary = _validate_ip(body.secondary_ip, "Secondary CC IP")
        if secondary == cc_ip:
            raise HTTPException(status_code=400,
                                detail="Secondary CC IP must differ from the primary CC IP.")
    spec = _spec_from_request(body, max_count=SCALE_MAX_SERVE)
    rules = list(netgen.iter_rules(spec))
    cc_sets[cc_ip] = {
        "cc_ip": cc_ip,
        "secondary_ip": secondary,
        "destination_network": spec["destination_network"],
        "mode": spec["mode"],
        "count": len(rules),
        "created_at": _iso_now(),
        "rules": rules,
    }
    dst_seen = {tuple(r["destinationIPs"]) for r in rules}
    src_seen = {tuple(r["sourceIPs"]) for r in rules}
    unique_ids = len({r["ruleId"] for r in rules}) == len(rules)
    ha = f" (or secondary {secondary})" if secondary else ""
    return {
        "generated": len(rules),
        "cc_ip": cc_ip,
        "secondary_ip": secondary,
        "destination_network": spec["destination_network"],
        "mode": spec["mode"],
        "unique_rule_ids": unique_ids,
        "unique_destinations": len(dst_seen),
        "unique_sources": len(src_seen),
        "hint": f"Cyber Controller {cc_ip}{ha} now receives {len(rules)} rules when "
                f"it requests {spec['destination_network']}. Use Download for larger sets.",
    }


@app.post("/ui/scale/download")
def scale_download(body: ScaleRequest) -> StreamingResponse:
    """Stream the full scale set as a downloadable JSON file (memory-safe)."""
    spec = _spec_from_request(body, max_count=SCALE_MAX_DOWNLOAD)

    def _stream() -> Iterator[str]:
        yield '{"destination_network": %s, "mode": %s, "count": %d, "rules": [' % (
            json.dumps(spec["destination_network"]), json.dumps(spec["mode"]), spec["count"])
        first = True
        for rule in netgen.iter_rules(spec):
            yield ("" if first else ",") + json.dumps(rule)
            first = False
        yield "]}"

    fname = f"scale_{spec['destination_network'].replace('/', '-')}_{spec['mode']}_{spec['count']}.json"
    return StreamingResponse(
        _stream(), media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'})


@app.get("/ui/cc-sets")
def list_cc_sets() -> dict[str, Any]:
    """List the recommendation sets assigned to Cyber Controllers (summaries)."""
    out = []
    for s in cc_sets.values():
        out.append({
            "cc_ip": s["cc_ip"],
            "secondary_ip": s.get("secondary_ip"),
            "destination_network": s["destination_network"],
            "mode": s["mode"],
            "count": s["count"],
            "created_at": s.get("created_at", ""),
            "sample": s["rules"][:5],
        })
    return {"cc_sets": out}


@app.delete("/ui/cc-sets/{cc_ip}")
def delete_cc_set(cc_ip: str) -> dict[str, Any]:
    if cc_ip not in cc_sets:
        raise HTTPException(status_code=404, detail=f"No recommendation set assigned to CC '{cc_ip}'")
    del cc_sets[cc_ip]
    return {"removed": cc_ip}


# --- Tab 3: browse existing recommendations ---------------------------------
@app.get("/ui/recommendations")
def list_recommendations() -> dict[str, Any]:
    """Return all existing rule sets so users can browse and reuse them.

    - 'template':  every editable template (Tab 2) that currently has rules
    - 'permanent': pinned per-network responses (permanent_responses.py)
    - 'cc':        per-CC generated sets (assigned by CC IP)
    """
    template_group = []
    for tpl in response_template.list_templates():
        if not tpl.get("rules"):
            continue
        state = "active" if tpl.get("enabled") else "inactive"
        nets = tpl.get("networks", [])
        scope = ", ".join(nets) if nets else "any network"
        # Expand to concrete rules WITH ruleId (using one representative network
        # so the count matches the stored rules) so 'View JSON' shows real ids.
        rep = [nets[0]] if nets else None
        display_rules = response_template.expand_template(tpl, rep)
        template_group.append({
            "kind": "template",
            "key": f"{tpl.get('name', 'Template')} \u2014 {state} ({scope})",
            "networks": nets,
            "count": len(display_rules),
            "rules": display_rules,
        })
    permanent = [
        {"kind": "permanent", "key": net, "networks": [net],
         "count": len(rules), "rules": rules}
        for net, rules in PERMANENT_NETWORK_RULES.items()
    ]
    cc_group = []
    for s in cc_sets.values():
        ha = f" + {s['secondary_ip']}" if s.get("secondary_ip") else ""
        cc_group.append({
            "kind": "cc",
            "key": f"CC {s['cc_ip']}{ha} \u2014 {s['destination_network']} ({s['mode']})",
            "networks": [s["destination_network"]],
            "count": s["count"],
            "rules": s["rules"][:50],  # sample only; sets can be very large
        })
    return {"groups": template_group + permanent + cc_group}


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
