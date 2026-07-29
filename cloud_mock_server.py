from __future__ import annotations
import hashlib, json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from permanent_responses import permanent_rules_for

app = FastAPI(
    title="SOC-X Cloud Recommendation Simulator",
    version="2.0.0",
    description="Simulates _getRecommendation. Open /ui to configure.",
)

rules_store: dict[str, list[dict[str, Any]]] = {}

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
        rules = [_normalize(r) for r in raw] if raw is not None else _generate(request.networks)
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


_UI = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SOC-X Simulator</title>
<style>
*{box-sizing:border-box}body{font-family:Arial,sans-serif;margin:0;background:#f0f2f5;color:#222}
header{background:#1a3c5e;color:#fff;padding:16px 32px}header h1{margin:0;font-size:1.4rem}
header p{margin:4px 0 0;font-size:.85rem;opacity:.8}
main{max-width:960px;margin:24px auto;padding:0 16px 40px}
.card{background:#fff;border-radius:8px;box-shadow:0 2px 6px rgba(0,0,0,.1);padding:24px;margin-bottom:24px}
.card h2{margin:0 0 16px;font-size:1.1rem;color:#1a3c5e;border-bottom:2px solid #e0e6f0;padding-bottom:8px}
label{display:block;font-size:.85rem;font-weight:bold;margin-bottom:4px}
input,textarea{width:100%;padding:8px 10px;border:1px solid #ccc;border-radius:4px;font-size:.9rem;margin-bottom:12px}
input[type=number]{width:130px}.row{display:flex;gap:16px;flex-wrap:wrap}.row .f{flex:1;min-width:180px}
button{background:#1a3c5e;color:#fff;border:none;padding:10px 24px;border-radius:4px;cursor:pointer;font-size:.9rem}
button:hover{background:#245080}.hint{font-size:.78rem;color:#888;margin-top:-8px;margin-bottom:12px}
.tags{display:flex;flex-wrap:wrap;gap:8px;margin-top:8px}
.badge{background:#e8f0fe;color:#1a3c5e;border-radius:4px;padding:4px 12px;font-size:.82rem;display:flex;align-items:center;gap:8px}
.rm{background:none;color:#c0392b;padding:0 2px;font-size:1rem;cursor:pointer;border:none}
.toast{position:fixed;bottom:24px;right:24px;color:#fff;padding:12px 24px;border-radius:6px;display:none;font-size:.9rem;box-shadow:0 4px 12px rgba(0,0,0,.2)}
</style></head><body>
<header><h1>&#128737; SOC-X Recommendation Simulator</h1>
<p>Any Cyber Controller sending a request will receive recommendations. Use this UI to control what gets returned.</p></header>
<main>
<div class="card"><h2>&#9881; Auto-Generation Settings</h2>
<p style="font-size:.85rem;color:#555;margin-top:0">Applies to <b>every request</b> whose tag has no pinned rules.</p>
<label>Rules per network</label><input type="number" id="cfg_n" value="3" min="1" max="50" style="width:130px">
<div class="row">
  <div class="f"><label>Protocols</label><input id="cfg_proto" placeholder="6,17"><p class="hint">6=TCP 17=UDP 2=ICMP</p></div>
  <div class="f"><label>Source Geo</label><input id="cfg_geo" placeholder="US,IL,DE"></div>
  <div class="f"><label>Source ASN</label><input id="cfg_asn" placeholder="7018,1234"></div>
</div>
<div class="row">
  <div class="f"><label>Source IPs</label><input id="cfg_sip" placeholder="5.5.5.1/32"></div>
  <div class="f"><label>Source Ports</label><input id="cfg_sp" placeholder="8080,443"></div>
  <div class="f"><label>Destination Ports</label><input id="cfg_dp" placeholder="80,1024"></div>
</div>
<div class="row">
  <div class="f"><label>Packet Size</label><input id="cfg_pkt" placeholder="128,512"></div>
  <div class="f"><label>Fragment</label><input id="cfg_frag" value="none"></div>
</div>
<button onclick="saveConfig()">&#128190; Save Settings</button></div>

<div class="card"><h2>&#127919; Pin Custom Rules for a Tag</h2>
<p style="font-size:.85rem;color:#555;margin-top:0">Requests for this tag always return these rules instead of auto-generated ones.</p>
<label>Tag / Policy Name</label><input id="pin_tag" placeholder="e.g. icmp  or  Socx_Connection">
<label>Number of rules to generate</label><input type="number" id="pin_n" value="3" min="1" max="50" style="width:130px">
<p class="hint">Uses Auto-Generation Settings above. destinationIPs will be the real networks from each request.</p>
<label>Or paste raw rules JSON (overrides count)</label>
<textarea id="pin_json" rows="5" style="font-family:monospace;font-size:.82rem"
  placeholder='[{"ruleId":"rule_abc","destinationIPs":["10.0.0.1/32"],"protocol":["6"],"status":"success"}]'></textarea>
<p class="hint">Leave empty to auto-generate.</p>
<button onclick="pinRules()">&#128204; Pin Rules for Tag</button></div>

<div class="card"><h2>&#128203; Pinned Tags</h2>
<p style="font-size:.85rem;color:#555;margin-top:0">Pinned tags return fixed rules. All others auto-generate from request networks.</p>
<div class="tags" id="tag_list">Loading&#8230;</div><br>
<button onclick="reloadDisk()">&#128260; Reload from recommendations/ folder</button></div>
</main>
<div class="toast" id="toast"></div>
<script>
const csv=s=>s.split(",").map(x=>x.trim()).filter(Boolean);
function toast(m,ok=true){const t=document.getElementById("toast");t.textContent=m;t.style.background=ok?"#27ae60":"#c0392b";t.style.display="block";setTimeout(()=>t.style.display="none",3000)}
async function saveConfig(){
  const b={rules_per_network:parseInt(document.getElementById("cfg_n").value)||3,
    protocols:csv(document.getElementById("cfg_proto").value),sourceGeo:csv(document.getElementById("cfg_geo").value),
    sourceASN:csv(document.getElementById("cfg_asn").value),sourceIPs:csv(document.getElementById("cfg_sip").value),
    sourcePorts:csv(document.getElementById("cfg_sp").value),destinationPorts:csv(document.getElementById("cfg_dp").value),
    packetSize:csv(document.getElementById("cfg_pkt").value),fragment:document.getElementById("cfg_frag").value||"none"};
  const r=await fetch("/ui/config",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(b)});
  r.ok?toast("Settings saved!"):toast("Failed",false)}
async function pinRules(){
  const tag=document.getElementById("pin_tag").value.trim();
  if(!tag){toast("Tag cannot be empty",false);return}
  const raw=document.getElementById("pin_json").value.trim();
  let rules=[];
  if(raw){try{rules=JSON.parse(raw)}catch(e){toast("Invalid JSON: "+e.message,false);return}}
  else{const cnt=parseInt(document.getElementById("pin_n").value)||3;
    const r=await fetch("/ui/generate",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({tag,count:cnt})});
    if(!r.ok){toast("Could not generate",false);return}rules=(await r.json()).rules}
  const r=await fetch("/admin/seed",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({tag,rules})});
  r.ok?(toast("Pinned for: "+tag),loadTags()):toast("Failed",false)}
async function removeTag(tag){await fetch("/admin/seed/"+encodeURIComponent(tag),{method:"DELETE"});toast("Removed: "+tag);loadTags()}
async function reloadDisk(){const d=await(await fetch("/admin/reload",{method:"POST"})).json();toast("Reloaded "+d.loaded_tags.length+" tag(s)");loadTags()}
async function loadTags(){const tags=await(await fetch("/admin/tags")).json();const el=document.getElementById("tag_list");
  const e=Object.entries(tags);if(!e.length){el.innerHTML='<span style="color:#888;font-size:.85rem">No pinned tags — all use auto-generation.</span>';return}
  el.innerHTML=e.map(([t,c])=>`<div class="badge"><span><b>${t}</b> <span style="opacity:.65">(${c} rules)</span></span><button class="rm" onclick="removeTag('${t}')" title="Remove">&#10005;</button></div>`).join("")}
async function loadCfg(){const c=await(await fetch("/ui/config")).json();
  document.getElementById("cfg_n").value=c.rules_per_network;
  document.getElementById("cfg_proto").value=(c.protocols||[]).join(",");
  document.getElementById("cfg_geo").value=(c.sourceGeo||[]).join(",");
  document.getElementById("cfg_asn").value=(c.sourceASN||[]).join(",");
  document.getElementById("cfg_sip").value=(c.sourceIPs||[]).join(",");
  document.getElementById("cfg_sp").value=(c.sourcePorts||[]).join(",");
  document.getElementById("cfg_dp").value=(c.destinationPorts||[]).join(",");
  document.getElementById("cfg_pkt").value=(c.packetSize||[]).join(",");
  document.getElementById("cfg_frag").value=c.fragment||"none"}
loadCfg();loadTags();
</script></body></html>"""


@app.get("/ui", response_class=HTMLResponse)
def ui() -> str:
    return _UI

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
