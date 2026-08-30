"""Editable recommendation templates shared by all Cyber Controllers.
Tab 2 of the UI edits a *collection* of recommendation templates. On every
``_getRecommendation`` request the matching templates are expanded into concrete
rules where:
  * ``destinationIPs`` is ALWAYS overwritten with the network(s) from the
    incoming request (the "dst network must match the request" requirement).
  * every other field (protocol, ttl, ports, geo, asn, ...) is OPTIONAL - it is
    only included in the emitted rule if the template rule actually sets it.
Template selection
------------------
Each template has a ``networks`` list:
  * empty ``networks`` => a *catch-all* template that matches every request;
  * non-empty ``networks`` => matches only requests for those exact networks.
All enabled templates that match a requested network contribute their rules.
Unique Rule IDs
---------------
Every template gets a globally-unique ``id`` (uuid4) when created. Generated
Rule IDs are derived from that id, so rules produced by a newly created
template can never collide with the Rule IDs of any previously created
template. Within one response, IDs also differ per requested network and per
rule index, so a single response never contains duplicate Rule IDs.
The collection is persisted to ``data/response_template.json`` so it survives
restarts and is shared across all callers.
"""
from __future__ import annotations
import hashlib
import json
import threading
import uuid
from pathlib import Path
from typing import Any
_DATA_DIR = Path(__file__).parent / "data"
_TEMPLATE_FILE = _DATA_DIR / "response_template.json"
_LOCK = threading.RLock()
# The legacy single-template API (get_template/set_template and the /ui/template
# endpoint) operates on a template with this fixed id.
_DEFAULT_ID = "default"
# Salt mixed into generated template rule IDs. Bump this to rotate all
# template-derived rule IDs at once.
_RULE_ID_SALT = "v2-2026-08-30"
# Optional fields a template rule may set. destinationIPs is intentionally NOT
# here because it is always derived from the request network.
_OPTIONAL_FIELDS = (
    "sourceIPs",
    "sourcePorts",
    "destinationPorts",
    "protocol",
    "tcpFlags",
    "packetSize",
    "ttl",
    "fragment",
    "sourceGeo",
    "sourceASN",
    "action",
)
def _rule_id(template_id: str, network: str, index: int) -> str:
    """Deterministic, globally-unique rule id for (template, network, rule)."""
    return "rule_" + hashlib.sha256(
        f"{_RULE_ID_SALT}:{template_id}:{network}:{index}".encode()
    ).hexdigest()
def _new_template_id(existing: set[str]) -> str:
    tid = uuid.uuid4().hex
    while tid in existing or tid == _DEFAULT_ID:
        tid = uuid.uuid4().hex
    return tid
def _empty_default() -> dict[str, Any]:
    return {
        "id": _DEFAULT_ID,
        "name": "Default template",
        "enabled": False,
        "networks": [],
        "rules": [{"action": "allow"}],
    }
# In-memory collection, loaded once and kept in sync with disk.
_templates: list[dict[str, Any]] = [_empty_default()]
def _coerce_template(raw: dict[str, Any], fallback_id: str | None = None) -> dict[str, Any]:
    """Normalize an arbitrary dict into a well-formed template record."""
    tid = str(raw.get("id") or fallback_id or "").strip()
    networks = raw.get("networks")
    if not isinstance(networks, list):
        networks = []
    networks = [str(n).strip() for n in networks if str(n).strip()]
    rules = raw.get("rules")
    if not isinstance(rules, list):
        rules = []
    name = str(raw.get("name") or "").strip()
    return {
        "id": tid,
        "name": name or "Template",
        "enabled": bool(raw.get("enabled", False)),
        "networks": networks,
        "rules": rules,
    }
def _load() -> None:
    """Load templates from disk, migrating the legacy single-template format."""
    global _templates
    if not _TEMPLATE_FILE.exists():
        return
    try:
        data = json.loads(_TEMPLATE_FILE.read_text(encoding="utf-8"))
    except Exception as exc:  # pragma: no cover - corrupt file fallback
        print(f"[template] WARNING: could not read {_TEMPLATE_FILE}: {exc}")
        return
    loaded: list[dict[str, Any]] = []
    if isinstance(data, dict) and isinstance(data.get("templates"), list):
        # New multi-template format.
        seen: set[str] = set()
        for entry in data["templates"]:
            if not isinstance(entry, dict):
                continue
            t = _coerce_template(entry)
            if not t["id"] or t["id"] in seen:
                t["id"] = _new_template_id(seen)
            seen.add(t["id"])
            loaded.append(t)
    elif isinstance(data, dict):
        # Legacy single-template format: {enabled, networks, rules}.
        legacy = _coerce_template(data, fallback_id=_DEFAULT_ID)
        legacy["id"] = _DEFAULT_ID
        legacy["name"] = legacy.get("name") or "Default template"
        loaded.append(legacy)
    if loaded:
        _templates = loaded
_load()
def _persist_locked() -> None:
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    _TEMPLATE_FILE.write_text(
        json.dumps({"templates": _templates}, indent=2), encoding="utf-8"
    )
def _find_locked(template_id: str) -> dict[str, Any] | None:
    for t in _templates:
        if t["id"] == template_id:
            return t
    return None
# --------------------------------------------------------------------------- #
# Multi-template API (Tab 2)
# --------------------------------------------------------------------------- #
def list_templates() -> list[dict[str, Any]]:
    """Return a copy of all templates."""
    with _LOCK:
        return json.loads(json.dumps(_templates))
def get_template_by_id(template_id: str) -> dict[str, Any] | None:
    with _LOCK:
        t = _find_locked(template_id)
        return json.loads(json.dumps(t)) if t else None
def _validate(data: dict[str, Any]) -> None:
    if not isinstance(data, dict):
        raise ValueError("template must be a JSON object")
    rules = data.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ValueError("template must contain a non-empty 'rules' list")
    for i, r in enumerate(rules):
        if not isinstance(r, dict):
            raise ValueError(f"rule #{i} must be a JSON object")
def add_template(data: dict[str, Any]) -> dict[str, Any]:
    """Create and persist a new template. Returns the stored record."""
    _validate(data)
    with _LOCK:
        existing = {t["id"] for t in _templates}
        record = _coerce_template(data)
        record["id"] = _new_template_id(existing)
        if not record["name"] or record["name"] == "Template":
            record["name"] = f"Template {len(_templates) + 1}"
        _templates.append(record)
        _persist_locked()
        return json.loads(json.dumps(record))
def update_template(template_id: str, data: dict[str, Any]) -> dict[str, Any]:
    """Update an existing template in place. Returns the stored record."""
    _validate(data)
    with _LOCK:
        t = _find_locked(template_id)
        if t is None:
            raise KeyError(template_id)
        updated = _coerce_template(data, fallback_id=template_id)
        updated["id"] = template_id  # id is immutable
        t.clear()
        t.update(updated)
        _persist_locked()
        return json.loads(json.dumps(t))
def delete_template(template_id: str) -> bool:
    """Remove a template. Returns True if something was removed."""
    with _LOCK:
        before = len(_templates)
        _templates[:] = [t for t in _templates if t["id"] != template_id]
        removed = len(_templates) != before
        if removed:
            _persist_locked()
        return removed
# --------------------------------------------------------------------------- #
# Legacy single-template API (kept for the /ui/template endpoint & tests)
# --------------------------------------------------------------------------- #
def get_template() -> dict[str, Any]:
    """Return the legacy 'default' template (creating a blank one if needed)."""
    with _LOCK:
        t = _find_locked(_DEFAULT_ID)
        if t is None:
            return _empty_default()
        return json.loads(json.dumps(t))
def set_template(data: dict[str, Any]) -> dict[str, Any]:
    """Upsert the legacy 'default' template.
    A missing/empty ``networks`` means the default template is a *catch-all*
    that matches every request (this preserves the historical behavior where a
    single enabled template applied to any non-pinned network).
    """
    if not isinstance(data, dict):
        raise ValueError("template must be a JSON object")
    rules = data.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ValueError("template must contain a non-empty 'rules' list")
    for i, r in enumerate(rules):
        if not isinstance(r, dict):
            raise ValueError(f"rule #{i} must be a JSON object")
    record = _coerce_template(data, fallback_id=_DEFAULT_ID)
    record["id"] = _DEFAULT_ID
    record["name"] = record.get("name") or "Default template"
    with _LOCK:
        existing = _find_locked(_DEFAULT_ID)
        if existing is None:
            _templates.insert(0, record)
        else:
            existing.clear()
            existing.update(record)
        _persist_locked()
        return json.loads(json.dumps(record))
def is_enabled() -> bool:
    """True if any enabled template currently has rules."""
    with _LOCK:
        return any(t.get("enabled") and t.get("rules") for t in _templates)
# --------------------------------------------------------------------------- #
# Request-time expansion
# --------------------------------------------------------------------------- #
def _matching_templates_locked(network: str) -> list[dict[str, Any]]:
    """Enabled templates that apply to ``network`` (catch-all or exact match)."""
    out = []
    for t in _templates:
        if not t.get("enabled") or not t.get("rules"):
            continue
        # A template matches a request when it has no networks (an explicit
        # catch-all) or explicitly lists the requested network. Templates with a
        # non-empty network list only match those networks, so an unconfigured
        # network falls through to the caller's 'learning' default.
        nets = t.get("networks") or []
        if not nets or network in nets:
            out.append(t)
    return out
def build_rules(networks: list[str]) -> list[dict[str, Any]]:
    """Expand all matching enabled templates into rules for the given networks.
    ``destinationIPs`` is forced to each requested network; all other fields are
    copied only when present in the template rule. Rule IDs are globally unique
    (namespaced by each template's id). Returns an empty list when no template
    matches, so the caller can fall back to auto-generation.
    """
    out: list[dict[str, Any]] = []
    with _LOCK:
        for net in networks:
            for t in _matching_templates_locked(net):
                tid = t["id"]
                for i, rt in enumerate(t.get("rules", [])):
                    rule: dict[str, Any] = {
                        "ruleId": rt.get("ruleId") or _rule_id(tid, net, i),
                        # dst network ALWAYS matches the incoming request
                        "destinationIPs": [net],
                    }
                    for field in _OPTIONAL_FIELDS:
                        if field in rt and rt[field] not in (None, "", []):
                            rule[field] = rt[field]
                    # ADE requires these scalar fields to be non-null (its DTO
                    # mapper calls fragment.equalsIgnoreCase(...)), so always
                    # provide a safe default even when the user left them blank.
                    rule.setdefault("fragment", "none")
                    rule.setdefault("action", "allow")
                    rule["status"] = "success"
                    out.append(rule)
    return out

