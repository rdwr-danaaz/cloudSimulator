"""Editable recommendation template shared by all Cyber Controllers.

Tab 2 of the UI edits a single, global *recommendation template*. On every
`_getRecommendation` request the template is expanded into concrete rules where:

  * ``destinationIPs`` is ALWAYS overwritten with the network(s) from the
    incoming request (the "dst network must match the request" requirement).
  * every other field (protocol, ttl, ports, geo, asn, ...) is OPTIONAL — it is
    only included in the emitted rule if the template rule actually sets it.

Because the template is global and the destination is derived per-request, many
Cyber Controllers can hit the same simulator simultaneously and each still gets
rules whose destination matches its own request.

The template is persisted to ``data/response_template.json`` so it survives
restarts and is shared across all callers.
"""
from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path
from typing import Any

_DATA_DIR = Path(__file__).parent / "data"
_TEMPLATE_FILE = _DATA_DIR / "response_template.json"
_LOCK = threading.Lock()

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

# A sensible starter template: one permissive rule. Users edit this in the UI.
_DEFAULT_TEMPLATE: dict[str, Any] = {
    "enabled": False,
    "rules": [
        {
            "protocol": ["6", "17"],
            "action": "allow",
        }
    ],
}


def _rule_id(network: str, index: int) -> str:
    return "rule_" + hashlib.sha256(f"{network}:{index}".encode()).hexdigest()


# In-memory copy, loaded once and kept in sync with disk.
_template: dict[str, Any] = json.loads(json.dumps(_DEFAULT_TEMPLATE))


def _load() -> None:
    global _template
    if _TEMPLATE_FILE.exists():
        try:
            _template = json.loads(_TEMPLATE_FILE.read_text(encoding="utf-8"))
        except Exception as exc:  # pragma: no cover - corrupt file fallback
            print(f"[template] WARNING: could not read {_TEMPLATE_FILE}: {exc}")


_load()


def get_template() -> dict[str, Any]:
    """Return a copy of the current recommendation template."""
    with _LOCK:
        return json.loads(json.dumps(_template))


def set_template(data: dict[str, Any]) -> dict[str, Any]:
    """Validate, persist and activate a new recommendation template.

    Raises ValueError if the structure is invalid.
    """
    if not isinstance(data, dict):
        raise ValueError("template must be a JSON object")
    rules = data.get("rules")
    if not isinstance(rules, list) or not rules:
        raise ValueError("template must contain a non-empty 'rules' list")
    for i, r in enumerate(rules):
        if not isinstance(r, dict):
            raise ValueError(f"rule #{i} must be a JSON object")
    normalized = {
        "enabled": bool(data.get("enabled", True)),
        "rules": rules,
    }
    with _LOCK:
        global _template
        _template = normalized
        _DATA_DIR.mkdir(parents=True, exist_ok=True)
        _TEMPLATE_FILE.write_text(
            json.dumps(normalized, indent=2), encoding="utf-8"
        )
    return json.loads(json.dumps(normalized))


def is_enabled() -> bool:
    with _LOCK:
        return bool(_template.get("enabled")) and bool(_template.get("rules"))


def build_rules(networks: list[str]) -> list[dict[str, Any]]:
    """Expand the template into rules for the requested networks.

    destinationIPs is forced to each requested network; all other fields are
    copied only when present in the template rule.
    """
    with _LOCK:
        rules_tpl = list(_template.get("rules", []))
    out: list[dict[str, Any]] = []
    for net in networks:
        for i, rt in enumerate(rules_tpl):
            rule: dict[str, Any] = {
                "ruleId": rt.get("ruleId") or _rule_id(net, i),
                # dst network ALWAYS matches the incoming request
                "destinationIPs": [net],
            }
            for field in _OPTIONAL_FIELDS:
                if field in rt and rt[field] not in (None, "", []):
                    rule[field] = rt[field]
            # ADE requires these scalar fields to be non-null (its DTO mapper
            # calls fragment.equalsIgnoreCase(...)), so always provide a safe
            # default even when the user left them blank.
            rule.setdefault("fragment", "none")
            rule.setdefault("action", "allow")
            rule["status"] = "success"
            out.append(rule)
    return out


