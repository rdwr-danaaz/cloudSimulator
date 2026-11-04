"""Dedicated attack-mitigation definitions for the Remediation Recommendations
tab (the attack-time flow), kept SEPARATE from the peacetime recommendation
templates in ``response_template.py``.

Peacetime vs attack-time
------------------------
* Peacetime (``response_template.py`` / Tab 2): a Cyber Controller sends ONE
  ``_getRecommendation`` request and gets a list of traffic ``rules``.
* Attack-time (this module / the new tab): when an attack starts the CC calls
  ``_initiateAttackAnalysis`` to open an attack session, then polls
  ``_getMitigation`` repeatedly (~every 15s) for an evolving mitigation, and
  finally calls ``_closeAttack`` when the attack ends.

A *mitigation definition* says WHAT mitigation to return for an attack on a
given destination network. Each definition carries:
  * ``geolocationFilters`` - per-country blockage filters
  * ``trafficFilters``     - L3/L4 traffic filters (the bulk of a mitigation)
  * ``progressive``        - when true the mitigation is revealed gradually over
    successive polls (simulating the AI "learning" while the attack is ongoing);
    when false the full mitigation is returned on every poll (static).
  * ``progressivePolls``   - how many polls it takes a progressive definition to
    reach full mitigation.

Definitions are matched to an attack by destination network (exact match, or a
catch-all definition with an empty ``networks`` list). The collection is
persisted to ``data/attack_mitigations.json`` so it survives restarts.
"""
from __future__ import annotations
import hashlib
import json
import math
import threading
import uuid
from typing import Any
from pathlib import Path

import permanent_mitigations

_DATA_DIR = Path(__file__).parent / "data"
_FILE = _DATA_DIR / "attack_mitigations.json"
_LOCK = threading.RLock()

# In-memory collection, loaded once and kept in sync with disk.
_defs: list[dict[str, Any]] = []


def _new_id(existing: set[str]) -> str:
    did = uuid.uuid4().hex
    while did in existing:
        did = uuid.uuid4().hex
    return did


def _filter_hash(obj: Any) -> int:
    """Stable, process-independent hash code for a filter (so the same filter
    always reports the same ``filterHashCode``, like the real cloud)."""
    blob = json.dumps(obj, sort_keys=True, default=str).encode()
    return int(hashlib.sha256(blob).hexdigest()[:8], 16)


def _coerce(raw: dict[str, Any], fallback_id: str | None = None) -> dict[str, Any]:
    """Normalize an arbitrary dict into a well-formed definition record."""
    did = str(raw.get("id") or fallback_id or "").strip()
    networks = raw.get("networks")
    if not isinstance(networks, list):
        networks = []
    networks = [str(n).strip() for n in networks if str(n).strip()]
    asn = raw.get("asnFilters")
    if not isinstance(asn, list):
        asn = []
    geo = raw.get("geolocationFilters")
    if not isinstance(geo, list):
        geo = []
    traffic = raw.get("trafficFilters")
    if not isinstance(traffic, list):
        traffic = []
    name = str(raw.get("name") or "").strip()
    try:
        polls = int(raw.get("progressivePolls") or 3)
    except (TypeError, ValueError):
        polls = 3
    polls = max(1, polls)
    return {
        "id": did,
        "name": name or "Mitigation",
        "enabled": bool(raw.get("enabled", True)),
        "networks": networks,
        "isPartialMitigated": bool(raw.get("isPartialMitigated", False)),
        "progressive": bool(raw.get("progressive", False)),
        "progressivePolls": polls,
        "asnFilters": [a for a in asn if isinstance(a, dict)],
        "geolocationFilters": [g for g in geo if isinstance(g, dict)],
        "trafficFilters": [t for t in traffic if isinstance(t, dict)],
    }


def _load() -> None:
    global _defs
    if not _FILE.exists():
        return
    try:
        data = json.loads(_FILE.read_text(encoding="utf-8"))
    except Exception as exc:  # pragma: no cover - corrupt file fallback
        print(f"[attack_mitigation] WARNING: could not read {_FILE}: {exc}")
        return
    items = data.get("mitigations") if isinstance(data, dict) else None
    if not isinstance(items, list):
        return
    seen: set[str] = set()
    loaded: list[dict[str, Any]] = []
    for entry in items:
        if not isinstance(entry, dict):
            continue
        d = _coerce(entry)
        if not d["id"] or d["id"] in seen:
            d["id"] = _new_id(seen)
        seen.add(d["id"])
        loaded.append(d)
    _defs = loaded


_load()


def _persist_locked() -> None:
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    _FILE.write_text(json.dumps({"mitigations": _defs}, indent=2), encoding="utf-8")


def _find_locked(def_id: str) -> dict[str, Any] | None:
    for d in _defs:
        if d["id"] == def_id:
            return d
    return None


# --------------------------------------------------------------------------- #
# CRUD API (used by the UI tab)
# --------------------------------------------------------------------------- #
def list_mitigations() -> list[dict[str, Any]]:
    with _LOCK:
        return json.loads(json.dumps(_defs))


def get_mitigation(def_id: str) -> dict[str, Any] | None:
    with _LOCK:
        d = _find_locked(def_id)
        return json.loads(json.dumps(d)) if d else None


def _validate(data: dict[str, Any]) -> None:
    if not isinstance(data, dict):
        raise ValueError("mitigation must be a JSON object")
    asn = data.get("asnFilters") or []
    geo = data.get("geolocationFilters") or []
    traffic = data.get("trafficFilters") or []
    if not isinstance(asn, list) or not isinstance(geo, list) or not isinstance(traffic, list):
        raise ValueError("asnFilters, geolocationFilters and trafficFilters must be lists")
    if not asn and not geo and not traffic:
        raise ValueError("a mitigation needs at least one ASN, geolocation or traffic filter")


def add_mitigation(data: dict[str, Any]) -> dict[str, Any]:
    _validate(data)
    with _LOCK:
        existing = {d["id"] for d in _defs}
        record = _coerce(data)
        record["id"] = _new_id(existing)
        if not record["name"] or record["name"] == "Mitigation":
            record["name"] = f"Mitigation {len(_defs) + 1}"
        _defs.append(record)
        _persist_locked()
        return json.loads(json.dumps(record))


def update_mitigation(def_id: str, data: dict[str, Any]) -> dict[str, Any]:
    _validate(data)
    with _LOCK:
        d = _find_locked(def_id)
        if d is None:
            raise KeyError(def_id)
        updated = _coerce(data, fallback_id=def_id)
        updated["id"] = def_id  # id is immutable
        d.clear()
        d.update(updated)
        _persist_locked()
        return json.loads(json.dumps(d))


def delete_mitigation(def_id: str) -> bool:
    with _LOCK:
        before = len(_defs)
        _defs[:] = [d for d in _defs if d["id"] != def_id]
        removed = len(_defs) != before
        if removed:
            _persist_locked()
        return removed


# --------------------------------------------------------------------------- #
# Attack-time matching + response building
# --------------------------------------------------------------------------- #
def match_definition(networks: list[str]) -> dict[str, Any] | None:
    """Return the enabled definition that applies to an attack on ``networks``.

    Priority: a permanent (always-on) mitigation pinned to a network wins over
    everything; then an exact user-defined network match; then a catch-all
    (empty ``networks``) user definition. Returns a deep copy, or None.
    """
    pinned = permanent_mitigations.permanent_mitigation_for(networks)
    if pinned is not None:
        return _coerce(pinned, fallback_id=pinned.get("id"))
    with _LOCK:
        exact: dict[str, Any] | None = None
        catch_all: dict[str, Any] | None = None
        for d in _defs:
            if not d.get("enabled"):
                continue
            nets = d.get("networks") or []
            if not nets:
                catch_all = catch_all or d
            elif any(n in nets for n in networks):
                exact = exact or d
        chosen = exact or catch_all
        return json.loads(json.dumps(chosen)) if chosen else None


def _enrich_filters(
    items: list[dict[str, Any]],
    *,
    applied: bool | None,
    seed: str = "",
) -> list[dict[str, Any]]:
    """Add a ``filterHashCode`` and (optionally) force ``applied`` on each filter,
    returning fresh copies.

    When ``seed`` (the attack id) is given, the ``filterHashCode`` is derived from
    the filter content PLUS the seed, so every attack session produces DISTINCT
    hash codes for the same filter — even for the permanent mitigation whose
    filters carry a preset ``filterHashCode``. This is required because the Cyber
    Controller identifies remediation recommendations by ``filterHashCode``: if a
    new attack reused a previous (now-reverted) attack's hash codes, the CC would
    treat the filters as the already-removed old recommendations and never
    re-activate them ("Not Active - remediation filters were reverted..."). The
    hash stays stable across polls within the same attack (seed is constant per
    session), preserving filter identity while the attack is ongoing.
    """
    out: list[dict[str, Any]] = []
    for f in items:
        g = json.loads(json.dumps(f))
        if seed:
            base = {k: v for k, v in g.items() if k != "filterHashCode"}
            g["filterHashCode"] = _filter_hash([seed, base])
        else:
            g.setdefault("filterHashCode", _filter_hash(f))
        if applied is not None:
            g["applied"] = applied
        else:
            g.setdefault("applied", True)
        out.append(g)
    return out


def build_mitigation_response(
    defn: dict[str, Any] | None,
    *,
    poll_count: int,
    progressive: bool,
    account_id: str,
    attack_id: str,
    start_ts: str,
    now_ts: str,
) -> dict[str, Any]:
    """Build a ``_getMitigation`` response body from a matched definition.

    * ``progressive=False`` (static): every poll returns the full mitigation,
      with ``isPartialMitigated`` taken from the definition.
    * ``progressive=True``: filters are revealed gradually across polls (the AI
      "learning" during the attack). Early polls return few/no filters with
      ``isPartialMitigated=true``; once all filters are revealed it flips to
      ``false`` (fully mitigated).

    When no definition matches, an empty, still-learning mitigation is returned.

    ``start_ts`` / ``now_ts`` are ISO-8601 ``Z`` strings (the real cloud
    contract uses ISO timestamps for ``startTimestamp`` / ``endTimestamp``).
    """
    if defn is None:
        asn_out: list[dict[str, Any]] = []
        geo_out: list[dict[str, Any]] = []
        traffic_out: list[dict[str, Any]] = []
        partial = True
    else:
        asn = defn.get("asnFilters", [])
        geo = defn.get("geolocationFilters", [])
        traffic = defn.get("trafficFilters", [])
        if progressive:
            stages = max(1, int(defn.get("progressivePolls") or 3))
            frac = min(1.0, max(0, poll_count) / stages)
            na = math.ceil(len(asn) * frac)
            ng = math.ceil(len(geo) * frac)
            nt = math.ceil(len(traffic) * frac)
            asn_out = _enrich_filters(asn[:na], applied=True, seed=attack_id)
            geo_out = _enrich_filters(geo[:ng], applied=True, seed=attack_id)
            traffic_out = _enrich_filters(traffic[:nt], applied=True, seed=attack_id)
            partial = (
                (na < len(asn)) or (ng < len(geo)) or (nt < len(traffic))
                or poll_count < 1
            )
        else:
            asn_out = _enrich_filters(asn, applied=None, seed=attack_id)
            geo_out = _enrich_filters(geo, applied=None, seed=attack_id)
            traffic_out = _enrich_filters(traffic, applied=None, seed=attack_id)
            partial = bool(defn.get("isPartialMitigated", False))
    return {
        "accountId": account_id,
        "asnFilters": asn_out,
        "geolocationFilters": geo_out,
        "trafficFilters": traffic_out,
        "isPartialMitigated": partial,
        "id": 0,
        "type": "MITIGATION",
        "updated": False,
        "endTimestamp": now_ts,
        "startTimestamp": start_ts,
        "attackId": attack_id,
    }


def build_fully_mitigated_response(
    *,
    account_id: str,
    attack_id: str,
    start_ts: str,
    now_ts: str,
) -> dict[str, Any]:
    """The "fully mitigated" response the real cloud returns as an attack winds
    down: ``isPartialMitigated=false`` with empty asn/geo/traffic filter lists.

    The Cyber Controller treats a sustained run of these (≈2.5 min / ~10 polls in
    the reference log) as the signal that the attack is over, and only then calls
    ``_closeAttack``. Returning it for a few cycles before the session closes
    reproduces that real close-attack sequence.
    """
    return {
        "accountId": account_id,
        "asnFilters": [],
        "geolocationFilters": [],
        "trafficFilters": [],
        "isPartialMitigated": False,
        "id": 0,
        "type": "MITIGATION",
        "updated": False,
        "endTimestamp": now_ts,
        "startTimestamp": start_ts,
        "attackId": attack_id,
    }


