"""Scale-test recommendation generator.

Produces a large number of *unique* recommendations for a destination network,
for load/scale testing the Cyber Controller -> ADE pipeline.

Four generation modes control how the varying IP address is produced:

    "dst-seq"  : the DESTINATION IP increments sequentially through the
                 destination network; the source is fixed (optional).
    "dst-rand" : the DESTINATION IP is drawn at random (without replacement)
                 from the destination network; the source is fixed (optional).
    "src-seq"  : the SOURCE IP increments sequentially through the source
                 network; the destination is fixed (the destination network).
    "src-rand" : the SOURCE IP is drawn at random (without replacement) from
                 the source network; the destination is fixed.

Guarantees
----------
* No duplicate recommendations - the varying IP is distinct for every rule
  (sequential ranges are inherently distinct; random uses sampling without
  replacement).
* The Rule ID is ALWAYS randomly generated (``secrets.token_hex``), never
  derived from the inputs, so IDs never collide with previously issued ones.
* Rules are produced lazily by a generator, so arbitrarily large sets can be
  streamed to disk/clients without materializing them all in memory.
"""
from __future__ import annotations

import ipaddress
import random
import secrets
from typing import Any, Iterator

import netvalidate

MODES = ("dst-seq", "dst-rand", "src-seq", "src-rand")
_DST_MODES = ("dst-seq", "dst-rand")
_SRC_MODES = ("src-seq", "src-rand")
# Above this capacity we cannot call random.sample(range(n), k) because
# len(range(n)) overflows a C ssize_t; fall back to rejection sampling instead.
_SAMPLE_RANGE_LIMIT = 1 << 31


def _rand_rule_id() -> str:
    """A fresh, random Rule ID (never derived from the request)."""
    return "rule_" + secrets.token_hex(32)


def capacity(base: str, host_prefix: int) -> int:
    """How many distinct /host_prefix blocks fit inside ``base``."""
    net = ipaddress.ip_network(base, strict=False)
    if host_prefix < net.prefixlen or host_prefix > net.max_prefixlen:
        return 0
    return 1 << (host_prefix - net.prefixlen)


def _block(net: ipaddress._BaseNetwork, host_prefix: int, index: int) -> str:
    """Return the ``index``-th /host_prefix block of ``net`` as a CIDR string."""
    step = 1 << (net.max_prefixlen - host_prefix)
    addr = ipaddress.ip_address(int(net.network_address) + index * step)
    return f"{addr}/{host_prefix}"


def build_spec(
    *,
    destination_network: str,
    count: int,
    mode: str = "dst-seq",
    source_network: str | None = None,
    host_prefix: int | None = None,
    protocol: list[str] | None = None,
    source_ports: list[str] | None = None,
    destination_ports: list[str] | None = None,
    action: str = "allow",
    max_count: int | None = None,
) -> dict[str, Any]:
    """Validate inputs and return a normalized, ready-to-expand spec.

    Raises ``ValueError`` with a clear message on any invalid input.
    """
    if mode not in MODES:
        raise ValueError(f"mode must be one of {', '.join(MODES)} (got '{mode}').")
    if not isinstance(count, int) or count < 1:
        raise ValueError("count must be a positive integer (at least 1).")
    if max_count is not None and count > max_count:
        raise ValueError(
            f"count {count} exceeds the maximum of {max_count}. "
            f"Reduce the count or use the streaming download for larger sets."
        )

    # Destination is always required and must be a CIDR (IPv4 or IPv6). It is
    # also the KEY a Cyber Controller matches on, so it is kept verbatim.
    dst = netvalidate.parse_network(destination_network, field="destination network")
    dst_str = netvalidate.validate_cidr(destination_network, field="destination network")

    src_str = ""
    src = None
    if mode in _SRC_MODES:
        if not source_network:
            raise ValueError(
                f"source network is required for mode '{mode}' (e.g. 10.0.0.0/8)."
            )
        src = netvalidate.parse_network(source_network, field="source network")
        src_str = netvalidate.validate_cidr(source_network, field="source network")
    elif source_network:
        # Optional fixed source for destination-varying modes.
        src = netvalidate.parse_network(source_network, field="source network")
        src_str = netvalidate.validate_cidr(source_network, field="source network")

    # The address family being incremented/sampled determines the host mask.
    vary = dst if mode in _DST_MODES else src
    if host_prefix is None:
        host_prefix = vary.max_prefixlen
    if not (vary.prefixlen <= host_prefix <= vary.max_prefixlen):
        raise ValueError(
            f"host prefix /{host_prefix} is invalid for {vary} "
            f"(must be between /{vary.prefixlen} and /{vary.max_prefixlen})."
        )

    cap = capacity(str(vary), host_prefix)
    if count > cap:
        axis = "destination" if mode in _DST_MODES else "source"
        raise ValueError(
            f"count {count} exceeds the {cap} available /{host_prefix} "
            f"addresses in the {axis} network {vary}. "
            f"Enlarge the {axis} network or lower the count."
        )

    return {
        "mode": mode,
        "count": count,
        "host_prefix": host_prefix,
        "destination_network": dst_str,
        "source_network": src_str,          # "" when no fixed source
        "protocol": list(protocol) if protocol else ["6", "17"],
        "source_ports": list(source_ports) if source_ports else [],
        "destination_ports": list(destination_ports) if destination_ports else [],
        "action": action or "allow",
        "capacity": cap,
        "seed": secrets.randbits(64),
    }


def _rule(source: list[str], destination: list[str], spec: dict[str, Any]) -> dict[str, Any]:
    return {
        "ruleId": _rand_rule_id(),
        "sourceIPs": source,
        "destinationIPs": destination,
        "sourcePorts": list(spec["source_ports"]),
        "destinationPorts": list(spec["destination_ports"]),
        "protocol": list(spec["protocol"]),
        "tcpFlags": [],
        "packetSize": [],
        "ttl": [],
        "fragment": "none",
        "sourceGeo": [],
        "sourceASN": [],
        "action": spec["action"],
        "status": "success",
    }


def _random_indices(cap: int, count: int, seed: int) -> Iterator[int]:
    rng = random.Random(seed)
    if cap <= _SAMPLE_RANGE_LIMIT:
        yield from rng.sample(range(cap), count)
    else:
        # Rejection sampling for astronomically large (typically IPv6) spaces,
        # where count << cap so collisions are rare.
        seen: set[int] = set()
        while len(seen) < count:
            n = rng.randrange(cap)
            if n not in seen:
                seen.add(n)
                yield n


def iter_rules(spec: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Yield ``spec['count']`` unique rules according to the spec's mode."""
    mode = spec["mode"]
    count = spec["count"]
    hp = spec["host_prefix"]
    dst_net = ipaddress.ip_network(spec["destination_network"], strict=False)
    src_fixed = [spec["source_network"]] if spec["source_network"] else []

    if mode == "dst-seq":
        for i in range(count):
            yield _rule(list(src_fixed), [_block(dst_net, hp, i)], spec)
    elif mode == "dst-rand":
        for i in _random_indices(spec["capacity"], count, spec["seed"]):
            yield _rule(list(src_fixed), [_block(dst_net, hp, i)], spec)
    else:
        # source-varying modes: destination fixed to the destination network
        src_net = ipaddress.ip_network(spec["source_network"], strict=False)
        dst_fixed = [spec["destination_network"]]
        if mode == "src-seq":
            for i in range(count):
                yield _rule([_block(src_net, hp, i)], list(dst_fixed), spec)
        else:  # src-rand
            for i in _random_indices(spec["capacity"], count, spec["seed"]):
                yield _rule([_block(src_net, hp, i)], list(dst_fixed), spec)


def sample_rules(spec: dict[str, Any], n: int = 5) -> list[dict[str, Any]]:
    """Return the first ``n`` rules for a preview (does not build the full set)."""
    out: list[dict[str, Any]] = []
    for rule in iter_rules(spec):
        out.append(rule)
        if len(out) >= n:
            break
    return out



