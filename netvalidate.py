"""Strict IPv4/IPv6 network validation shared across the simulator.

Every network the user supplies (destination or source) must be written in
CIDR notation, i.e. an IPv4 or IPv6 address *with a subnet mask*:

    1.1.1.1/32          (single IPv4 host)
    10.0.0.0/8          (IPv4 subnet)
    2001:db8::/48       (IPv6 subnet)
    2001:db8::1/128     (single IPv6 host)

A value without a ``/prefix`` (e.g. ``1.1.1.1``) or an invalid address/prefix
(e.g. ``1.1.1.1/33`` or ``999.1.1.1/32``) is rejected with a clear message so
the caller can surface it to the user.
"""
from __future__ import annotations

import ipaddress

_EXAMPLE = "e.g. 1.1.1.1/32 (IPv4) or 2001:db8::/48 (IPv6)"


def validate_cidr(value: object, *, field: str = "network") -> str:
    """Validate a CIDR string. Return the trimmed original on success.

    Raises ``ValueError`` with a human-readable message on any problem. The
    original text is returned (not normalized) so downstream exact-match logic
    keeps working with the value the user actually typed.
    """
    if value is None:
        raise ValueError(f"{field} is required ({_EXAMPLE}).")
    s = str(value).strip()
    if not s:
        raise ValueError(f"{field} is required ({_EXAMPLE}).")
    if "/" not in s:
        # Guess a sensible host mask for the hint (/32 for v4, /128 for v6).
        mask = "128" if ":" in s else "32"
        raise ValueError(
            f"{field} '{s}' must include a subnet mask, {_EXAMPLE}. "
            f"Did you mean {s}/{mask}?"
        )
    try:
        net = ipaddress.ip_network(s, strict=False)
    except ValueError as exc:
        raise ValueError(f"{field} '{s}' is not a valid IPv4/IPv6 subnet: {exc}.")
    # ip_network accepts the value; make sure the prefix is in range (it is,
    # by construction) and hand back the original text.
    _ = net
    return s


def parse_network(value: object, *, field: str = "network") -> ipaddress._BaseNetwork:
    """Validate and return the parsed ``ip_network`` (host bits allowed)."""
    validate_cidr(value, field=field)
    return ipaddress.ip_network(str(value).strip(), strict=False)


def is_valid_cidr(value: object) -> bool:
    try:
        validate_cidr(value)
        return True
    except ValueError:
        return False

