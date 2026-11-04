"""Permanent, fixed attack-time mitigations keyed by destination network.

This is the attack-flow analog of ``permanent_responses.py``: for the
``.../attack/_getMitigation`` poll, some destination networks must always
return an exact, pre-defined mitigation (asnFilters / geolocationFilters /
trafficFilters), regardless of what the user has configured in the UI.

Permanent mitigations are matched BEFORE any user-created definition, so they
act as always-on pins. To add another one, add an entry to
``PERMANENT_MITIGATIONS`` with the destination network CIDR as the key.

The values below are taken verbatim from a real cloud ``_getMitigation``
response (see ``cloud response example.txt``), with the three ``trafficFilters``
``dst_ip`` values rewritten to host IPs inside the pinned asset
``10.10.10.0/24`` (``10.10.10.41`` / ``10.10.10.42`` / ``10.10.10.40``). The
original ``filterHashCode`` / ``applied`` values are preserved verbatim.
"""
from __future__ import annotations

import copy
from typing import Any

PERMANENT_MITIGATIONS: dict[str, dict[str, Any]] = {
    "10.10.10.0/24": {
        "name": "Permanent mitigation 10.10.10.0/24",
        "enabled": True,
        "networks": ["10.10.10.0/24"],
        # Static (full mitigation every poll), still partially mitigated like
        # the source cloud response.
        "progressive": False,
        "isPartialMitigated": True,
        "asnFilters": [
            {
                "asn": "139007",
                "attackBlockagePercentage": {"bps": 8.0, "pps": 2.0},
                "filterHashCode": 1454678341,
                "applied": False,
                "organization": "UNICOM InnerMongolia province network",
            },
            {
                "asn": "2018",
                "attackBlockagePercentage": {"bps": 14.0, "pps": 4.0},
                "filterHashCode": 4541866,
                "applied": False,
                "organization": "TENET (The UNINET Project)",
            },
            {
                "asn": "213541",
                "attackBlockagePercentage": {"bps": 10.0, "pps": 3.0},
                "filterHashCode": 1481286627,
                "applied": False,
                "organization": "WS Telecom Inc",
            },
            {
                "asn": "23969",
                "attackBlockagePercentage": {"bps": 12.0, "pps": 4.0},
                "filterHashCode": 50756512,
                "applied": False,
                "organization": "TOT Public Company Limited",
            },
            {
                "asn": "45528",
                "attackBlockagePercentage": {"bps": 10.0, "pps": 3.0},
                "filterHashCode": 52659167,
                "applied": False,
                "organization": "Tikona Infinet Ltd.",
            },
            {
                "asn": "5524",
                "attackBlockagePercentage": {"bps": 14.0, "pps": 4.0},
                "filterHashCode": 4636071,
                "applied": False,
                "organization": "Signet B.V.",
            },
        ],
        "geolocationFilters": [
            {
                "country": "CN",
                "attackBlockagePercentage": 8.0,
                "filterHashCode": -372005034,
                "applied": False,
                "countryName": "China",
            },
            {
                "country": "MY",
                "attackBlockagePercentage": 10.0,
                "filterHashCode": -372004713,
                "applied": False,
                "countryName": "Malaysia",
            },
            {
                "country": "NL",
                "attackBlockagePercentage": 14.0,
                "filterHashCode": -372004695,
                "applied": False,
                "countryName": "Netherlands",
            },
            {
                "country": "TH",
                "attackBlockagePercentage": 12.0,
                "filterHashCode": -372004513,
                "applied": False,
                "countryName": "Thailand",
            },
            {
                "country": "ZA",
                "attackBlockagePercentage": 14.0,
                "filterHashCode": -372004334,
                "applied": False,
                "countryName": "South Africa",
            },
        ],
        "trafficFilters": [
            {
                "priority": 0,
                "attackBlockagePercentage": {"bps": 30.0, "pps": 9.0},
                "filterCriteria": {
                    "src_ip": "",
                    "src_port": "34781",
                    "dst_ip": "10.10.10.41",
                    "dst_port": "555",
                    "protocol": "UDP",
                    "protocol_id": "17",
                    "tcp_flags": "",
                    "packet_size": "",
                    "fragmented": False,
                },
                "actionParameters": {
                    "threshold_trigger": 0,
                    "threshold_units": "kbps",
                    "tracking_mode": "All",
                },
                "filterMode": "Matching Traffic",
                "filterHashCode": -35134031,
                "applied": False,
            },
            {
                "priority": 0,
                "attackBlockagePercentage": {"bps": 25.0, "pps": 8.0},
                "filterCriteria": {
                    "src_ip": "",
                    "src_port": "34781",
                    "dst_ip": "10.10.10.42",
                    "dst_port": "555",
                    "protocol": "UDP",
                    "protocol_id": "17",
                    "tcp_flags": "",
                    "packet_size": "",
                    "fragmented": False,
                },
                "actionParameters": {
                    "threshold_trigger": 0,
                    "threshold_units": "kbps",
                    "tracking_mode": "All",
                },
                "filterMode": "Matching Traffic",
                "filterHashCode": 1318175666,
                "applied": False,
            },
            {
                "priority": 0,
                "attackBlockagePercentage": {"bps": 24.0, "pps": 8.0},
                "filterCriteria": {
                    "src_ip": "",
                    "src_port": "34781",
                    "dst_ip": "10.10.10.40",
                    "dst_port": "555",
                    "protocol": "UDP",
                    "protocol_id": "17",
                    "tcp_flags": "",
                    "packet_size": "",
                    "fragmented": False,
                },
                "actionParameters": {
                    "threshold_trigger": 0,
                    "threshold_units": "kbps",
                    "tracking_mode": "All",
                },
                "filterMode": "Matching Traffic",
                "filterHashCode": -1388443728,
                "applied": False,
            },
        ],
    },
}


def permanent_mitigation_for(networks: list[str]) -> dict[str, Any] | None:
    """Return a deep copy of the permanent mitigation for the first requested
    network that has one pinned, or None when none apply."""
    for net in networks:
        m = PERMANENT_MITIGATIONS.get(net)
        if m is not None:
            pinned = copy.deepcopy(m)
            pinned["id"] = f"permanent:{net}"
            return pinned
    return None

