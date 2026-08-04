"""Self-contained CI test suite for the SOC-X recommendation simulator.

These tests intentionally do NOT depend on any files in ``recommendations/``
(which are machine/customer specific and not committed), so they run
deterministically in CI on a fresh clone.
"""
from datetime import datetime

import pytest
from fastapi.testclient import TestClient

from cloud_mock_server import app, rules_store, generation_config
from permanent_responses import PERMANENT_NETWORK_RULES
import response_template

client = TestClient(app)

ENDPOINT = "/api/sdcc/genai/core/analysis/peacetime/_getRecommendation"
_DEFAULT_N = 3


@pytest.fixture(autouse=True)
def reset_state():
    """Restore default generation config and a clean seed store around each test."""
    saved = dict(generation_config)
    generation_config.update({
        "rules_per_network": _DEFAULT_N, "sourceIPs": [], "sourcePorts": [],
        "destinationPorts": [], "protocols": ["6", "17"], "tcpFlags": [],
        "packetSize": ["128"], "sourceGeo": ["US"], "sourceASN": ["7018"],
        "fragment": "none", "action": "allow"})
    # Ensure the recommendation template is disabled by default so the
    # generation/permanent tests are deterministic regardless of any persisted
    # data/response_template.json on disk.
    response_template.set_template({"enabled": False, "rules": [{"action": "allow"}]})
    yield
    generation_config.clear()
    generation_config.update(saved)
    rules_store.clear()


def _post(tag, networks):
    return client.post(ENDPOINT, json={"tag": tag, "networks": networks})


# --- health / basic contract -------------------------------------------------

def test_health():
    assert client.get("/health").json() == {"status": "ok"}


def test_response_structure():
    body = _post("any", ["10.0.0.0/8"]).json()
    assert set(body.keys()) == {"account_id", "rules", "metadata", "timestamp"}
    assert set(body["rules"][0].keys()) == {
        "ruleId", "sourceIPs", "destinationIPs", "sourcePorts", "destinationPorts",
        "protocol", "tcpFlags", "packetSize", "fragment", "sourceGeo", "sourceASN",
        "action", "status"}


# --- pinned / permanent networks --------------------------------------------

@pytest.mark.parametrize("network", sorted(PERMANENT_NETWORK_RULES))
def test_permanent_networks_return_pinned_rules(network):
    expected = PERMANENT_NETWORK_RULES[network]
    body = _post("whatever-tag", [network]).json()
    # Pinned rules are returned verbatim, regardless of the request tag.
    assert body["rules"] == expected
    assert all(r["status"] == "success" for r in body["rules"])


# --- auto-generation ---------------------------------------------------------

def test_unknown_tag_generates_rules():
    networks = ["192.168.1.0/24", "10.168.2.1/32"]
    body = _post("brand-new-tag", networks).json()
    assert body["rules"]
    dests = {ip for r in body["rules"] for ip in r["destinationIPs"]}
    assert dests <= set(networks)


def test_rules_per_network_count():
    networks = ["10.0.0.0/8", "192.168.1.0/24"]
    assert len(_post("gen", networks).json()["rules"]) == _DEFAULT_N * 2


def test_configurable_count_and_protocol():
    client.post("/ui/config", json={"rules_per_network": 5, "protocols": ["17"]})
    body = _post("cfg", ["10.0.0.0/8"]).json()
    assert len(body["rules"]) == 5
    assert all(r["protocol"] == ["17"] for r in body["rules"])


def test_custom_geo_asn():
    client.post("/ui/config", json={
        "rules_per_network": 2, "sourceGeo": ["IL"], "sourceASN": ["1234"],
        "protocols": ["6"]})
    for rule in _post("geo", ["172.16.0.0/12"]).json()["rules"]:
        assert rule["sourceGeo"] == ["IL"]
        assert rule["sourceASN"] == ["1234"]


# --- metadata / timing -------------------------------------------------------

def test_interval_is_3h_block():
    iv = _post("gen", ["10.0.0.0/8"]).json()["metadata"]["interval"]
    s = datetime.strptime(iv["start_time"], "%Y-%m-%dT%H:%M:%SZ")
    e = datetime.strptime(iv["end_time"], "%Y-%m-%dT%H:%M:%SZ")
    assert s.hour % 3 == 0 and s.minute == 0
    assert int((e - s).total_seconds()) == 3 * 3600 - 1


def test_timestamp_format():
    ts = _post("gen", ["10.0.0.0/8"]).json()["timestamp"]
    datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ")


# --- seed / admin ------------------------------------------------------------

def test_seed_overrides_generation():
    client.post("/admin/seed", json={
        "tag": "seed-tag",
        "rules": [{"ruleId": "rule_test", "destinationIPs": ["1.2.3.4/32"]}]})
    body = _post("seed-tag", ["1.2.3.4/32"]).json()
    assert body["rules"][0]["ruleId"] == "rule_test"


def test_seed_and_clear():
    client.post("/admin/seed", json={"tag": "tmp", "rules": []})
    assert "tmp" in rules_store
    assert client.delete("/admin/seed/tmp").status_code == 200
    assert "tmp" not in rules_store


def test_clear_missing_returns_404():
    assert client.delete("/admin/seed/no-such-tag").status_code == 404


# --- validation --------------------------------------------------------------

def test_missing_tag_422():
    assert client.post(ENDPOINT, json={"networks": ["10.0.0.0/8"]}).status_code == 422


def test_empty_networks_422():
    assert client.post(ENDPOINT, json={"tag": "t", "networks": []}).status_code == 422


# --- recommendation template (Tab 2) ----------------------------------------

def _disable_template():
    client.post("/ui/template", json={"enabled": False, "rules": [{"action": "allow"}]})


def test_template_dst_always_matches_request():
    # Only 'protocol' + 'ttl' set; destination must be forced to the request net.
    client.post("/ui/template", json={
        "enabled": True,
        "rules": [{"protocol": ["6"], "ttl": ["64"]}]})
    try:
        body = _post("some-tag", ["203.0.113.0/24"]).json()
        assert len(body["rules"]) == 1
        rule = body["rules"][0]
        assert rule["destinationIPs"] == ["203.0.113.0/24"]
        assert rule["protocol"] == ["6"]
        assert rule["ttl"] == ["64"]
        # optional list fields not provided must be absent (not mandatory)
        assert "sourceGeo" not in rule
        assert "packetSize" not in rule
        # ADE requires non-null fragment/action, so they always get safe defaults
        assert rule["fragment"] == "none"
        assert rule["action"] == "allow"
        assert rule["status"] == "success"
    finally:
        _disable_template()


def test_template_multiple_networks_and_rules():
    client.post("/ui/template", json={
        "enabled": True,
        "rules": [{"action": "allow"}, {"action": "block"}]})
    try:
        nets = ["10.1.0.0/24", "10.2.0.0/24"]
        body = _post("t", nets).json()
        assert len(body["rules"]) == 4  # 2 rules x 2 networks
        dests = {ip for r in body["rules"] for ip in r["destinationIPs"]}
        assert dests == set(nets)
    finally:
        _disable_template()


def test_template_disabled_falls_back_to_generation():
    client.post("/ui/template", json={"enabled": False, "rules": [{"action": "allow"}]})
    body = _post("gen", ["10.0.0.0/8"]).json()
    # Falls back to auto-generation default shape (has all fixed keys).
    assert set(body["rules"][0].keys()) >= {"sourceIPs", "protocol", "fragment"}


def test_template_preview_does_not_persist():
    d = client.post("/ui/template/preview", json={
        "networks": ["198.51.100.0/24"],
        "rules": [{"protocol": ["17"]}]}).json()
    assert d["rules"][0]["destinationIPs"] == ["198.51.100.0/24"]
    assert d["rules"][0]["protocol"] == ["17"]


def test_template_requires_rules():
    assert client.post("/ui/template", json={"enabled": True, "rules": []}).status_code == 400


# --- Cyber Controller registry (Tab 1) --------------------------------------

def test_cc_list_endpoint():
    assert isinstance(client.get("/ui/cc").json(), list)


def test_cc_delete_unknown_404():
    assert client.delete("/ui/cc/no-such-host").status_code == 404


def test_cc_reset_unreachable_returns_ok_false():
    # Reset against a closed port should fail gracefully (ok False) with a log,
    # not raise. Port 1 on localhost refuses immediately (fast, deterministic).
    r = client.post("/ui/cc/reset", json={
        "cc_host": "127.0.0.1", "ssh_user": "root",
        "ssh_pass": "x", "ssh_port": 1})
    body = r.json()
    assert r.status_code == 200
    assert body["ok"] is False
    assert any("SSH connection failed" in line for line in body["log"])


# --- UI page -----------------------------------------------------------------

def test_ui_page_served():
    r = client.get("/ui")
    assert r.status_code == 200
    assert "Cyber Controller" in r.text
    assert "Recommendation" in r.text


def test_siminfo_reports_address_and_version():
    d = client.get("/ui/siminfo").json()
    assert "version" in d
    assert "suggested_sim_hostport" in d


def test_configure_without_address_uses_host_header():
    # No sim_hostport supplied; server should derive it and still attempt SSH,
    # failing gracefully (ok False) rather than 400 for a missing address.
    r = client.post("/ui/cc/configure", json={
        "cc_host": "127.0.0.1", "ssh_user": "root", "ssh_pass": "x",
        "ssh_port": 1}, headers={"host": "sim.example:8080"})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False







