"""Self-contained CI test suite for the SOC-X recommendation simulator.

These tests intentionally do NOT depend on any files in ``recommendations/``
(which are machine/customer specific and not committed), so they run
deterministically in CI on a fresh clone.

Model under test
----------------
* A Cyber Controller sends ONLY the destination network(s); no tag.
* Recommendations are routed by the CALLING CC's IP (auto-detected, or an
  explicit ``cc_ip`` override for tests). Per requested network the order is:
  Permanent pin -> this CC's assigned set -> Template -> single 'learning' rule.
* No traffic rules are ever auto-generated.
"""
from datetime import datetime

import pytest
from fastapi.testclient import TestClient

from cloud_mock_server import app, cc_sets
from permanent_responses import PERMANENT_NETWORK_RULES
import response_template
import netvalidate

client = TestClient(app)

ENDPOINT = "/api/sdcc/genai/core/analysis/peacetime/_getRecommendation"

RULE_KEYS = {
    "ruleId", "sourceIPs", "destinationIPs", "sourcePorts", "destinationPorts",
    "protocol", "tcpFlags", "packetSize", "ttl", "fragment", "sourceGeo",
    "sourceASN", "action", "status",
}


@pytest.fixture(autouse=True)
def reset_state():
    """Disable the default template and clear all CC sets / named templates so
    each test starts from a clean, deterministic state."""
    response_template.set_template({"enabled": False, "rules": [{"action": "allow"}]})
    for _t in response_template.list_templates():
        if _t["id"] != "default":
            response_template.delete_template(_t["id"])
    cc_sets.clear()
    yield
    cc_sets.clear()
    for _t in response_template.list_templates():
        if _t["id"] != "default":
            response_template.delete_template(_t["id"])


def _post(networks, cc_ip=None):
    body = {"networks": networks}
    if cc_ip:
        body["cc_ip"] = cc_ip
    return client.post(ENDPOINT, json=body)


def _generate_for(cc_ip, destination_network, count=10, mode="dst-seq", **extra):
    payload = {"destination_network": destination_network, "count": count,
               "mode": mode, "cc_ip": cc_ip}
    payload.update(extra)
    return client.post("/ui/scale/generate", json=payload)


# --- health / basic contract -------------------------------------------------

def test_health():
    assert client.get("/health").json() == {"status": "ok"}


def test_response_structure():
    body = _post(["10.0.0.0/8"]).json()
    assert set(body.keys()) == {"account_id", "rules", "metadata", "timestamp"}
    assert set(body["rules"][0].keys()) == RULE_KEYS


# --- default 'learning' behavior (no auto-generation) ------------------------

def test_default_is_single_learning_rule():
    body = _post(["203.0.113.0/24"]).json()
    assert len(body["rules"]) == 1
    r = body["rules"][0]
    assert r["status"] == "learning"
    assert r["destinationIPs"] == ["203.0.113.0/24"]
    assert r["ruleId"].startswith("rule_")
    assert r["action"] == "allow"
    assert r["sourceIPs"] == []
    assert body["metadata"]["networks"][0]["status"] == "learning"


def test_learning_rule_id_is_random():
    a = _post(["203.0.113.0/24"]).json()["rules"][0]["ruleId"]
    b = _post(["203.0.113.0/24"]).json()["rules"][0]["ruleId"]
    assert a != b  # random each time


# --- pinned / permanent networks --------------------------------------------

@pytest.mark.parametrize("network", sorted(PERMANENT_NETWORK_RULES))
def test_permanent_networks_return_pinned_rules(network):
    expected = PERMANENT_NETWORK_RULES[network]
    body = _post([network]).json()
    assert body["rules"] == expected
    assert all(r["status"] == "success" for r in body["rules"])


# --- metadata / timing -------------------------------------------------------

def test_interval_is_3h_block():
    iv = _post(["10.0.0.0/8"]).json()["metadata"]["interval"]
    s = datetime.strptime(iv["start_time"], "%Y-%m-%dT%H:%M:%SZ")
    e = datetime.strptime(iv["end_time"], "%Y-%m-%dT%H:%M:%SZ")
    assert s.hour % 3 == 0 and s.minute == 0
    assert int((e - s).total_seconds()) == 3 * 3600 - 1


def test_timestamp_format():
    ts = _post(["10.0.0.0/8"]).json()["timestamp"]
    datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ")


# --- validation --------------------------------------------------------------

def test_empty_networks_422():
    assert client.post(ENDPOINT, json={"networks": []}).status_code == 422


def test_netvalidate_accepts_ipv4_and_ipv6_cidr():
    assert netvalidate.validate_cidr("1.1.1.1/32") == "1.1.1.1/32"
    assert netvalidate.validate_cidr("10.0.0.0/8") == "10.0.0.0/8"
    assert netvalidate.validate_cidr("2001:db8::/48") == "2001:db8::/48"
    assert netvalidate.validate_cidr("2001:db8::1/128") == "2001:db8::1/128"


@pytest.mark.parametrize("bad", [
    "1.1.1.1", "2001:db8::", "1.1.1.1/33", "2001:db8::/129",
    "999.1.1.1/32", "not-an-ip/24", "",
])
def test_netvalidate_rejects_bad_values(bad):
    with pytest.raises(ValueError):
        netvalidate.validate_cidr(bad)


def test_getrecommendation_requires_subnet():
    r = _post(["1.1.1.1"])
    assert r.status_code == 422
    assert "subnet" in r.json()["detail"].lower()


def test_getrecommendation_accepts_ipv6():
    r = _post(["2001:db8::/48"])
    assert r.status_code == 200
    assert r.json()["rules"]


def test_getrecommendation_rejects_bad_prefix():
    assert _post(["10.0.0.0/40"]).status_code == 422


# --- recommendation template (Tab 2) ----------------------------------------

def _disable_template():
    client.post("/ui/template", json={"enabled": False, "rules": [{"action": "allow"}]})


def test_template_dst_always_matches_request():
    client.post("/ui/template", json={
        "enabled": True,
        "rules": [{"protocol": ["6"], "ttl": ["64"]}]})
    try:
        body = _post(["203.0.113.0/24"]).json()
        assert len(body["rules"]) == 1
        rule = body["rules"][0]
        assert rule["destinationIPs"] == ["203.0.113.0/24"]
        assert rule["protocol"] == ["6"]
        assert rule["ttl"] == ["64"]
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
        body = _post(nets).json()
        assert len(body["rules"]) == 4  # 2 rules x 2 networks
        dests = {ip for r in body["rules"] for ip in r["destinationIPs"]}
        assert dests == set(nets)
    finally:
        _disable_template()


def test_template_disabled_falls_back_to_learning():
    client.post("/ui/template", json={"enabled": False, "rules": [{"action": "allow"}]})
    body = _post(["10.0.0.0/8"]).json()
    assert len(body["rules"]) == 1
    assert body["rules"][0]["status"] == "learning"


def test_template_preview_does_not_persist():
    d = client.post("/ui/template/preview", json={
        "networks": ["198.51.100.0/24"],
        "rules": [{"protocol": ["17"]}]}).json()
    assert d["rules"][0]["destinationIPs"] == ["198.51.100.0/24"]
    assert d["rules"][0]["protocol"] == ["17"]


def test_template_requires_rules():
    assert client.post("/ui/template", json={"enabled": True, "rules": []}).status_code == 400


def test_template_saves_request_networks():
    client.post("/ui/template", json={
        "enabled": True,
        "networks": ["10.20.30.0/24", "10.20.40.0/24"],
        "rules": [{"protocol": ["6"]}]})
    t = client.get("/ui/template").json()
    assert t["networks"] == ["10.20.30.0/24", "10.20.40.0/24"]
    _disable_template()


# --- Multiple templates (Tab 2, plural API) ---------------------------------

def test_multiple_templates_coexist_and_match():
    a = client.post("/ui/templates", json={
        "name": "A", "enabled": True,
        "networks": ["10.11.12.0/24"], "rules": [{"action": "block"}]})
    b = client.post("/ui/templates", json={
        "name": "B", "enabled": True,
        "networks": ["10.22.33.0/24"], "rules": [{"action": "allow"}]})
    assert a.status_code == 201 and b.status_code == 201
    names = {t["name"] for t in client.get("/ui/templates").json()["templates"]}
    assert {"A", "B"} <= names
    ra = _post(["10.11.12.0/24"]).json()["rules"]
    rb = _post(["10.22.33.0/24"]).json()["rules"]
    assert ra[0]["destinationIPs"] == ["10.11.12.0/24"]
    assert rb[0]["destinationIPs"] == ["10.22.33.0/24"]


def test_templates_rule_ids_globally_unique():
    client.post("/ui/templates", json={
        "name": "U1", "enabled": True, "networks": ["10.44.0.0/24"],
        "rules": [{"action": "block"}, {"action": "allow"}]})
    client.post("/ui/templates", json={
        "name": "U2", "enabled": True, "networks": ["10.55.0.0/24"],
        "rules": [{"action": "block"}, {"action": "allow"}]})
    ids = [r["ruleId"] for r in _post(["10.44.0.0/24"]).json()["rules"]]
    ids += [r["ruleId"] for r in _post(["10.55.0.0/24"]).json()["rules"]]
    assert len(set(ids)) == len(ids)


def test_template_delete_and_404():
    created = client.post("/ui/templates", json={
        "name": "Doomed", "enabled": True, "networks": ["10.66.0.0/24"],
        "rules": [{"action": "allow"}]}).json()["template"]
    tid = created["id"]
    assert client.delete(f"/ui/templates/{tid}").status_code == 200
    assert client.delete(f"/ui/templates/{tid}").status_code == 404


# --- Per-CC recommendation sets (routing by CC IP) --------------------------

def test_cc_set_served_to_its_cc():
    g = _generate_for("10.9.9.9", "4.4.4.0/24", count=200, mode="dst-seq").json()
    assert g["generated"] == 200
    assert g["cc_ip"] == "10.9.9.9"
    served = _post(["4.4.4.0/24"], cc_ip="10.9.9.9").json()["rules"]
    assert len(served) == 200
    assert len({x["ruleId"] for x in served}) == 200
    assert all(x["status"] == "success" for x in served)


def test_cc_set_served_to_primary_and_secondary_ha():
    g = _generate_for("10.1.1.1", "4.4.4.0/24", count=50, mode="dst-seq",
                      secondary_ip="10.1.1.2").json()
    assert g["generated"] == 50 and g["secondary_ip"] == "10.1.1.2"
    assert len(_post(["4.4.4.0/24"], cc_ip="10.1.1.1").json()["rules"]) == 50
    assert len(_post(["4.4.4.0/24"], cc_ip="10.1.1.2").json()["rules"]) == 50


def test_unassigned_cc_gets_learning():
    _generate_for("10.1.1.1", "4.4.4.0/24", count=10)
    body = _post(["4.4.4.0/24"], cc_ip="9.9.9.9").json()
    assert len(body["rules"]) == 1
    assert body["rules"][0]["status"] == "learning"


def test_cc_set_only_for_its_destination_network():
    _generate_for("10.1.1.1", "4.4.4.0/24", count=10)
    body = _post(["5.5.5.0/24"], cc_ip="10.1.1.1").json()
    assert len(body["rules"]) == 1
    assert body["rules"][0]["status"] == "learning"


def test_cc_set_and_template_both_served_in_one_response():
    _generate_for("10.1.1.1", "4.4.4.0/24", count=10, mode="dst-seq")
    client.post("/ui/templates", json={
        "name": "T", "enabled": True, "networks": ["25.25.25.0/24"],
        "rules": [{"action": "block"}]})
    body = _post(["4.4.4.0/24", "25.25.25.0/24"], cc_ip="10.1.1.1").json()
    dsts = [r["destinationIPs"][0] for r in body["rules"]]
    assert len(body["rules"]) == 11  # 10 CC-set + 1 template
    assert any(d.startswith("4.4.4") for d in dsts)
    assert "25.25.25.0/24" in dsts


def test_one_set_per_cc_regenerating_replaces():
    _generate_for("10.1.1.1", "4.4.4.0/24", count=10)
    _generate_for("10.1.1.1", "6.6.6.0/24", count=20)
    # The first destination is no longer served to this CC.
    assert _post(["4.4.4.0/24"], cc_ip="10.1.1.1").json()["rules"][0]["status"] == "learning"
    assert len(_post(["6.6.6.0/24"], cc_ip="10.1.1.1").json()["rules"]) == 20


def test_delete_cc_set_and_404():
    _generate_for("10.7.7.7", "4.4.4.0/24", count=5)
    assert client.delete("/ui/cc-sets/10.7.7.7").status_code == 200
    assert client.delete("/ui/cc-sets/10.7.7.7").status_code == 404


# --- scale-test generation ---------------------------------------------------

def test_scale_preview_reports_capacity_and_sample():
    d = client.post("/ui/scale/preview", json={
        "destination_network": "10.9.0.0/24", "count": 100, "mode": "dst-seq"}).json()
    assert d["ok"] is True
    assert d["capacity"] == 256
    assert len(d["sample"]) == 5
    assert all(s["ruleId"].startswith("rule_") for s in d["sample"])


def test_scale_generate_requires_cc_ip():
    r = client.post("/ui/scale/generate", json={
        "destination_network": "4.4.4.0/24", "count": 10, "mode": "dst-seq"})
    assert r.status_code == 400
    assert "CC IP" in r.json()["detail"]


def test_scale_src_seq_unique_sources():
    g = _generate_for("10.9.9.8", "10.9.0.0/24", count=500, mode="src-seq",
                      source_network="172.16.0.0/16").json()
    assert g["generated"] == 500
    assert g["unique_sources"] == 500


def test_scale_dst_rand_no_duplicate_destinations():
    d = client.post("/ui/scale/download", json={
        "destination_network": "10.9.0.0/24", "count": 200, "mode": "dst-rand"})
    import json as _json
    rules = _json.loads(d.text)["rules"]
    dsts = [tuple(r["destinationIPs"]) for r in rules]
    ids = [r["ruleId"] for r in rules]
    assert len(rules) == 200
    assert len(set(dsts)) == 200
    assert len(set(ids)) == 200


def test_scale_src_rand_no_duplicates():
    d = client.post("/ui/scale/download", json={
        "destination_network": "10.9.0.0/24", "count": 300, "mode": "src-rand",
        "source_network": "10.80.0.0/16"})
    import json as _json
    rules = _json.loads(d.text)["rules"]
    srcs = [tuple(r["sourceIPs"]) for r in rules]
    assert len(rules) == 300
    assert len(set(srcs)) == 300


def test_scale_ipv6_destination_increment():
    d = client.post("/ui/scale/download", json={
        "destination_network": "2001:db8::/120", "count": 50, "mode": "dst-seq"})
    import json as _json
    rules = _json.loads(d.text)["rules"]
    dsts = {tuple(r["destinationIPs"]) for r in rules}
    assert len(rules) == 50
    assert len(dsts) == 50
    assert all(":" in r["destinationIPs"][0] for r in rules)


def test_scale_count_exceeds_capacity_400():
    r = client.post("/ui/scale/generate", json={
        "destination_network": "10.9.0.0/30", "count": 100, "mode": "dst-seq",
        "cc_ip": "10.1.1.9"})
    assert r.status_code == 400
    assert "exceeds" in r.json()["detail"]


def test_scale_src_rand_requires_source_network():
    r = client.post("/ui/scale/generate", json={
        "destination_network": "10.9.0.0/24", "count": 10, "mode": "src-rand",
        "cc_ip": "10.1.1.9"})
    assert r.status_code == 400
    assert "source network is required" in r.json()["detail"]


def test_scale_rejects_bad_destination():
    r = client.post("/ui/scale/preview", json={
        "destination_network": "10.9.0.0", "count": 10, "mode": "dst-seq"})
    assert r.status_code == 400
    assert "subnet" in r.json()["detail"].lower()


# --- Cyber Controller registry (Tab 1) --------------------------------------

def test_cc_list_endpoint():
    assert isinstance(client.get("/ui/cc").json(), list)


def test_cc_delete_unknown_404():
    assert client.delete("/ui/cc/no-such-host").status_code == 404


def test_cc_preflight_unreachable_returns_checks():
    r = client.post("/ui/cc/test", json={
        "cc_host": "localhost", "ssh_user": "root", "ssh_pass": "x", "ssh_port": 1})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False
    assert any(c["name"] == "SSH login" and c["ok"] is False for c in body["checks"])


def test_cc_host_validation_rejects_docker_and_loopback():
    import cc_manager
    assert cc_manager.validate_cc_host("172.17.142.3") is not None
    assert cc_manager.validate_cc_host("172.18.0.5") is not None
    assert cc_manager.validate_cc_host("127.0.0.1") is not None
    assert cc_manager.validate_cc_host("0.0.0.0") is not None
    assert cc_manager.validate_cc_host("169.254.1.1") is not None
    assert cc_manager.validate_cc_host("") is not None
    assert cc_manager.validate_cc_host("10.205.50.10") is None
    assert cc_manager.validate_cc_host("10.28.100.103") is None
    assert cc_manager.validate_cc_host("cc.example.com") is None


def test_cc_configure_rejects_docker_ip_without_ssh():
    r = client.post("/ui/cc/configure", json={
        "cc_host": "172.17.142.3", "ssh_user": "root", "ssh_pass": "x"})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False
    assert any("Docker-internal" in line for line in body["log"])


def test_cc_reset_unreachable_returns_ok_false():
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


def test_recommendations_lists_permanent_networks():
    d = client.get("/ui/recommendations").json()
    keys = {g["key"] for g in d["groups"] if g["kind"] == "permanent"}
    assert set(PERMANENT_NETWORK_RULES).issubset(keys)
    for g in d["groups"]:
        if g["kind"] == "permanent":
            assert g["count"] == len(g["rules"])


def test_recommendations_includes_cc_sets():
    _generate_for("10.3.3.3", "7.7.7.0/24", count=8)
    d = client.get("/ui/recommendations").json()
    cc = [g for g in d["groups"] if g["kind"] == "cc"]
    assert any("10.3.3.3" in g["key"] for g in cc)
    assert any(g["count"] == 8 for g in cc)


def test_cc_sets_list_and_delete():
    # The Scale-test tab lists generated sets and can delete them.
    _generate_for("10.4.4.4", "8.8.8.0/24", count=6, secondary_ip="10.4.4.5")
    listing = client.get("/ui/cc-sets").json()["cc_sets"]
    mine = [s for s in listing if s["cc_ip"] == "10.4.4.4"]
    assert mine, "generated set not listed"
    assert mine[0]["destination_network"] == "8.8.8.0/24"
    assert mine[0]["secondary_ip"] == "10.4.4.5"
    assert mine[0]["count"] == 6
    # Delete it and confirm it is gone.
    r = client.delete("/ui/cc-sets/10.4.4.4")
    assert r.status_code == 200
    assert r.json()["removed"] == "10.4.4.4"
    after = client.get("/ui/cc-sets").json()["cc_sets"]
    assert not any(s["cc_ip"] == "10.4.4.4" for s in after)


def test_cc_sets_delete_unknown_is_404():
    r = client.delete("/ui/cc-sets/203.0.113.99")
    assert r.status_code == 404


def test_recommendations_template_rules_include_ruleid():
    # Templates store rule specs without a ruleId; the browse endpoint must
    # expand them WITH a globally-unique ruleId so 'View JSON' shows real ids.
    response_template.add_template({
        "name": "RID demo", "enabled": True,
        "networks": ["9.9.9.0/24"],
        "rules": [{"action": "block"}, {"protocol": ["6"]}],
    })
    d = client.get("/ui/recommendations").json()
    tpls = [g for g in d["groups"] if g["kind"] == "template" and "RID demo" in g["key"]]
    assert tpls, "template group missing"
    rules = tpls[0]["rules"]
    assert tpls[0]["count"] == len(rules) == 2
    ids = [r["ruleId"] for r in rules]
    assert all(rid.startswith("rule_") for rid in ids)
    assert len(set(ids)) == len(ids)  # unique within the set


def test_configure_without_address_uses_host_header():
    r = client.post("/ui/cc/configure", json={
        "cc_host": "127.0.0.1", "ssh_user": "root", "ssh_pass": "x",
        "ssh_port": 1}, headers={"host": "sim.example:8080"})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False

