content = """\
import pytest
from datetime import datetime
from fastapi.testclient import TestClient
from cloud_mock_server import app, rules_store, generation_config, _load_recommendations_from_disk

client = TestClient(app)
SAMPLE_TAG = "CFIA-Canadian_200"
SAMPLE_NETWORKS = ["192.168.1.0/24", "10.168.2.1/32"]
REAL_TAGS = ["icmp", "85", "86"]
_DEFAULT_N = 3


@pytest.fixture(autouse=True)
def reset_state():
    rules_store.clear()
    _load_recommendations_from_disk()
    generation_config.update({
        "rules_per_network": _DEFAULT_N, "sourceIPs": [], "sourcePorts": [],
        "destinationPorts": [], "protocols": ["6", "17"], "tcpFlags": [],
        "packetSize": ["128"], "sourceGeo": ["US"], "sourceASN": ["7018"],
        "fragment": "none", "action": "allow"})
    yield
    rules_store.clear()


def _post(tag, networks):
    return client.post("/api/sdcc/genai/core/analysis/peacetime/_getRecommendation",
                       json={"tag": tag, "networks": networks})


def test_health():
    assert client.get("/health").json() == {"status": "ok"}


def test_unknown_tag_generates_rules():
    body = _post("new-tag", SAMPLE_NETWORKS).json()
    assert body["rules"]
    all_dest = {ip for r in body["rules"] for ip in r["destinationIPs"]}
    assert all_dest <= set(SAMPLE_NETWORKS)


def test_rules_per_network_count():
    networks = ["10.0.0.0/8", "192.168.1.0/24"]
    assert len(_post("any", networks).json()["rules"]) == _DEFAULT_N * 2


def test_auto_generated_status_success():
    assert all(r["status"] == "success" for r in _post("any", ["10.0.0.0/8"]).json()["rules"])


def test_multiple_networks():
    nets = ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"]
    body = _post("multi", nets).json()
    assert len(body["rules"]) == _DEFAULT_N * 3
    assert {n["subnet"] for n in body["metadata"]["networks"]} == set(nets)


def test_real_tags_loaded():
    loaded = client.get("/admin/tags").json()
    for tag in REAL_TAGS:
        assert tag in loaded


@pytest.mark.parametrize("tag", REAL_TAGS)
def test_real_status_success(tag):
    body = _post(tag, ["100.98.89.0/24"]).json()
    assert all(r["status"] == "success" for r in body["rules"])


def test_configurable_count():
    client.post("/ui/config", json={"rules_per_network": 5, "protocols": ["17"]})
    body = _post("t", ["10.0.0.0/8"]).json()
    assert len(body["rules"]) == 5
    assert all(r["protocol"] == ["17"] for r in body["rules"])


def test_custom_geo_asn():
    client.post("/ui/config", json={
        "rules_per_network": 2, "sourceGeo": ["IL"], "sourceASN": ["1234"], "protocols": ["6"]})
    for rule in _post("geo", ["172.16.0.0/12"]).json()["rules"]:
        assert rule["sourceGeo"] == ["IL"]
        assert rule["sourceASN"] == ["1234"]


def test_interval_3h_block():
    iv = _post("icmp", ["100.98.89.0/24"]).json()["metadata"]["interval"]
    s = datetime.strptime(iv["start_time"], "%Y-%m-%dT%H:%M:%SZ")
    e = datetime.strptime(iv["end_time"],   "%Y-%m-%dT%H:%M:%SZ")
    assert s.hour % 3 == 0 and s.minute == 0
    assert int((e - s).total_seconds()) == 3*3600 - 1


def test_timestamp_format():
    datetime.strptime(_post("icmp", ["100.98.89.0/24"]).json()["timestamp"], "%Y-%m-%dT%H:%M:%S.%fZ")


def test_response_structure():
    body = _post("icmp", ["100.98.89.0/24"]).json()
    assert set(body.keys()) == {"account_id", "rules", "metadata", "timestamp"}
    assert set(body["rules"][0].keys()) == {
        "ruleId", "sourceIPs", "destinationIPs", "sourcePorts", "destinationPorts",
        "protocol", "tcpFlags", "packetSize", "fragment", "sourceGeo", "sourceASN", "action", "status"}


def test_reload():
    rules_store.clear()
    assert set(client.post("/admin/reload").json()["loaded_tags"]) >= set(REAL_TAGS)


def test_seed_overrides():
    client.post("/admin/seed", json={"tag": "icmp", "rules": [{"ruleId": "rule_test", "destinationIPs": ["1.2.3.4/32"]}]})
    assert _post("icmp", ["1.2.3.4/32"]).json()["rules"][0]["ruleId"] == "rule_test"


def test_seed_and_clear():
    client.post("/admin/seed", json={"tag": SAMPLE_TAG, "rules": []})
    assert SAMPLE_TAG in rules_store
    assert client.delete(f"/admin/seed/{SAMPLE_TAG}").status_code == 200
    assert SAMPLE_TAG not in rules_store


def test_clear_404():
    assert client.delete("/admin/seed/no-such").status_code == 404


def test_missing_tag_422():
    assert client.post("/api/sdcc/genai/core/analysis/peacetime/_getRecommendation",
                       json={"networks": ["10.0.0.0/8"]}).status_code == 422


def test_empty_networks_422():
    assert client.post("/api/sdcc/genai/core/analysis/peacetime/_getRecommendation",
                       json={"tag": SAMPLE_TAG, "networks": []}).status_code == 422
"""

with open("tests/test_cloud_mock_server.py", "w", encoding="utf-8") as f:
    f.write(content)
print(f"Written {len(content)} chars to tests/test_cloud_mock_server.py")

