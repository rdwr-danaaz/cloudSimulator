from __future__ import annotations

import hashlib
import json
import time
import uuid
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="SOC-X Mock API", version="1.0.0")


class FilterDefinition(BaseModel):
    deviceIp: str = Field(min_length=1)
    policyName: str = Field(min_length=1)
    po: str = Field(min_length=1)
    destinationNetworks: list[str] = Field(default_factory=list)
    destinationIps: list[str] = Field(default_factory=list)
    sourceIps: list[str] = Field(default_factory=list)
    sourcePorts: list[str] = Field(default_factory=list)
    destinationPorts: list[str] = Field(default_factory=list)
    protocols: list[str] = Field(default_factory=list)
    tcpFlags: list[str] = Field(default_factory=list)
    packetSize: list[str] = Field(default_factory=list)
    sourceGeo: list[str] = Field(default_factory=list)
    sourceAsn: list[str] = Field(default_factory=list)
    ttl: list[str] = Field(default_factory=list)
    fragmented: bool | None = None
    permanent: bool


class AddFilterRequest(FilterDefinition):
    pass


class EditFilterRequest(FilterDefinition):
    ruleHash: str = Field(min_length=1)


class DeleteRecommendationsRequest(BaseModel):
    deviceIp: str = Field(min_length=1)
    policyName: str = Field(min_length=1)
    recommendations: list[str] = Field(min_length=1)


class GetByRuleRequest(BaseModel):
    deviceIp: str = Field(min_length=1)
    policyName: str = Field(min_length=1)
    ruleId: str = Field(min_length=1)
    timeStamp: int = Field(gt=0)
    metaData: dict[str, Any] = Field(default_factory=dict)


class DevicePolicyRequest(BaseModel):
    deviceIp: str = Field(min_length=1)
    policyName: str = Field(min_length=1)
    metaData: dict[str, Any] = Field(default_factory=dict)


class RevertRecommendationsRequest(BaseModel):
    deviceIp: str = Field(min_length=1)
    policyName: str = Field(min_length=1)
    recommendations: list[str] = Field(min_length=1)


recommendations_store: dict[str, dict[str, Any]] = {}


def _now_ms() -> int:
    return int(time.time() * 1000)


def _hash_from_payload(payload: FilterDefinition) -> str:
    serialized = json.dumps(payload.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.md5(serialized.encode("utf-8")).hexdigest()


def _rule_id_from_hash(rule_hash: str) -> str:
    digest = hashlib.sha256(rule_hash.encode("utf-8")).hexdigest()
    return f"rule_{digest}"


def _build_recommendation(payload: FilterDefinition, parent_hash: str | None = None) -> dict[str, Any]:
    cloud_timestamp = _now_ms()
    rule_hash = _hash_from_payload(payload)

    recommendation = payload.model_dump(mode="json")
    recommendation.update(
        {
            "recommendationId": str(uuid.uuid4()),
            "parentHash": parent_hash,
            "ruleHash": rule_hash,
            "ruleId": _rule_id_from_hash(rule_hash),
            "recommendationStatus": "success",
            "dpStatus": "Pending",
            "deleted": False,
            "timeStamp": cloud_timestamp,
            "cloudTimestamp": cloud_timestamp,
        }
    )
    return recommendation


def _matches_device_policy(item: dict[str, Any], device_ip: str, policy_name: str) -> bool:
    return item["deviceIp"] == device_ip and item["policyName"] == policy_name


def _recommendations_for_device_policy(device_ip: str, policy_name: str) -> list[dict[str, Any]]:
    return [
        recommendation
        for recommendation in recommendations_store.values()
        if _matches_device_policy(recommendation, device_ip, policy_name)
    ]


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/socx/policy/recommendations/add")
def add_filter(request: AddFilterRequest) -> dict[str, Any]:
    recommendation = _build_recommendation(request)
    recommendations_store[recommendation["recommendationId"]] = recommendation
    return recommendation


@app.post("/socx/policy/recommendations/edit")
def edit_filter(request: EditFilterRequest) -> dict[str, Any]:
    parent_hash = request.ruleHash
    recommendation = _build_recommendation(request, parent_hash=parent_hash)
    recommendations_store[recommendation["recommendationId"]] = recommendation
    return recommendation


@app.delete("/socx/positive/policy/recommendations")
def delete_recommendations(request: DeleteRecommendationsRequest) -> dict[str, Any]:
    changed = 0
    for recommendation_id in request.recommendations:
        recommendation = recommendations_store.get(recommendation_id)
        if recommendation is None:
            continue
        if recommendation["deviceIp"] != request.deviceIp or recommendation["policyName"] != request.policyName:
            continue
        recommendation["deleted"] = True
        recommendation["dpStatus"] = "PendingToRemove"
        changed += 1

    if changed == 0:
        raise HTTPException(status_code=404, detail="No matching recommendations found")

    return {"metaData": {}, "data": [{"row": {"value": "ok"}}]}


@app.post("/socx/policy/recommendations/rule")
def get_by_rule(request: GetByRuleRequest) -> dict[str, Any]:
    start_ms = _now_ms()

    matches = [
        recommendation
        for recommendation in recommendations_store.values()
        if recommendation["deviceIp"] == request.deviceIp
        and recommendation["policyName"] == request.policyName
        and recommendation["ruleId"] == request.ruleId
        and recommendation["timeStamp"] >= request.timeStamp
    ]

    if matches:
        last_dp_update = max(item["timeStamp"] for item in matches)
        last_cloud_update = max(item["cloudTimestamp"] for item in matches)
        status = "Succeeded" if all(item["dpStatus"] == "Succeeded" for item in matches) else "Pending"
    else:
        last_dp_update = 0
        last_cloud_update = 0
        status = "NoData"

    total_time = str(max(1, _now_ms() - start_ms))
    return {
        "metaData": {"totalTime": total_time},
        "data": [],
        "dataMap": {
            "preventiveRecommendations": matches,
            "statistics": {
                "lastDefenseProUpdate": last_dp_update,
                "lastCloudUpdate": last_cloud_update,
                "status": status,
            },
        },
    }


@app.post("/socx/policy/last/recommendations")
def get_last_by_device_policy(request: DevicePolicyRequest) -> dict[str, Any]:
    start_ms = _now_ms()
    matches = _recommendations_for_device_policy(request.deviceIp, request.policyName)

    if matches:
        last_dp_update = max(item["timeStamp"] for item in matches)
        last_cloud_update = max(item["cloudTimestamp"] for item in matches)
        status = "Failed" if any(item["dpStatus"] == "Failed" for item in matches) else "Succeeded"
    else:
        last_dp_update = 0
        last_cloud_update = 0
        status = "NoData"

    total_time = str(max(1, _now_ms() - start_ms))
    return {
        "metaData": {"totalTime": total_time},
        "data": [],
        "dataMap": {
            "preventiveRecommendations": matches,
            "statistics": {
                "lastCloudUpdate": last_cloud_update,
                "lastDefenseProUpdate": last_dp_update,
                "status": status,
            },
        },
    }


@app.post("/socx/policy/historical/recommendations")
def get_historical_by_device_policy(request: DevicePolicyRequest) -> dict[str, Any]:
    start_ms = _now_ms()
    matches = _recommendations_for_device_policy(request.deviceIp, request.policyName)
    sorted_matches = sorted(matches, key=lambda item: item["timeStamp"], reverse=True)

    history_rows = [
        {
            "row": {
                "deviceIp": item["deviceIp"],
                "policyName": item["policyName"],
                "ruleId": item["ruleId"],
                "timeStamp": str(item["timeStamp"]),
                "status": item["dpStatus"].lower(),
            }
        }
        for item in sorted_matches
    ]

    total_time = str(max(1, _now_ms() - start_ms))
    return {
        "metaData": {"totalTime": total_time},
        "data": history_rows,
    }


@app.post("/socx/policy/recommendations/revert")
def revert_recommendations(request: RevertRecommendationsRequest) -> dict[str, Any]:
    changed = 0
    for recommendation_id in request.recommendations:
        recommendation = recommendations_store.get(recommendation_id)
        if recommendation is None:
            continue
        if not _matches_device_policy(recommendation, request.deviceIp, request.policyName):
            continue
        recommendation["deleted"] = False
        recommendation["dpStatus"] = "Pending"
        changed += 1

    if changed == 0:
        raise HTTPException(status_code=404, detail="No matching recommendations found")

    return {"metaData": {}, "data": [{"row": {"value": "ok"}}]}


