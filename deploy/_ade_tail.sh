ADE=$(docker ps --format '{{.Names}}' | grep -i anomaly-detection-engine | head -1)
echo "ADE=$ADE"
echo "=== last 3 min: PKIX / recommendation flow for 2.2.1.0 ==="
docker logs --since 180s "$ADE" 2>&1 | grep -E 'PKIX|Received recommendation|recommendations returned|Cloud connectivity|Processing recommendation DTO|Full REST API: https|success|2\.2\.1\.0' | tail -50

