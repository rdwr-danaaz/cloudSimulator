set +e
echo "HEALTH:"; curl -ks https://localhost:8080/health; echo
echo "TAB_COUNT:"; curl -ks https://localhost:8080/ui | grep -c "Remediation Recommendations"
echo "ATTACK_MITIGATIONS:"; curl -ks https://localhost:8080/ui/attack-mitigations; echo
echo "ATTACK_SESSIONS:"; curl -ks https://localhost:8080/ui/attack-sessions; echo
echo "INITIATE:"; UID_JSON=$(curl -ks -X POST https://localhost:8080/api/sdcc/genai/core/analysis/attack/_initiateAttackAnalysis -H "Content-Type: application/json" -d '{"networks":["2.1.5.0/24"]}'); echo "$UID_JSON"
UID=$(echo "$UID_JSON" | sed -E 's/.*"uid":"?([^",}]+).*/\1/')
echo "GETMITIGATION ($UID):"; curl -ks "https://localhost:8080/api/sdcc/genai/core/analysis/attack/_getMitigation?uid=$UID"; echo
echo "CLOSE:"; curl -ks -X POST "https://localhost:8080/api/sdcc/genai/core/analysis/attack/_closeAttack?uid=$UID"; echo
echo "CLEANUP_SESSION:"; curl -ks -X DELETE "https://localhost:8080/ui/attack-sessions/$UID"; echo

