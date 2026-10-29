import paramiko, json
c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect('10.205.102.81', username='socx', password='radware', timeout=30)

def run(cmd):
    _, out, err = c.exec_command(cmd, timeout=60)
    return out.read().decode('utf-8', 'replace'), err.read().decode('utf-8', 'replace')

B = "https://localhost:8080"

# 1. create a progressive attack-mitigation definition for 2.1.5.0/24
body = json.dumps({
    "name": "live-smoke",
    "networks": ["2.1.5.0/24"],
    "progressive": True, "progressivePolls": 2,
    "geolocationFilters": [{"country": "CN", "attackBlockagePercentage": 80}],
    "trafficFilters": [
        {"priority": 1, "filterMode": "DROP", "filterCriteria": {"dst_ip": "2.1.5.0/24"}},
        {"priority": 2, "filterMode": "DROP", "filterCriteria": {"dst_ip": "2.1.5.1/32"}},
    ],
})
o, _ = run(f"curl -ks -X POST {B}/ui/attack-mitigations -H 'Content-Type: application/json' -d '{body}'")
print("CREATE:", o)
mid = json.loads(o)["mitigation"]["id"]

# 2. initiate attack
o, _ = run(f"curl -ks -X POST {B}/api/sdcc/genai/core/analysis/attack/_initiateAttackAnalysis "
           f"-H 'Content-Type: application/json' -d '{{\"networks\":[\"2.1.5.0/24\"]}}'")
print("INITIATE:", o)
uid = json.loads(o)["uid"]

# 3. poll twice (progressive: 1 filter then 2)
for i in (1, 2):
    o, _ = run(f"curl -ks '{B}/api/sdcc/genai/core/analysis/attack/_getMitigation?uid={uid}'")
    m = json.loads(o)
    print(f"POLL {i}: traffic={len(m['trafficFilters'])} geo={len(m['geolocationFilters'])} partial={m['isPartialMitigated']}")

# 4. close
o, _ = run(f"curl -ks -X POST '{B}/api/sdcc/genai/core/analysis/attack/_closeAttack?uid={uid}'")
print("CLOSE:", o)

# 5. cleanup (delete session + definition)
run(f"curl -ks -X DELETE '{B}/ui/attack-sessions/{uid}'")
o, _ = run(f"curl -ks -X DELETE '{B}/ui/attack-mitigations/{mid}'")
print("CLEANUP:", o)

c.close()

