cd "$HOME/cloudSimulator"
echo "== git pull =="
git pull --ff-only || true
echo "== build --no-cache =="
echo __PW__ | sudo -S -p "" docker compose build --no-cache
echo "== up --force-recreate =="
echo __PW__ | sudo -S -p "" docker compose up -d --force-recreate
sleep 5
echo "== container status line (should be rt.get) =="
echo __PW__ | sudo -S -p "" docker exec socx-sim grep -n 'rt.get("status")' /app/response_template.py
echo "== health =="
curl -ks https://localhost:8080/health && echo
echo "DONE_OK"

