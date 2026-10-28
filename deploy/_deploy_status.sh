cd "$HOME/cloudSimulator"
echo "== git pull =="
git pull --ff-only
echo "== build --no-cache =="
echo __PW__ | sudo -S -p "" docker compose build --no-cache 2>&1 | tail -2
echo "== up --force-recreate =="
echo __PW__ | sudo -S -p "" docker compose up -d --force-recreate 2>&1 | tail -3
sleep 5
echo "== ui.html has r_status? =="
echo __PW__ | sudo -S -p "" docker exec socx-sim grep -c 'r_status' /app/static/ui.html
echo "== health =="
curl -ks https://localhost:8080/health && echo
echo "DONE_OK"

