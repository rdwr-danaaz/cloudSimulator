cd "$HOME/cloudSimulator"
echo "== HEAD =="
git log --oneline -1
echo "== git status =="
git status -s -b | head -5
echo "== REPO status line =="
grep -n 'rt.get("status")' response_template.py
echo "== CONTAINER image id =="
echo __PW__ | sudo -S -p "" docker inspect --format '{{.Image}}' socx-sim
echo "== CONTAINER file status lines =="
echo __PW__ | sudo -S -p "" docker exec socx-sim grep -n 'status' /app/response_template.py

