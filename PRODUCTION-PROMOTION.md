# Production Promotion — v3.7.0 + MongoDB (argos-2026)

Staged, parity-first promotion of the Network Agent from **v3.5.0 (JSON)** on
prod to **v3.7.0 (MongoDB + Phase-1 features)**. Each stage has a verification
gate and a rollback. Do not proceed to the next stage until the current one is
green. New feature pollers stay OFF until Mongo is stable (Stage 4).

Hosts / repos
- Dev: `arubaagent`, origin `github.com/LuckyBasartd/Aruba-Network-Agent`
- Prod: `argos-2026`, remote `github.sandiego.edu/NISS/Network-Agent`
- Prod deploy: `sudo /home/aruba-agent-deploy/bin/deploy.sh`
- Prod app dir: `/opt/aruba-agent`  · config `/etc/aruba-agent/`  · data `/var/lib/aruba-agent/`

Version model: v3.5.0 = current prod (JSON) · v3.6.0 = mid-dev (stale tag) ·
**v3.7.0 = this release** (Mongo, config-diff, interface/L2/MAC/LLDP, CRC,
trap receiver, threshold alerting + health).

---

## Stage 0 — Pre-flight (NO changes)

Capture state and back up the irreplaceable bits first.

```bash
# On argos-2026:
systemctl is-active aruba-agent
curl -s http://127.0.0.1:8080/healthz ; echo
# current device count (JSON state)
python3 -c "import json;print('switches',len(json.load(open('/var/lib/aruba-agent/state.json')).get('switches',[])))"
free -m ; nproc ; df -h /var /opt
cat /etc/os-release | head -2

# BACK UP (master.key is unrecoverable if lost!)
sudo cp -a /etc/aruba-agent/master.key   /root/preflight-master.key.bak
sudo cp -a /etc/aruba-agent/config.ini   /root/preflight-config.ini.bak
sudo cp -a /var/lib/aruba-agent/state.json /root/preflight-state.json.bak
sudo tar czf /root/preflight-backups.tgz -C /var/lib/aruba-agent backups 2>/dev/null; ls -lh /root/preflight-*
# note the running version/commit
git -C /opt/aruba-agent describe --tags --always ; git -C /opt/aruba-agent rev-parse HEAD
```

**Gate:** healthz ok, device count recorded, backups saved off-path, and RAM
is adequate. Sizing: parity-only on JSON is ~v3.5.0 footprint, but Mongo + the
new pollers want headroom — **8 GB RAM recommended** for 481 switches + Mongo +
all features (the dev box needed ~2 GB agent + Mongo working set). If argos has
<4 GB, resize before Stage 4.

---

## Stage 1 — Deploy v3.7.0 code on the JSON backend (parity only)

Ship the new code but keep `[store] backend = json` and every new poller OFF,
so behaviour equals today. This proves the v3.7.0 code runs clean on prod
before any data-layer change.

```bash
# --- On the Mac: tag HEAD and push to BOTH remotes ---
cd "/Users/mvieira/Desktop/Python/Aruba-Networking/Network Agent"
git push origin main
git tag -a v3.7.0 -m "Phase 1 release: Mongo, config-diff, interface/L2/MAC/LLDP, CRC, traps, threshold alerting"
git push origin v3.7.0
git push production main
git push production v3.7.0

# --- On argos-2026: deploy ---
sudo /home/aruba-agent-deploy/bin/deploy.sh
# deploy.sh has a known regression (git pull only). Ensure the rest ran:
sudo /opt/aruba-agent/venv/bin/pip install -r /opt/aruba-agent/requirements.txt   # pulls pymongo, pins pysnmp<6.2
git -C /opt/aruba-agent describe --tags        # expect v3.7.0
sudo systemctl restart aruba-agent
```

Confirm the prod `config.ini` has NO new features enabled yet (they default
off, but check): `[interfaces] [l2] [traps] [health] [thresholds]` either
absent or `enabled = false`; `[store]` absent or `backend = json`.

**Gate:** `systemctl is-active` = active; healthz ok; dashboard loads; device
count matches Stage 0; a manual backup still works
(`--controller-backup` dry-run or wait for the nightly). Watch `journalctl -u
aruba-agent -n 50` for tracebacks.

**Rollback:** `cd /opt/aruba-agent && sudo git checkout v3.5.0 && sudo systemctl restart aruba-agent`
(JSON state untouched, so this is a clean revert).

---

## Stage 2 — Install MongoDB on argos-2026 (auth + backups)

```bash
# MongoDB 7 community repo (AlmaLinux/RHEL). Adjust version to policy.
sudo tee /etc/yum.repos.d/mongodb-org-7.0.repo >/dev/null <<'REPO'
[mongodb-org-7.0]
name=MongoDB 7.0
baseurl=https://repo.mongodb.org/yum/redhat/$releasever/mongodb-org/7.0/x86_64/
gpgcheck=1
enabled=1
gpgkey=https://pgp.mongodb.com/server-7.0.asc
REPO
sudo dnf install -y mongodb-org
sudo systemctl enable --now mongod
mongosh --quiet --eval 'db.runCommand({ping:1})'

# Create admin + app user, then TURN ON auth
mongosh <<'JS'
use admin
db.createUser({user:"admin", pwd:"<STRONG_ADMIN_PW>", roles:["root"]})
use aruba_agent
db.createUser({user:"aruba_agent", pwd:"<STRONG_APP_PW>", roles:[{role:"readWrite", db:"aruba_agent"}]})
JS
sudo sed -i 's/^#security:/security:\n  authorization: enabled/' /etc/mongod.conf
# ensure it stays bound to localhost only:
grep -A2 'net:' /etc/mongod.conf   # bindIp: 127.0.0.1
sudo systemctl restart mongod
mongosh --quiet "mongodb://aruba_agent:<STRONG_APP_PW>@localhost:27017/aruba_agent" --eval 'db.runCommand({ping:1})'

# Nightly mongodump backup
sudo tee /etc/cron.d/aruba-mongodump >/dev/null <<'CRON'
30 2 * * * root mongodump --uri="mongodb://aruba_agent:<STRONG_APP_PW>@localhost:27017/aruba_agent" --out=/var/backups/mongo/$(date +\%F) >/dev/null 2>&1
CRON
```

**Gate:** authenticated `mongosh` ping succeeds; Mongo bound to 127.0.0.1 only;
dump cron in place. **Rollback:** nothing changed in the agent yet — Mongo is
just installed and idle.

---

## Stage 3 — Migrate state to Mongo and cut the backend over

Agent is still running on JSON. Import the live state, verify, then flip.

```bash
# Import current JSON state into Mongo (reads state.json, writes devices/runtime)
sudo /opt/aruba-agent/venv/bin/python /opt/aruba-agent/main.py /etc/aruba-agent/config.ini --import-state-to-mongo
# Verify the count matches Stage 0 (should say imported N; Mongo now reports N)
mongosh --quiet "mongodb://aruba_agent:<STRONG_APP_PW>@localhost:27017/aruba_agent" --eval 'db.devices.countDocuments()'
```

Then edit `/etc/aruba-agent/config.ini` — add ONE `[store]` section (mind the
one-section rule):

```ini
[store]
backend = mongo
uri = mongodb://aruba_agent:<STRONG_APP_PW>@localhost:27017/aruba_agent
require_mongo = true
metrics_retention_days = 30
```

Validate + restart:
```bash
python3 -c "import configparser; configparser.ConfigParser().read('/etc/aruba-agent/config.ini'); print('config OK')"
sudo systemctl restart aruba-agent
curl -s http://127.0.0.1:8080/healthz ; echo
```

**Gate:** healthz ok; dashboard device count matches Stage 0; log shows
`MongoStore: connected`; a state change (mute a host, then unmute) persists
across a restart. **Rollback:** set `[store] backend = json`, restart — the
JSON `state.json` is still current, so you're instantly back on the old path.

---

## Stage 4 — Enable new features, one at a time

Only after Mongo has been stable for a bit. Enable, restart, verify, watch
`free -m` + `journalctl`, then move to the next. Start interface/L2/health
**scoped** (an `include =` subnet) before going fleet-wide.

Order (safest first):
1. `[interfaces] enabled = true, include = <one subnet>, record_zero_util = false`
2. `[l2] enabled = true, include = <same subnet>`
3. `[health] enabled = true, include = <same subnet>`
4. `[thresholds] enabled = true` + add a couple of rules in the UI
5. `[traps] enabled = true, port = 16200` + firewalld redirect
   `sudo firewall-cmd --permanent --add-forward-port=port=162:proto=udp:toport=16200 && sudo firewall-cmd --reload`
   (validate with `--l2-discover-once`/`--health-once`/a test trap as on dev)

After each: watch `ls /proc/$(pgrep -f aruba-agent/main.py)/fd | wc -l` stays
flat and `free -m` has headroom. Widen `include` to the fleet last.

**Safeguard:** add `LimitNOFILE=65536` to the systemd unit
(`sudo systemctl edit aruba-agent`) before fleet-wide.

---

## Rollback summary
- Stage 1 (code): `git checkout v3.5.0` + restart.
- Stage 3 (backend): `[store] backend = json` + restart (JSON state stays live).
- Stage 4 (a feature misbehaves): set that section `enabled = false` + restart.
- Full revert: `git checkout v3.5.0`, remove `[store]`, restart — back to the
  pre-promotion state; `/root/preflight-*` holds the originals.

## Post-promotion checklist
- healthz ok; device count matches; nightly config backup ran; mongodump ran.
- fd count flat; RAM headroom; load average sane.
- Alerts/traps emails arriving as expected (not chatty).
- Tag the prod state; note the date/commit in CLAUDE.md "Current state".
