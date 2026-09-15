# Network Agent — Troubleshooting Guide

Operator runbook for the Network Agent (systemd service `aruba-agent`).
Companion to `CLAUDE.md` (architecture) and `INSTALL*.md` (setup).

---

## Key locations

| What            | Path |
|-----------------|------|
| Config          | `/etc/aruba-agent/config.ini` |
| Master key      | `/etc/aruba-agent/master.key`  ← **encrypts all secrets; never delete/commit** |
| State snapshot  | `/var/lib/aruba-agent/state.json` |
| Backups         | `/var/lib/aruba-agent/backups/<hostname>/` |
| Scanner IP list | `/var/lib/aruba-agent/ip_list.txt` |
| Audit log       | `/var/log/aruba-agent/audit.log` |
| Wireless subnets| `/etc/aruba-agent/wireless_subnets.txt` |
| Code / venv     | `/opt/aruba-agent/` , `/opt/aruba-agent/venv/` |
| Runs as         | user/group `aruba-agent` |
| Web UI          | proxied at `https://arubaagent.sandiego.edu` → app on `127.0.0.1:8080` |

---

## Service control

```bash
sudo systemctl status aruba-agent --no-pager      # up? last exit? memory/cpu
sudo systemctl restart aruba-agent                # apply config changes
sudo systemctl stop aruba-agent
sudo systemctl start aruba-agent
systemctl is-active aruba-agent                   # active / failed / inactive
systemctl is-enabled aruba-agent                  # starts on boot?
```

Config changes take effect **only after a restart** (the web GUI says this on
each Settings page). Live monitor add/remove from the GUI is the exception.

---

## Watch logs live

```bash
# Watch logs live
sudo journalctl -u aruba-agent -f

# start with the last 100 lines, then follow
sudo journalctl -u aruba-agent -n 100 -f

# follow but only show warnings/errors
sudo journalctl -u aruba-agent -f -p warning

# follow and filter to a specific switch/keyword as it scrolls
sudo journalctl -u aruba-agent -f | grep --line-buffered "10.80.0.116"

# everything since the last boot / a time window (not following)
sudo journalctl -u aruba-agent -b --no-pager
sudo journalctl -u aruba-agent --since "1 hour ago" --no-pager
sudo journalctl -u aruba-agent --since today -p err --no-pager

# just the last 50 error-level lines
sudo journalctl -u aruba-agent -p err -n 50 --no-pager
```

Tip: `-p` levels are `emerg alert crit err warning notice info debug`.

---

## Is it actually up? (health checks)

```bash
# App health (localhost, behind the proxy)
curl -s http://127.0.0.1:8080/healthz ; echo
curl -s http://127.0.0.1:8080/metrics | head        # Prometheus metrics

# Through the proxy (TLS)
curl -sk https://arubaagent.sandiego.edu/healthz ; echo

# Is the port listening / who owns it?
sudo ss -ltnp | grep 8080
```

A **503 "Service Unavailable"** in the browser almost always means the backend
process is down (Apache/nginx can't reach `127.0.0.1:8080`). Go straight to
`systemctl status` + `journalctl`.

---

## Won't start / crash loop

```bash
# See why it exits (last run's traceback)
sudo journalctl -u aruba-agent -n 60 --no-pager

# Run it in the foreground as the service user to see the traceback directly.
# Ctrl-C once it either starts listening or prints an error.
sudo -u aruba-agent /opt/aruba-agent/venv/bin/python \
     /opt/aruba-agent/main.py /etc/aruba-agent/config.ini
```

Common causes:
- **Config typo** in a section you just edited → the traceback names the file/line.
  Temporarily disable the suspect section (`enabled = false`) and restart to isolate.
- **`config.ini` not writable / wrong owner** (Settings pages warn about this):
  ```bash
  sudo chown aruba-agent:aruba-agent /etc/aruba-agent/config.ini
  sudo chmod 640 /etc/aruba-agent/config.ini
  ```
- **Missing Python dep** (netmiko/napalm) after a deploy:
  ```bash
  sudo /opt/aruba-agent/venv/bin/pip install -r /opt/aruba-agent/requirements.txt
  ```

---

## Manual / on-demand job runs

```bash
# Dry-run controller backups: login / save / capture size per controller (no files written)
sudo /opt/aruba-agent/venv/bin/python /opt/aruba-agent/main.py /etc/aruba-agent/config.ini --controller-backup

# Check the VPN controller web-server once (also sends the alert email if down)
sudo /opt/aruba-agent/venv/bin/python /opt/aruba-agent/main.py /etc/aruba-agent/config.ini --webserver-check

# Wireless subnet utilization check (prints low/high, emails if any flagged)
sudo /opt/aruba-agent/venv/bin/python /opt/aruba-agent/main.py /etc/aruba-agent/config.ini --subnet-health

# Verify every backup file against its SHA-256 sidecar (exit 0 = all good, 2 = corruption)
sudo /opt/aruba-agent/venv/bin/python /opt/aruba-agent/main.py /etc/aruba-agent/config.ini --verify-backups

# Decrypt one backup to a file for restore (backups are encrypted at rest)
sudo /opt/aruba-agent/venv/bin/python /opt/aruba-agent/main.py /etc/aruba-agent/config.ini \
     --decrypt-backup /var/lib/aruba-agent/backups/<host>/<file>.cfg.enc > restored.cfg

# Interface poll — one cycle now. Utilization needs a 2nd run (counter delta).
sudo /opt/aruba-agent/venv/bin/python /opt/aruba-agent/main.py /etc/aruba-agent/config.ini --interfaces-poll-once
# Probe interfaces on ONE switch (fast; prints ifName/util/CRC + SNMP diagnostics)
sudo /opt/aruba-agent/venv/bin/python /opt/aruba-agent/main.py /etc/aruba-agent/config.ini --interfaces-poll-once --host 10.40.0.6

# L2 discovery — one MAC-table + LLDP/CDP neighbor sweep now
sudo /opt/aruba-agent/venv/bin/python /opt/aruba-agent/main.py /etc/aruba-agent/config.ini --l2-discover-once
# Probe ONE switch: prints its per-port MAC table AND classified neighbors
sudo /opt/aruba-agent/venv/bin/python /opt/aruba-agent/main.py /etc/aruba-agent/config.ini --l2-discover-once --host 10.40.0.6
```

Nightly Config Backup, Discovery, and ARP can also be **Run now** from the
**Jobs** page in the web UI.

---

## A device shows DOWN (but you think it's up)

Reachability ladder is **SNMP → ICMP → SSH**. SNMP OK = Up; SNMP fail + ICMP
fail = Down; ICMP OK + SSH OK = Up but "SNMP-degraded" (dashboard warning).

```bash
# Basic reachability from the agent host
ping -c3 <ip>
nc -vz <ip> 22          # SSH open?
nc -vz <ip> 443         # AOS-CX REST open? (CX switches only)
nc -vz -u <ip> 161      # SNMP (UDP)

# SNMPv3 sanity (net-snmp) — fill in YOUR profile; do not paste real secrets into shared docs
snmpget -v3 -l authPriv -u <user> -a SHA -A '<AUTHPASS>' -x AES -X '<PRIVPASS>' <ip> sysDescr.0
snmpget -v3 -l authPriv -u <user> -a SHA -A '<AUTHPASS>' -x AES -X '<PRIVPASS>' <ip> sysObjectID.0

# Manual SSH login test
ssh <user>@<ip>
```

Also check on the dashboard / `state.json`: is the host **muted** or
**unmanaged** (maintenance mode)? Muted switches suppress alerts;
unmanaged switches aren't polled at all.

---

## Inspect what the agent thinks about a device

```bash
# With jq (nicest): find a host by IP and show its state
sudo jq '.switches[] | select(.host=="10.80.0.116")' /var/lib/aruba-agent/state.json

# Vendor tag / down flag / snmp health / mute / unmanaged for every host
sudo jq -r '.switches[] | [.host,.vendor,.is_down,.snmp_ok,.alerts_muted,.unmanaged] | @tsv' \
     /var/lib/aruba-agent/state.json | column -t

# No jq? crude grep with context
sudo grep -A8 '"10.80.0.116"' /var/lib/aruba-agent/state.json
```

Vendor keys: `aruba_cx` (CX/REST), `aruba_os` (ProCurve/AOS-S SSH),
`aruba_aos8` (AOS-8 controllers SSH), `cisco_ios`, `arista_eos`. A **wrong or
blank vendor** is the usual reason a backup uses the wrong transport (e.g. a
ProCurve trying REST on :443 and timing out). Manually-pinned or
statically-configured devices (controllers) are pinned rather than SNMP-detected.

---

## A backup failed

The dashboard **Needs attention → Backup fails** tab shows the reason per device.
Reading the error tells you the layer:

- `Login failed (aruba_cx): ... timed out / connection refused` on :443 → not a
  CX box (REST absent) or REST disabled. If it's really ProCurve/AOS-8, fix its
  vendor tag so it uses SSH.
- `Login failed (...): Authentication failed` → wrong creds for that vendor;
  check `[credentials]` / `[credentials.cisco]` / `[credentials.aos8]` etc.
- `Pattern not detected` / `ReadTimeout` (Cisco) → slow gear; raise
  `[credentials.cisco] read_timeout` and `global_delay_factor`.
- `Save running→startup failed` → account lacks write/manager privilege.

```bash
# Latest backup per host + size (sanity that they're non-empty)
sudo ls -lt /var/lib/aruba-agent/backups/<host>/ | head
sudo du -sh /var/lib/aruba-agent/backups/*         # per-host footprint
df -h /var/lib/aruba-agent                          # disk space for backups
```

---

## No email alerts

- Settings → **Email Alerts** → **Test** sends a one-shot message using the
  on-disk SMTP config (doesn't need a restart).
- Confirm recipients and that alerts aren't all **muted**.
- Watch the log during a trigger: `journalctl -u aruba-agent -f | grep -i "Email"`.

---

## New devices not discovered

- Settings → **Network Scanner**: correct subnets, exclude suffixes, keywords.
- The scanner writes `ip_list.txt`; **backup reads that same file**. If a device
  isn't in `ip_list.txt` it won't be backed up (except statically-configured
  controllers, which are merged in separately).
- Coverage safeguard: on a big drop the agent keeps the previous `ip_list`
  rather than shrinking the monitored set — check the log for a coverage warning.

---

## Interface & L2 monitoring (util, CRC, MACs, neighbors)

Two optional background jobs, both off by default, both SNMP-only. They poll
**every switch the agent already knows** when their `include` is blank — no
CIDR list to maintain — skipping unmanaged and icmp-only hosts.

```ini
[interfaces]              # per-port util %, speed, CRC errors, discards
enabled = true
include =                 # blank = all known switches; or "10.40.0.0/24", names, IPs
poll_seconds = 600        # floor 60; a full-fleet sweep must finish inside this
physical_only = true      # ethernetCsmacd ports only
record_metrics = true     # write util time-series to Mongo (needs backend = mongo)
record_zero_util = false  # skip idle (0%) ports — this is where the volume is

[l2]                      # bridge MAC table (FDB) + LLDP/CDP neighbors
enabled = true
include =                 # same semantics as [interfaces]
poll_seconds = 3600       # floor 300; FDB/neighbors change slowly — hourly is plenty
```

- **CRC vs In err.** The table's `CRC` column is `dot3StatsFCSErrors` (real CRC/
  FCS), *not* `ifInErrors` — the latter counts giants from AP jumbo-frame
  negotiation and false-flagged healthy AP ports. A down port with a nonzero
  CRC is a genuine historical error.
- **MAC search.** Top-nav search box (any spelling: `aa:bb:cc:dd:ee:ff`,
  `aabb.ccdd.eeff`, bare) → `/tools/mac`. Shows the **edge port** per switch
  (fewest MACs = access port); tick "show all" for uplink/trunk hits.
- **Neighbor types** come from LLDP capability bits, falling back to the
  sysName/sysDesc when a device (many VoIP phones) doesn't advertise them.
  New phone/AP model not classified? It's a one-line pattern add in `lldp.py`
  (`_TEXT_HINTS`).
- **Scale note.** One sweep of ~108 switches ≈ 100 s at `max_workers = 8`;
  ~450 s for all 481. If a sweep can't finish inside `poll_seconds` you'll see
  `previous cycle still running — skipping this tick` — raise `poll_seconds`
  or `max_workers` (an overlap guard prevents stacking, so it's safe, just
  stale). Start scoped, widen once it looks healthy.

---

## Performance & resources (high load / slow UI / swap)

```bash
PID=$(pgrep -f 'aruba-agent/main.py')
top -bn1 | head -12                 # load avg + who's hot (python vs mongod)
free -m                             # RAM / swap — swapping = the box is too small
ls /proc/$PID/fd | wc -l            # open fds — should be STABLE, not climbing
# metrics collection size (time-series can grow fast if record_zero_util=true)
mongosh --quiet aruba_agent --eval 'db.metrics.countDocuments()'
mongosh --quiet aruba_agent --eval 'db.metrics.stats().size'
```

- **fd count should be flat.** It ramps at startup as the ~481 per-switch
  monitors come online (~4 fds each ≈ ~1900 steady) then holds. A *steady
  climb* is a leak — historically the interface/L2 pool workers leaked an
  asyncio loop's socketpair per sweep (fixed by closing the loop per worker).
- **Metrics are bounded** by a Mongo TTL index (`[store] metrics_retention_days`,
  default 30) plus `record_zero_util = false`. If `db.metrics` is huge from an
  older run, it's safe to drop — nothing reads it yet:
  `mongosh --quiet aruba_agent --eval 'db.metrics.drop()'` (indexes/TTL rebuild
  on next write).
- **Box sizing.** ~481 switches in the one-thread-per-switch model + Mongo want
  headroom: **4–8 GB RAM**. On a 1.6 GB VM the agent (~1.3 GB) + Mongo swap and
  everything crawls. More RAM is the fix; right-size before going fleet-wide.

---

## Config file gotchas

```bash
# Validate config BEFORE restart (catches typos without a half-started service)
python3 -c "import configparser; configparser.ConfigParser().read('/etc/aruba-agent/config.ini'); print('config OK')"
# Find duplicate section headers (each section must appear exactly once)
grep -n '^\[' /etc/aruba-agent/config.ini | sort -t: -k2
```

- **One section each.** A pasted-twice `[store]`/`[interfaces]` gives
  `DuplicateSectionError` and the agent won't start. Merge the keys into the
  first section and delete the extra header. (The agent now logs a clear
  one-liner naming the section + line instead of a raw traceback.)
- **Secrets live here.** `config.ini` is gitignored — never commit it; back it
  up (`cp config.ini config.ini.bak`) before hand-edits.

---

## Deploy / update (reference)

```bash
# DEV (in-place git checkout)
cd /opt/aruba-agent && sudo git pull origin main && sudo systemctl restart aruba-agent
systemctl is-active aruba-agent

# PROD (deploy script — watch for "=== Syncing ===" and "=== Deploy OK ===")
sudo /home/aruba-agent-deploy/bin/deploy.sh
```

If the deploy output only shows a `git pull` with no Syncing/Deploy-OK lines,
the full deploy didn't run (known `deploy.sh` regression) — the new code isn't
live in `/opt`.

---

## Safety reminders

- **Never** commit `config.ini` (real secrets, gitignored) and never delete
  `master.key` — losing it makes every stored secret undecryptable.
- Don't `git add .` — stage explicit files.
- If a password ever lands in a log, chat, or shared doc, **rotate it**.
- Backups decrypt to stdout only; don't leave plaintext configs on disk.
