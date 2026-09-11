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
