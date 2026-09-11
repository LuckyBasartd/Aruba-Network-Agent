# CLAUDE.md — Network Agent

Working context for AI assistants (and humans) picking up this project cold.
Read this first, then `README.md` / `STRUCTURE.md` for deeper detail.

---

## 1. What this is

**Network Agent** (formerly "Aruba Network Agent") is a vendor-neutral network
monitoring + configuration-management application built to **replace a
SolarWinds NMS appliance at the University of San Diego (USD)**. It is a
self-hosted Flask app, server-rendered with Jinja2 + Bootstrap 5.3 (dark
theme). No SPA, no build step.

The SolarWinds features it must reach parity with (the "core" USD workflows):
- Up/Down alerting (email)
- Nightly configuration backups
- Running-config saves (write mem)
- Automated new-device discovery
- Batch configuration changes
- SNMP monitoring for events

Brand note: the product is called **Network Agent** in the UI and email
subjects (`[Network Agent] ...`). The Python package is still `aruba_agent`
and the systemd service is still `aruba-agent` — those were intentionally
left alone (only cosmetic/branding was renamed).

---

## 2. Repos, environments, deploy

**Git remotes:**
- `origin`     → https://github.com/LuckyBasartd/Aruba-Network-Agent.git  (**dev / personal**)
- `production` → https://github.sandiego.edu/NISS/Network-Agent.git       (**USD enterprise / prod**)

**Versioning:** annotated tags `vX.Y.Z`. Current line: **v3.5.0** (see §9).
`aruba_agent/__init__.py __version__` is a separate internal string ("1.0.0")
and is NOT the release version — the git tag is the source of truth.

**Dev server** (`/opt/aruba-agent`): an in-place git checkout. Deploy dev with:
```bash
# on your Mac
cd "<workspace>"; git push origin main
# on the dev server
cd /opt/aruba-agent && sudo git pull origin main && sudo systemctl restart aruba-agent
```

**Production** (host `argos-2026`, URL **https://arubaagent.sandiego.edu**):
deployed via a script, NOT an in-place checkout.
```bash
git push production main
git push --force production vX.Y.Z          # move/publish the tag if needed
sudo /home/aruba-agent-deploy/bin/deploy.sh
```
`deploy.sh` steps: pull `--ff-only` into `/home/aruba-agent-deploy/src/Network-Agent`
→ rsync into `/opt/aruba-agent` (venv + `/etc` config left untouched) → clear
bytecode → `pip install -r requirements.txt` → restore perms → `systemctl
restart aruba-agent` → healthcheck.
**WATCH THE OUTPUT** for `=== Syncing ===` and `=== Deploy OK ===`. This script
has more than once been reverted on the server to a pull-only stub (just
`git pull` + `git log`, no sync/restart). If those lines are missing, the
full deploy did not run — re-install the complete `deploy.sh` (a known-good
copy lives in this session's outputs history / ask the user).

**Runtime paths on the servers:**
- Config:   `/etc/aruba-agent/config.ini`, `/etc/aruba-agent/ip_list.txt`
- State:    `/var/lib/aruba-agent/state.json`
- Backups:  `/var/lib/aruba-agent/backups/<hostname>/...`
- Service:  `systemctl status|restart aruba-agent`; live logs: `journalctl -u aruba-agent -f`

---

## 3. SECURITY — read before touching anything

- **`config.ini` contains real secrets and is gitignored. NEVER commit it.**
  Use `config.ini.example` for documentation of sections/keys.
- **`master.key` encrypts all secrets (Fernet). Losing it is unrecoverable** —
  every stored password/secret becomes undecryptable. Never delete/commit it.
- Credentials in `config.ini` are Fernet-encrypted; decrypt via
  `secrets_store.decrypt()` (needs a `SecretManager` seeded with `master.key`).
- **Do NOT use `git add .`** — it sweeps in WIP, `.DS_Store`, the `github/`
  folder (a prod clone kept on disk, gitignored), backups, etc. Always stage
  explicit files/paths.
- Backups **decrypt in memory only** — plaintext config must never land on disk.
- If any credential is ever pasted in plaintext into a chat/PR/log, treat it as
  compromised and **rotate it** (this has happened at least once with an SNMP
  priv password).
- `github/` and `config.ini` and `master.key` are gitignored and kept on disk.

---

## 4. Architecture

Flask app factory in `aruba_agent/web/app.py`. A background **scheduler**
(`scheduler.py`) runs the periodic tasks. A **poller** thread keeps switch
reachability/identity fresh. All shared runtime state lives in one
`AgentState` snapshot persisted to `state.json`.

```
main.py                      entry point; daemon + CLI modes (--firmware-update,
                             --verify-backups, --decrypt-backup)
aruba_agent/
  state.py                   AgentState / SwitchState; to_dict() drives /api/state
  scheduler.py               fires backup / scanner / ARP per config schedule
  notifier.py                EmailNotifier (SMTP)
  alert_batcher.py           coalesces up/down alerts into ONE email (60s window)
  secrets_store.py           Fernet encrypt/decrypt + redact()
  snmp.py / snmp_profiles.py SNMPv3 (pysnmp) + SnmpProfile registry
  manual_hosts.py            manually-pinned hosts/profiles
  audit.py / metrics.py      audit log + /metrics
  auth.py local_auth.py passkeys.py api_tokens.py   login, 2FA, WebAuthn, tokens
  monitors/
    switch_poller.py         reachability ladder, vendor/os backfill, mute checks
  drivers/
    base.py                  SwitchDriver Protocol + Facts/ArpEntry dataclasses
    detector.py              vendor detection (sysObjectID + sysDescr)
    factory.py               driver_for(...) — routes by vendor_hint
    aruba_cx.py              AOS-CX 6300/6400 over REST (cx_session.py)
    aruba_os.py              Aruba OS-S / ProCurve over SSH (netmiko hp_procurve)
    cisco_ios.py             Cisco IOS/IOS-XE via NAPALM (ios)
    arista_eos.py            Arista EOS via NAPALM (eos)
  tasks/
    backup.py                nightly config backup (save→startup, download, encrypt, retain)
    scanner.py               OS-ping subnet sweep -> device discovery (ip_list)
    arp.py                   per-location ARP discovery
    config_push.py           batch CLI config push (netmiko, multi-vendor)
    firmware.py              on-demand firmware update
  web/
    app.py                   all routes (see §7)
    templates/*.html         Jinja templates (see §7)
```

---

## 5. Vendor detection & driver routing (IMPORTANT)

`drivers/detector.py` classifies a switch into a **vendor key**:
`aruba_cx`, `aruba_os`, `cisco_ios`, `arista_eos`.

1. **sysObjectID prefix** (authoritative):
   - `1.3.6.1.4.1.47196` → `aruba_cx`
   - `1.3.6.1.4.1.14823` → `aruba_os`   (Aruba/HP)
   - `1.3.6.1.4.1.11`    → `aruba_os`   (old HP/HPE ProCurve)
   - `1.3.6.1.4.1.9`     → `cisco_ios`
   - `1.3.6.1.4.1.30065` → `arista_eos`
2. **sysDescr keyword fallback** (order matters): `ArubaOS-CX`/`Aruba JL`→aruba_cx;
   `ProCurve`/`HP J`→aruba_os; generic `Aruba`→aruba_os; `Cisco *`→cisco_ios;
   `Arista`/`EOS-`→arista_eos.

`factory.driver_for(host, user, pw, *, vendor_hint=..., <per-vendor overrides>)`
returns the right driver. **Manually-pinned SNMP profiles skip the detector**,
so `switch_poller._maybe_resolve_vendor()` backfills `vendor` from the pinned
profile's sysObjectID/sysDescr when it's empty.

**UI label:** `aruba_os` is displayed as **"Aruba OS-S"** everywhere
(`VENDOR_LABEL` in dashboard.html, `vlabel` in switch_detail.html).

### Per-vendor backup transports
| vendor      | driver          | transport                    | save cmd        |
|-------------|-----------------|------------------------------|-----------------|
| aruba_cx    | ArubaCXDriver   | HTTPS REST `/rest/v10.x` :443| REST write-mem  |
| aruba_os    | ArubaOSDriver   | **SSH CLI (netmiko hp_procurve)** | `write memory` |
| cisco_ios   | CiscoIOSDriver  | SSH via NAPALM (ios)         | `write memory`  |
| arista_eos  | AristaEOSDriver | NAPALM (eos, https)          | NAPALM          |

**Why aruba_os is special:** ProCurve / ArubaOS-Switch (2530/2930F/3810 and
6000/6100-class) have **no REST API** — the CX driver's :443 login just times
out or refuses. They MUST go over SSH. This was the root cause of the
"Login failed (aruba_cx): ... timed out" errors on ProCurve IPs.

### aruba_os driver gotchas (already handled, don't regress)
- netmiko's `hp_procurve` session-prep sends a `terminal width` command that
  6000/6100 boxes reject (`Invalid input: width`), leaving noise in the read
  buffer → we **`clear_buffer()` after login**.
- `write memory` shows a `Copying configuration: [\|/-]` spinner for 10-20s and
  prints `[Success]`. Save detection: success if output contains "success";
  else fail only on a real rejection (`invalid input`/`unknown command`/etc.);
  silent output (older 2530) is treated as success. Uses `send_command`
  (waits for prompt, 120s), NOT `send_command_timing` (which scooped stale
  prep output and caused false failures).
- Needs manager (enable) privilege for `show running-config`. If the account
  is operator-level, set `[credentials.aruba_os] enable_secret`.

### cisco_ios driver gotchas
- Slow 2960CX/3560 gear overran netmiko's default read window → "Pattern not
  detected" / ReadTimeout. Driver now opens with `read_timeout_override=60`,
  `global_delay_factor=2`, `fast_cli=False` (via NAPALM optional_args). Tunable
  via `[credentials.cisco] read_timeout` and `global_delay_factor`.

---

## 6. Reachability, maintenance, alerts

- **Reachability ladder** (`switch_poller._poll_reachability`): SNMP → ICMP → SSH.
  SNMP ok = **Up**. SNMP fail → ICMP fail = **Down**. ICMP ok → SSH ok = **Up
  but SNMP-degraded** (dashboard shows an SNMP warning; no email for degraded).
- **Maintenance mode** (per switch, like SolarWinds): **mute** alerts
  (indefinite or timed via `mute_until`) and/or **unmanage** (skip polling
  entirely). State: `alerts_muted`, `mute_until`, `unmanaged`. API:
  `/api/switches/<name>/{mute,unmute,unmanage,manage}`. `alerts_suppressed()`
  auto-clears expired mutes.
- **Alert emails**: coalesced by `AlertBatcher` into a single email per 60s
  window (subject `[Network Agent] N switches DOWN`), and show **hostname**
  (not just IP). Restored events batch too.

---

## 7. Web UI map

Shared chrome: `_topnav.html` (brand "Network Agent"; tabs **Dashboard / Jobs /
Settings**; `active_nav` var). `_settings_chrome.html` wraps settings sub-pages
(blocks: content/heading/crumb + CSRF-aware fetch). Dark GitHub palette
(#0d1117 / #161b22 / #30363d, accent #58a6ff).

- **`/` dashboard.html** — `/api/state` polled client-side. Rows:
  1. **Metric cards** (Total / Up / Down / Unmanaged) — clickable status filters.
  2. **Switch Reachability** panel — Table/Group(vendor→status) toggle, search.
     Switch names link to `/switch/<name>`.
  3. **Needs attention** panel + **Fleet overview** panel (replaced the old
     Scanner/ARP/Backup cards, which now live on Jobs). Needs-attention chips
     (**Down / SNMP / Muted / Unmanaged / Backup fails**) are **clickable tabs**
     that filter the list; Backup-fails tab shows each device's failure reason;
     active tab persists in `localStorage`. Fleet overview = per-vendor bars,
     up/down/unmanaged, last backup result, discovery count.
- **`/switch/<name>` switch_detail.html** — status/identity/config-backups cards
  + maintenance bar (mute/unmute/unmanage/manage).
- **`/jobs` jobs.html** — live table from `/api/jobs` (Backup/Scanner/ARP:
  schedule/status/last/next/result + run-on-demand). Header has a **Batch config**
  button → `/config-push`.
- **`/config-push` config_push.html** — batch CLI config push (multi-vendor,
  one vendor per batch), template CRUD.
- **`/settings` settings.html** — card-grid landing → sub-pages: auth, api-tokens,
  manual-hosts, 2fa, passkeys, email, snmp (+ profiles), credentials
  (+ cisco/arista), scanner, backup, firmware, web.

Key APIs: `/api/state`, `/api/jobs`, `/api/switches/<name>/{mute,...}`,
`/api/config-push/execute`, `/healthz`, `/metrics`.

---

## 8. config.ini sections

`[agent] [snmp] [credentials] [credentials.cisco] [credentials.arista]
[smtp] [web] [local_auth] [radius] [switch.<name>] [scanner] [backup]
[arp.<location>] [firmware]`

New / notable keys:
- `[credentials.aruba_os]` — optional `username` / `password` / `enable_secret`
  for ProCurve SSH. Omit to reuse the default `[credentials]` account.
- `[credentials.cisco]` — `read_timeout` (default 60), `global_delay_factor`
  (default 2), plus `username/password/enable_secret/napalm_driver/key_file`.
- Enterprise SMTP: unauthenticated relay on port 25 is supported (USD prod has
  no auth; the dev box authenticates to Gmail). Sysadmin prefers sendmail —
  a sendmail transport is a deferred TODO.

---

## 9. Current state (as of v3.5.0)

`v3.5.0` on dev `main` bundles: full UI redesign (modern shell/nav, Home,
breadcrumbs, rebrand to "Network Agent"); dashboard metric cards + grouped
reachability view + `/switch/<name>` detail + live `/jobs` page; vendor
backfill for pinned profiles; ProCurve → "Aruba OS-S" labeling; maintenance
mode (mute/unmanage); coalesced hostname alert emails; dashboard
Needs-attention (tabbed) + Fleet-overview panels; **ProCurve SSH backup driver
+ save-detection fix**; **Cisco read-timeout tolerance**; Jobs Batch-config link.

**Deploy status:** all of the above is on dev. **v3.5.0 has NOT yet been pushed
to production** — promote per §2 when the user is ready.

**Backup failures triage** (from a full prod run): ProCurve (aruba_os) and slow
Cisco failures are FIXED in code. Remaining are **environmental**, needing
switch-side action, not code:
- Auth failures (CX + some Cisco/ProCurve): monitoring account invalid on those boxes.
- :443 refused/timeout: REST not enabled, OR a non-CX switch still misclassified
  as `aruba_cx` (check/pin its vendor to `aruba_os`).
- SSH unreachable / device down.
- `10.40.0.222` (MFCDC120-6300M, real CX): "Save failed" with a **blank error**
  — the AOS-CX save path swallows the reason. Open code-side lead: add error
  surfacing to `cx_session` save so it's diagnosable.

**Deferred (user-aware) TODOs:** sendmail transport; SNMP trap-based event
monitoring (PSU/temp/VSF/LAG) for fuller SolarWinds parity; better AOS-CX save
error surfacing.

---

## 10. Working notes for the AI agent (dev sandbox constraints)

This app is edited from a Cowork/Claude sandbox with specific quirks:
- **File tools (Read/Edit/Write) hit `EPERM` on the workspace.** Do edits and
  reads through **bash** at the mounted path
  `/sessions/<session-id>/mnt/Network Agent/` (the session id changes per
  session; check the "Shell access" mapping). Use `python3` heredocs with
  exact-string `assert count==1` replacements, or `sed`/`cat`.
- **No ICMP** in the sandbox (can't ping real switches). **No PyPI network**
  (can't `pip install`; netmiko/napalm ship transitively but aren't importable
  in-sandbox for live runs).
- **Testing without hardware:**
  - Jinja render checks: `jinja2.Environment(..., undefined=ChainableUndefined)`
    with stubbed `url_for`/`csrf_token`/`get_flashed_messages`.
  - JS: extract the last `<script>` block and `node --check`.
  - Drivers/logic: inject a **fake `netmiko`/`napalm` module into
    `sys.modules`** and exercise the driver methods (see prior commits' test
    harnesses — mock ConnectHandler / get_network_driver, assert on
    `optional_args`, success/failure detection, factory routing).
  - `python3 -m py_compile` every changed .py.
- **str.replace pitfall:** indentation-only-different lines can be substrings of
  each other (e.g. a 20-space vs 24-space line) → `count()` mismatch aborts a
  multi-edit script and writes nothing. Use newline-anchored, unique patterns.
- **Workflow:** make change → py_compile / render-check / node --check /
  mock-test → `git add <explicit files>` → commit → (usually) move the `v3.5.0`
  tag forward with `git tag -d` + `git tag -a`. Never `git add .`.

## 11. Subnet-health job (wireless distro ARP monitor)

`aruba_agent/tasks/subnet_health.py` (`SubnetHealthTask`) — a **self-contained**
nightly job, independent of backup/scanner/ARP/poller (shares no state, only
scheduled when `[subnet_health] enabled = true`; imported only when enabled).

What it does: SSHes (netmiko) to the wireless distros (default 10.253.0.30 /
.31), runs `show arp`, extracts all IPv4s, buckets them into the configured
/24 wireless subnets, computes utilization = distinct active IPs / usable
(254), and **emails** when a subnet is **< low_pct** (likely IP-helper / DHCP
broken — clients not getting leases) or **> high_pct** (pool near exhaustion).
Runs 03:00 by default. Stays quiet when everything is healthy.

Fail-safe: if it can't read ARP from the distros (both unreachable / zero IPs
parsed) it sends a distinct "FAILED to collect ARP" email rather than flagging
every subnet as low — a collection failure can't masquerade as an outage.

Config: `[subnet_health]` in config.ini (see config.ini.example): `enabled`,
`schedule`, `distros`, `device_type` (aruba_aoscx | hp_procurve | cisco_ios),
`arp_command`, `low_pct` (10), `high_pct` (90), `usable_per_subnet` (254),
`subnets_file` (default `/etc/aruba-agent/wireless_subnets.txt` — writable
by the service so the GUI can edit it), `ignore` (subnets/labels to never
alert on), optional inline `subnets`, and optional cred overrides (blank =
reuse `[credentials]`). The subnet list ships as `wireless_subnets.txt`
(`<label> <CIDR>` per line, 124 VLANs) — deploy to
the repo root and rides to `/opt/aruba-agent/wireless_subnets.txt` via `git pull` (dev) or `deploy.sh` (prod). NOTE: prod's `deploy.sh` only rsyncs `aruba_agent/`+`main.py`+`requirements.txt`, so it needs a one-line `cp` for root-level data files like this one (already added to the reference deploy.sh).

Editable from the web GUI at **Settings -> Subnet Health**
(`/settings/subnet-health`): enable/schedule/distros/device_type/thresholds/
ignore, plus the whole subnet list in a textarea, and a **Run now** button
(`POST /api/settings/subnet-health/run`) that reads ARP live and shows the
low/high table without emailing. The GUI writes the subnet list to
`subnets_file`, which must be service-writable (hence /etc, not the
read-only /opt checkout). The repo `wireless_subnets.txt` is the initial seed.

Test on demand (no waiting for 03:00): `python main.py <config.ini> --subnet-health`
— prints per-subnet low/high results and sends the email if any are flagged.

Caveat: ARP reflects *active* hosts, so a legitimately quiet subnet at 3am can
read low. Tune `low_pct` / `high_pct` if it's noisy.

## 12. AOS-8 controllers + VPN web-server job

**AOS-8 Mobility controllers** (Conductors/ArubaMM, 9240 MCs, 9004 VPN) are a
distinct platform from AOS-CX and from Aruba OS-S/ProCurve — SSH/CLI only, no
REST. Vendor key `aruba_aos8`, driver `drivers/aos8.py` (netmiko device_type
`aruba_os`), labeled "Aruba AOS-8" in the UI. Do NOT confuse with `aruba_os`
(ProCurve, netmiko `hp_procurve`).

- Driver: `show running-config`, `write memory`, `cli()`, and a flash-backup
  path (`backup flash` then pull `flashbackup.tar.gz` via paramiko SFTP/SCP,
  falling back to running-config text if the box won't hand the archive over).
- `factory.driver_for` routes `aruba_aos8` with `aos8_*` creds (reuse default).
- detector: sysDescr keywords ("Wireless Operating System", ArubaMM, Aruba9240,
  Aruba9004, "Mobility Controller/Conductor") -> aruba_aos8. NOTE the SNMP OID
  prefix .14823 still maps to aruba_os, so controllers are **pinned** by config
  rather than SNMP-detected.
- `[controllers]` section: `enabled`, `hosts` ("name:ip" list), `vendor`,
  `monitor`, `monitor_mode`, `backup`, `backup_mode` (running-config default; flash needs the controller to PUSH the archive to a TFTP/SCP receiver — AOS-8 does not serve it for pull, so flash falls back to running-config).
  main.py preseeds them into the monitor manager (dashboard reachability) and
  pins their vendor (`state.pin_vendor`); backup.py merges their IPs into the
  nightly run and forces the aos8 driver. Optional `[credentials.aos8]`.
- Test on demand: `python main.py <cfg> --controller-backup` (dry-run, no files
  written — prints login/save/capture per controller).

**VPN web-server watchdog** (`tasks/webserver_health.py`, `WebServerHealthTask`):
SSHes to the VPN controller, runs `show web-server statistics`, and emails
(alert-only) when it is not responding (fail-pattern match, empty output, or
SSH/command failure). `[webserver_health]` section: `enabled`, `host`,
`interval_minutes` (default 60), `command`, `device_type`, `fail_patterns`.
Scheduled via the new `Scheduler.add_interval(seconds, fn)` (sub-daily cadence;
60s tick granularity). Test: `python main.py <cfg> --webserver-check`.

Both are editable in the web GUI: **Settings -> Controllers** (`/settings/controllers`; enable/monitor/backup toggles, monitor & backup modes, the name:ip host list, plus a **Test backup** dry-run button — saving registers/removes them in the live monitor manager so they appear in up/down monitoring without a restart) and **Settings -> Web-Server Watchdog** (`/settings/webserver-health`; host, interval, command, fail patterns, and a **Run now** button). Landing cards added to settings.html.

Scheduler now supports both daily `add("HH:MM", fn)` and interval
`add_interval(seconds, fn, run_at_start=False)` tasks.

## 13. Other docs
`README.md`, `STRUCTURE.md`, `INSTALL.md`, `INSTALL-AlmaLinux-10.md`,
`DISASTER-RECOVERY.md`, `config.ini.example`.
