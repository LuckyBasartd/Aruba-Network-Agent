# Aruba Network Agent

A vendor-neutral monitoring and automation agent for campus switch
infrastructure. Polls Aruba CX, Cisco IOS / IOS-XE, and Arista EOS
switches for reachability, backs up running-configs on a schedule,
discovers devices via ARP, and surfaces it all through a Flask
dashboard with RADIUS or local-with-TOTP login.

Designed to run as a systemd service on **AlmaLinux 10** (also tested
on AlmaLinux 9 / Rocky / RHEL family).

---

## What it does

| Capability | How it works |
|---|---|
| **Switch reachability** | SNMPv3 `sysUpTime.0` poll every 30 s per switch — single UDP round-trip, no session state, identical across vendors. Falls back to vendor REST when SNMP isn't configured. |
| **Auto-discovery** | Scapy ICMP sweep of configured subnets; verified via REST probe so Aruba switches with non-matching DNS names are still picked up. New switches join the monitor pool without a service restart. |
| **Multi-vendor drivers** | Aruba AOS-CX via REST, Cisco / Arista via NAPALM. Vendor is auto-detected by `sysObjectID` on first poll. |
| **Config backup** | Daily download of running-config from every discovered switch; rolling retention; **encrypted at rest** with the agent's master key; SHA-256 sidecar per file. |
| **ARP discovery** | Per-location `show arp` against your routers, deduped + DNS-enriched, written to timestamped CSV. Configurable retention. |
| **Firmware updater** | On-demand parallel compliance check and upload (CLI subcommand, not auto-scheduled). |
| **Web dashboard** | Dark Flask UI with live switch status, free-text search across name / hostname / IP, per-switch backup history, manual Run-Now triggers. |
| **Authentication** | Local accounts (scrypt-hashed) **or** RADIUS PAP; TOTP 2FA for local accounts; rate-limited (5 fails / 15 min); CSRF-protected; session cookies signed with a configurable secret_key. |
| **API tokens** | Scoped bearer tokens (`aat_…`) for scripting the agent from Grafana scrapers, CI backup triggers, etc. — without using operator credentials. |
| **Observability** | Prometheus `/metrics` endpoint (counters + gauges for switches, backups, scans, login failures); `/healthz` liveness probe; separate audit log at `/var/log/aruba-agent/audit.log` with `logrotate.d` integration. |
| **Settings UI** | Edit `config.ini` from the browser — credentials, SMTP, RADIUS, scanner, backup, ARP, firmware, SNMP profiles, web. Restart agent from the page (optional sudoers carve-out). |

---

## Status & version

**Current release: v3.0.2** — see [release notes below](#release-notes--v302).

Production-ready for fleets up to a few hundred switches. Single-node
deployment; HA is on the roadmap.

---

## Quick start

The fastest path from blank AlmaLinux 10 VM to working dashboard:

```bash
curl -fsSL https://raw.githubusercontent.com/LuckyBasartd/Aruba-Network-Agent/main/install.sh \
    | sudo bash
```

The script is idempotent — re-run any time to upgrade. It NEVER
touches `/etc/aruba-agent/config.ini`, `/etc/aruba-agent/master.key`,
or `/var/lib/aruba-agent/*`, so your state and secrets survive.

For a step-by-step walk-through (including SSH deploy-key setup and
the sysadmin-recommended venv + reverse-proxy patterns), see
**[INSTALL-AlmaLinux-10.md](INSTALL-AlmaLinux-10.md)**.

---

## Architecture at a glance

```
                        ┌──────────────────────┐
                        │  Operator browser    │
                        │  (HTTPS, port 443)   │
                        └──────────┬───────────┘
                                   │
                        ┌──────────▼───────────┐
                        │  nginx / Apache      │
                        │  TLS terminator      │
                        │  Security headers    │
                        └──────────┬───────────┘
                                   │  127.0.0.1:8080
                        ┌──────────▼───────────┐
                        │  Flask + waitress    │
                        │  ProxyFix middleware │
                        │  CSRF + rate limit   │
                        └──────────┬───────────┘
                                   │
      ┌───────────────┬────────────┴────────────┬───────────────┐
      │               │                         │               │
┌─────▼─────┐  ┌──────▼──────┐  ┌───────────────▼──────┐  ┌─────▼──────┐
│ Scheduler │  │SwitchMonitor│  │  Web routes          │  │ AgentState │
│ (HH:MM)   │  │ pool        │  │  /api/state /metrics │  │ snapshot   │
└─────┬─────┘  └──────┬──────┘  └──────────────────────┘  └────────────┘
      │               │
      │  ┌────────────┴─────────────┐
      │  │  SNMPv3 sysUpTime poll   │  Drivers (vendor abstraction)
      │  │  30 s, all vendors       │  ┌─────────────┐
      │  │                          │  │ aruba_cx    │ AOS-CX REST
      │  └──────────────────────────┤  │ cisco_ios   │ NAPALM SSH
      │                             │  │ arista_eos  │ NAPALM eAPI
┌─────▼─────────────────────────┐   │  └─────────────┘
│ Tasks                         │   │
│   backup.py    config snapshot│   │  Encrypted at rest
│   scanner.py   ICMP + verify  │   │  ┌──────────────────────┐
│   arp.py       show arp+nmap  │   │  │ secrets_store        │
│   firmware.py  on-demand      │   │  │ Fernet master.key    │
└───────────────────────────────┘   │  └──────────────────────┘
                                    │
                                    ▼
                              Campus switches
```

Full code map: **[STRUCTURE.md](STRUCTURE.md)**.

---

## Supported vendors

| Vendor | Reachability | Backup | ARP | Notes |
|---|---|---|---|---|
| Aruba CX (AOS-CX 10.x) | SNMPv3 ✓ | REST ✓ | `show arp` ✓ | Native — primary target |
| Cisco IOS / IOS-XE | SNMPv3 ✓ | NAPALM ✓ | `show arp` ✓ | Via NAPALM, requires SSH access |
| Cisco IOS-XR / NX-OS | SNMPv3 ✓ | NAPALM ✓ | Limited | NAPALM driver selectable in `[credentials.cisco]` |
| Arista EOS | SNMPv3 ✓ | NAPALM eAPI ✓ | `show arp` ✓ | Requires `management api http-commands` on the switch |
| Aruba AOS-S / AOS-W (legacy) | SNMPv3 ✓ | — | — | Reachability only; falls through to default driver |

Vendor detection is automatic via `sysObjectID` on first SNMPv3 poll.
Operators can pin a specific SNMP profile per-host from the dashboard
when auto-detection picks the wrong one.

---

## Security model

Hardening that's already in the box:

| Layer | What it does |
|---|---|
| **TLS** | Apache or nginx terminator on :443; modern Mozilla intermediate cipher suites; HSTS one year. |
| **Browser security headers** | CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Cache-Control: no-store. Shipped in both Apache and nginx vhosts. |
| **CSRF protection** | flask-wtf on every state-changing route. JSON APIs use `X-CSRFToken` header. |
| **Login rate limiting** | 5 failures / 15 min per (IP, username) → 429. In-memory sliding window. |
| **Encrypted secrets at rest** | Fernet master key encrypts every password / shared secret in `config.ini` plus every backup file. Auto-migrates cleartext on first start. |
| **TOTP 2FA** | Opt-in per local user; RFC 6238 codes + 10 single-use recovery codes. Disabling requires a current code. |
| **Scoped API tokens** | scrypt-hashed bearer tokens with explicit scopes (`state.read`, `backup.trigger`, …). Cleartext shown exactly once. |
| **Audit log** | `/var/log/aruba-agent/audit.log` mode 600 — login success/fail/throttle, password change, settings save, manual trigger, token mint/revoke, 2FA enroll/disable. logrotate daily. |
| **Service isolation** | Runs as a dedicated `aruba-agent` system account with `NoNewPrivileges`, `ProtectSystem=strict`, narrow `ReadWritePaths`. Only one allowed `sudo` rule: restart its own service. |

For incident-response and recovery scenarios:
**[DISASTER-RECOVERY.md](DISASTER-RECOVERY.md)**.

---

## Operational interfaces

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /healthz` | None | Liveness probe (Nagios / Uptime Kuma / kube). |
| `GET /metrics` | Optional bearer token | Prometheus exposition. |
| `GET /api/state` | Session or `state.read` token | Full fleet status JSON. |
| `POST /api/backup/trigger` | Session or `backup.trigger` token | Manual backup run. |
| `POST /api/scanner/trigger` | Session or `scanner.trigger` token | Manual subnet scan. |
| `POST /api/arp/<location>/trigger` | Session or `arp.trigger` token | Manual per-location ARP run. |
| `POST /api/settings/snmp/test` | Session or `snmp.test` token | One-shot SNMPv3 probe against a target host. |

CLI sub-commands of `main.py`:

| Command | Purpose |
|---|---|
| `main.py [config.ini]` | Normal daemon mode (run via systemd, not by hand). |
| `main.py [config.ini] --firmware-update` | On-demand parallel firmware compliance check + upload. |
| `main.py [config.ini] --verify-backups` | Walk `/var/lib/aruba-agent/backups/`, recompute SHA-256, exit 2 on corruption. Wired into `/etc/cron.daily/aruba-agent-verify-backups`. |
| `main.py [config.ini] --decrypt-backup <path>` | Decrypt a single `.cfg.enc` to stdout for restore. |

---

## Repository layout

```
Aruba-Network-Agent/
├── README.md                       # This file
├── INSTALL-AlmaLinux-10.md         # Step-by-step install (start here)
├── DISASTER-RECOVERY.md            # "I locked myself out" runbook
├── STRUCTURE.md                    # Full source-tree map
├── INSTALL.md                      # Original AlmaLinux 9 guide
│
├── install.sh                      # One-command installer (curl | sudo bash)
├── main.py                         # Entry point
├── requirements.txt                # Python deps
├── config.ini.example              # Annotated config template
├── aruba-agent.service             # systemd unit
├── pytest.ini                      # Test config
│
├── apache/aruba-switch-manager.conf  # Apache vhost + security headers
├── nginx/aruba-switch-manager.conf   # nginx vhost + security headers
│
├── scripts/
│   ├── aruba-agent-wrapper.sh           # ExecStart wrapper (venv aware)
│   ├── generate-self-signed-cert.sh     # Self-signed TLS cert helper
│   ├── install-apache.sh                # Idempotent Apache installer
│   ├── aruba-agent.logrotate            # logrotate.d rule for audit.log
│   └── aruba-agent-verify-backups.cron  # Daily backup integrity check
│
├── aruba_agent/                    # The Python package
│   ├── secrets_store.py              # Fernet master key + auto-migration
│   ├── audit.py                      # Structured audit log writer
│   ├── auth.py                       # RADIUS PAP authenticator
│   ├── local_auth.py                 # scrypt user store + TOTP
│   ├── api_tokens.py                 # Scoped bearer tokens
│   ├── metrics.py                    # Prometheus renderer
│   ├── state.py                      # Thread-safe in-memory state + snapshot
│   ├── scheduler.py                  # HH:MM scheduler with ±1m tolerance
│   ├── snmp.py / snmp_profiles.py    # SNMPv3 client + multi-profile registry
│   ├── config_editor.py              # Atomic config.ini I/O for Settings UI
│   ├── notifier.py                   # SMTP notifier
│   ├── drivers/                      # Vendor abstraction (aruba_cx / cisco_ios / arista_eos)
│   ├── monitors/switch_poller.py     # SwitchMonitor pool with alert dedup
│   ├── tasks/                        # backup, scanner, arp, firmware
│   └── web/                          # Flask app + templates
│
├── tests/                          # pytest suite
└── .github/workflows/tests.yml     # GitHub Actions CI
```

---

## Configuration

Every knob lives in `/etc/aruba-agent/config.ini`. The file ships as
`config.ini.example` with annotated defaults — read it once.

Selected highlights:

```ini
[agent]
state_file           = /var/lib/aruba-agent/state.json
master_key_file      = /etc/aruba-agent/master.key
audit_log_file       = /var/log/aruba-agent/audit.log
alert_dedup_minutes  = 5

[snmp]
enabled         = true
default_profile = aruba

[snmp.aruba]
username      = monitoring
auth_protocol = SHA
auth_password = ...        ; auto-encrypted on first start
priv_protocol = AES128
priv_password = ...
context_name  = network

[credentials]
username = admin
password = ...             ; auto-encrypted on first start

[backup]
enabled        = true
schedule       = 02:00
retention_days = 7

[arp.location-1]
enabled        = true
schedule       = 01:00
routers        = 10.253.0.12,10.253.0.13
ip_list        = /etc/aruba-agent/subnets/loc1_ip_list.txt
output_dir     = /var/lib/aruba-agent/arp/location-1
retention_days = 30

[web]
host                  = 127.0.0.1
port                  = 8080
threads               = 16
secret_key            = ...
session_timeout_hours = 8
secure_cookies        = true
trust_proxy_headers   = true
metrics_token         =                ; blank = open scrape; set for Bearer auth
```

Sensitive fields (passwords, secrets, keys) are encrypted in place on
first start. The Settings UI re-encrypts new values on save.

---

## Development

```bash
git clone git@github.com:LuckyBasartd/Aruba-Network-Agent.git
cd Aruba-Network-Agent
python3 -m venv venv
. venv/bin/activate
pip install -r requirements.txt
pip install pytest

pytest tests/ -v
```

Tests cover encryption roundtrip + migration, audit-log formatting,
SNMP profile parsing, AOS-CX ARP parser, scheduler tolerance window,
backup checksum verification, and the metrics renderer. GitHub
Actions runs the suite on Python 3.10 and 3.12 against every push to
`main` and every PR.

---

## Release notes — v3.0.2

This release is the cumulative production-hardening pass on top of
v3.0.0. Five distinct phases of work, all backward-compatible with
existing deployments:

**Initial security layer**
- Fernet-encrypted secrets at rest (auto-migration of cleartext)
- Switch table free-text search

**Tier 1 — hardening**
- Unauthenticated `/healthz` liveness probe
- ARP CSV retention policy
- Structured audit log file, separate from journald, with logrotate
- Login rate limiting (5 fails / 15 min per IP+username)
- CSRF protection app-wide

**Tier 2 — reliability + observability**
- Alert deduplication on switch flap
- SHA-256 sidecar checksums on every backup; `--verify-backups` CLI
- pytest harness + GitHub Actions CI on Python 3.10 / 3.12
- Prometheus `/metrics` endpoint with bearer-token auth

**Tier 3 — advanced security**
- Encrypted backup files at rest (`.cfg.enc`); `--decrypt-backup` CLI
- Scoped API tokens with `@require_session_or_scope`
- TOTP 2FA on local accounts with one-time recovery codes

**Operational polish (v3.0.2 finalisation)**
- Security headers on both Apache and nginx vhosts (CSP, HSTS,
  Permissions-Policy, etc.)
- Daily backup-integrity cron with mail-on-failure
- Disaster recovery runbook
- Python runtime moved into a per-install venv (no more pip-as-root)
- Updated install guide incorporating sysadmin feedback (deploy keys
  instead of personal SSH keys, `/opt/aruba-agent-src` instead of
  `/tmp`, explicit venv guidance)
- nginx as a first-class reverse-proxy option alongside Apache

---

## Roadmap (post-v3.0.2)

| Item | Why it's deferred |
|---|---|
| HA / second agent host | Multi-day architectural work — needs a coordination backend (etcd / postgres advisory locks / shared flock). Worth a separate design session. |
| pysnmp 6.2+ asyncio migration | Major refactor of the hottest code path. Pin to `pysnmp<6.2` works fine today; this is "future-proof" work, not "ship now." |
| Email-based password reset | Requires a one-time-token table and a recovery email flow. Currently you `sudo nano /var/lib/aruba-agent/users.json`. |
| Audit log forwarding to SIEM | The audit file is in the right place; this is rsyslog / syslog-ng config plumbing. |
| TLS cert auto-rotation | Self-signed cert + renewal script + systemd timer. Most operators already have an external PKI flow. |

None of these are security gaps. The agent is shippable as-is for the
threat model it targets (campus monitoring, internal LAN, ~few hundred
switches).

---

## License

This project is internal to its operator. See `LICENSE` if present in
this repository.

---

## Acknowledgements

Vendor abstractions stand on the shoulders of [NAPALM](https://napalm.readthedocs.io)
(Cisco / Arista), [pysnmp](https://pypi.org/project/pysnmp/) (SNMPv3),
[pyrad](https://pypi.org/project/pyrad/) (RADIUS), and the
[cryptography](https://pypi.org/project/cryptography/) library
(Fernet). The dashboard is built on Flask, waitress, Bootstrap 5, and
Bootstrap Icons.
