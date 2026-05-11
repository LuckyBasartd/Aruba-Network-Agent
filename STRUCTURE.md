# Repository structure

Source-tree map of the Aruba Network Agent. Generated against
**v3.0.1**.

```
Aruba-Network-Agent/
├── README.md                     Project overview + quick-start pointers
├── INSTALL.md                    Original AlmaLinux 9 install guide
├── INSTALL-AlmaLinux-10.md       AlmaLinux 10 install (with SSH-key + v3.0.1 steps)
├── STRUCTURE.md                  This file
│
├── main.py                       Entry point — daemon mode + --firmware-update CLI
├── requirements.txt              Python deps: flask, waitress, requests, urllib3,
│                                 scapy, pyrad, pysnmp<6.2, napalm
├── config.ini.example            Annotated template config; copied to
│                                 /etc/aruba-agent/config.ini at install time
├── aruba-agent.service           systemd unit (User=aruba-agent, Restart=always)
│
├── apache/
│   └── aruba-switch-manager.conf Vhost: TLS terminate on :443, reverse-proxy
│                                 to waitress on 127.0.0.1:8080
│
├── scripts/
│   ├── generate-self-signed-cert.sh   Issues the agent TLS cert with auto-detected
│   │                                  hostname + IP SANs
│   └── install-apache.sh              Installs httpd, fixes AlmaLinux 10's
│                                      ssl.conf / welcome.conf quirks, sets
│                                      SELinux + firewalld
│
└── aruba_agent/                  Python package — every runtime module lives here
    ├── __init__.py
    │
    ├── secrets_store.py          v3.0.1: Fernet master key + auto-migrate
    │                             cleartext config.ini → enc:<token>
    │
    ├── state.py                  Thread-safe in-memory state + JSON snapshot
    │                             persistence (survives restarts/reboots)
    ├── scheduler.py              HH:MM cron-style scheduler with ±1 min
    │                             tolerance window
    ├── notifier.py               SMTP email notifier (shared by tasks)
    │
    ├── auth.py                   RADIUS PAP authenticator (pyrad-backed)
    ├── local_auth.py             Local user store — scrypt hashes, JSON-backed,
    │                             bootstraps admin/admin must_change on first run
    │
    ├── config_editor.py          Read/write /etc/aruba-agent/config.ini
    │                             atomically; powers the Settings UI
    │
    ├── snmp.py                   SNMPv3 GET helper (sysUpTime / sysName /
    │                             sysObjectID); pysnmp wrapper with thread-local
    │                             engine cache
    ├── snmp_profiles.py          Multi-profile registry (one [snmp.<name>] per
    │                             credential set; backward-compat with single
    │                             [snmp] block)
    │
    ├── cx_session.py             Legacy AOS-CX REST session (pre-driver-pivot;
    │                             still referenced by some helpers)
    ├── conductor_session.py      Aruba Central / Conductor REST session helper
    │
    ├── drivers/                  Vendor-neutral driver abstraction
    │   ├── __init__.py           Re-exports driver_for() factory
    │   ├── base.py               BaseDriver protocol — get_running_config,
    │   │                         save_running_to_startup, cli, etc.
    │   ├── factory.py            driver_for() — picks the right driver based
    │   │                         on vendor hint or detection
    │   ├── detector.py           VendorDetector — classifies by sysObjectID
    │   │                         (Aruba / Cisco / Arista) on first SNMP poll
    │   ├── aruba_cx.py           AOS-CX REST driver (login → ops → logout)
    │   ├── cisco_ios.py          Cisco IOS / IOS-XE / IOS-XR / NX-OS via NAPALM
    │   └── arista_eos.py         Arista EOS via NAPALM eAPI (HTTPS)
    │
    ├── monitors/                 Continuous background pollers
    │   ├── __init__.py
    │   └── switch_poller.py      30-second reachability poll; SwitchMonitor
    │                             per host; pool managed by SwitchMonitorManager;
    │                             scanner.sync() hands it newly discovered IPs
    │
    ├── tasks/                    Scheduled jobs
    │   ├── __init__.py
    │   ├── scanner.py            Network scanner — Scapy ICMP sweep, AOS-CX
    │   │                         REST verify path for non-keyword matches
    │   ├── backup.py             Config backup — save running→startup, download,
    │   │                         rolling retention, email summary
    │   ├── arp.py                Per-location ARP discovery — nmap sweep +
    │   │                         "show arp" parse → timestamped CSV
    │   └── firmware.py           On-demand firmware updater (two-phase parallel
    │                             upload via --firmware-update CLI flag)
    │
    └── web/                      Flask + waitress dashboard
        ├── __init__.py
        ├── app.py                Routes — /login, /, /api/state, /settings/*,
        │                         /api/backup/trigger, /api/scanner/trigger,
        │                         /api/snmp/test, etc. ProxyFix when behind Apache.
        └── templates/
            ├── _settings_chrome.html              Shared sidebar+layout for /settings/*
            ├── login.html                         Login form (local + RADIUS)
            ├── change_password.html               Forced-rotation page on first login
            ├── dashboard.html                     Main dashboard — switches table
            │                                      with v3.0.1 free-text search
            ├── settings.html                      Settings landing page
            ├── settings_auth.html                 RADIUS + local users editor
            ├── settings_email.html                SMTP editor + Send-test button
            ├── settings_credentials.html          Default switch credentials
            ├── settings_cisco_credentials.html    Cisco-specific creds
            ├── settings_arista_credentials.html   Arista-specific creds
            ├── settings_snmp.html                 SNMPv3 profile list (CRUD)
            ├── settings_snmp_profile.html         Per-profile credential form
            ├── settings_scanner.html              Network scanner config
            ├── settings_backup.html               Backup schedule + retention
            ├── settings_arp.html                  Per-location ARP config
            ├── settings_firmware.html             Firmware update preferences
            └── settings_web.html                  Web server config + secret_key regen
```

---

## On-disk layout after install

These directories live *outside* the source tree and are populated by
`install-apache.sh`, the rsync deploy, and the agent at runtime.

```
/opt/aruba-agent/                              Deployed code (rsync target)
├── aruba_agent/                               Mirror of repo's aruba_agent/
├── main.py
└── requirements.txt

/etc/aruba-agent/                              Config + secrets
├── config.ini                                 Operator-edited config (mode 640)
├── config.ini.bak                             One-time backup written by the
│                                              first secrets migration; safe to
│                                              delete after verifying restart
├── master.key                                 Fernet key (mode 600, agent-owned)
│                                              ⚠ BACK THIS UP — losing it means
│                                              re-entering every password
└── subnets/                                   Optional per-location subnet lists
    └── <location>_ip_list.txt

/var/lib/aruba-agent/                          Runtime data (agent-owned)
├── state.json                                 Snapshot — switches, last backup,
│                                              scanner inventory, ARP timestamps
├── users.json                                 Local user store (scrypt, mode 600)
├── ip_list.txt                                Discovered switch IPs (scanner output)
├── network_devices.csv                        Full device inventory from scanner
├── backups/<hostname>/                        Rolling config backups per switch
│   └── <hostname>-startup-config-<ts>.cfg
├── arp/<location>/arp_scan_<ts>.csv           Per-location ARP CSVs
└── firmware/                                  Drop .swi images here for updates

/etc/systemd/system/
└── aruba-agent.service                        Copied from repo's aruba-agent.service

/etc/httpd/conf.d/
└── aruba-switch-manager.conf                  Copied from repo's apache/

/etc/pki/tls/certs/aruba-switch-manager.crt    Self-signed by generate-…-cert.sh
/etc/pki/tls/private/aruba-switch-manager.key

/etc/sudoers.d/aruba-agent-restart             Optional NOPASSWD for Settings →
                                               Restart Now button
```

---

## Reading order for someone new to the code

If you're picking this up cold, here's a sensible order to walk it:

1. `main.py` — wires everything together.
2. `aruba_agent/state.py` — the in-memory model every other module reads/writes.
3. `aruba_agent/scheduler.py` — how scheduled tasks actually fire.
4. `aruba_agent/monitors/switch_poller.py` — the reachability loop +
   per-host SwitchMonitor lifecycle.
5. `aruba_agent/drivers/base.py` then `factory.py` then `detector.py` —
   how the agent talks to switches regardless of vendor.
6. `aruba_agent/tasks/backup.py` — small, self-contained example of a
   driver-using task. Then scanner/arp/firmware once you have the pattern.
7. `aruba_agent/web/app.py` — Flask routes. Long file, but each route
   is independent so you can scan top-to-bottom.
8. `aruba_agent/secrets_store.py` — the v3.0.1 encryption layer. Useful
   to read after you've seen a few of the call sites that use it.
