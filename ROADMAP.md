# Network Agent — Architecture & Roadmap

Vision: replace **SolarWinds** (wired NMS) and then **Aruba AirWave** (wireless
management) with one self-hosted, enterprise-grade system at USD. This doc
captures the architecture decisions and the phased plan. Companion to
`CLAUDE.md` (how the code works today) and `TROUBLESHOOTING.md`.

Status legend: ✅ done · 🔨 in progress · ⬜ planned · ❓ decision needed

---

## 1. Where we are (v3.5.0, live in prod)

✅ Vendor-neutral reachability monitoring (SNMP→ICMP→SSH ladder), dashboard,
per-switch detail, maintenance mode (mute/unmanage), coalesced email alerts.
✅ Nightly encrypted config backups (AOS-CX, Aruba OS-S/ProCurve, Cisco IOS,
Arista, AOS-8 controllers) with retention + SHA-256 verification.
✅ Batch config push, network discovery/scanner, ARP discovery.
✅ AOS-8 Mobility controllers (5 wireless + 1 VPN) monitored + backed up.
✅ Subnet-health job, VPN web-server watchdog, in-app encrypted Help.
✅ Auth: local + RADIUS + TOTP 2FA + passkeys + API tokens; CSRF; audit log;
Fernet-encrypted secrets; atomic state writes; systemd Restart=on-failure.
✅ Prometheus `/metrics` endpoint; partial pytest suite.

**Good bones.** The gaps below are about *scale, history, and breadth*, not
fixing what's broken.

---

## 2. The pivotal decision: data layer  ❓→ leaning MongoDB

All state lives in a single in-memory `state.json` rewritten on every change.
Fine for ~475 switches of *current* state; two hard ceilings ahead:
1. **No history** — SolarWinds/AirWave are mostly time-series (utilization,
   CPU/mem/temp, client counts, RF trends). A snapshot can't hold it.
2. **Volume** — AirWave means thousands of APs + tens of thousands of clients,
   sampled continuously; a full-file JSON rewrite under one lock won't take it.

### Decision (pending final confirm): **MongoDB as the primary store**
Rationale: current state is already document-shaped (`SwitchState.to_dict()`),
so the transition is near 1:1; flexible schema suits the growing device model;
**Mongo 5+ time-series collections** can hold metrics too, so one datastore
covers both current state and history (potentially no separate TSDB).
- Pair with **Grafana** (Mongo datasource) for dashboards, or build in-app views.
- Keep `config.ini` for configuration (unchanged).
- Introduce a thin **data-access layer** (`aruba_agent/store/`) so the JSON→Mongo
  migration is contained and a future swap stays possible.

**Verify before committing:**
- [ ] MongoDB **SSPL licensing** acceptable under USD policy.
- [ ] Who owns running/patching/backing up the Mongo instance (sysadmin).

### Alternatives considered
- **Postgres + TimescaleDB** — "boring enterprise": rock-solid SQL reporting,
  purpose-built time-series, cleanest HA. Cost: schema design + ORM mapping work.
- **SQLite + Prometheus/Grafana** — lightest (zero infra) but can't be the
  metrics TSDB and won't scale writes to AirWave volume. Good only if we stay
  wired-only.

---

## 3. Cross-cutting architecture upgrades (before/with the phases)

- ⬜ **Data-access layer + migration** from `state.json` to the chosen store.
- ⬜ **Poller scalability** — thread-per-device is fine at hundreds; move to a
  bounded worker-pool / queue (or async) before AirWave's thousands of APs.
- ⬜ **Tests + CI** — port the recent features' ad-hoc mock tests (aos8/aruba_os
  drivers, subnet_health, webserver_health, controllers, help_store, factory)
  into `tests/`; add GitHub Actions CI (lint + pytest) to catch regressions
  (e.g. the `EmailNotifier` startup crash) before prod.
- ⬜ **RBAC** — roles (read-only NOC vs admin); today every login is admin.
- ⬜ **Self-monitoring / dead-man's switch** — systemd `WatchdogSec` + an
  external heartbeat so the *monitor going down* pages someone.
- ⬜ **Notification channels** — webhook / Teams / Slack + optional syslog, beyond
  email; shared by all alert sources.
- ⬜ **HA path** — external DB makes an active/passive standby feasible later.

---

## 4. Phase 1 — SolarWinds (wired NMS) parity

Cheapest-highest-value first:
- ⬜ **Config change detection + diff** — we already store versioned encrypted
    configs; diff consecutive versions, alert "config changed on X", show diffs.
    *Best first win.*
- ⬜ **Interface-level monitoring** — ifTable/ifXTable: port up/down, errors,
    discards, utilization (needs the time-series store).
- ⬜ **Threshold alerting engine** — generic CPU/mem/temp/PoE/interface-% rules
    → alerts (generalize beyond up/down + subnet + web-server).
- ⬜ **SNMP trap receiver** — PSU/temp/fan/VSF/LAG events.
- ⬜ **Syslog collector** — ingest + search device syslog.
- ⬜ **Topology** — LLDP/CDP neighbor discovery + a network map.
- ⬜ **Inventory** — model/serial/OS/EoL/license tracking + export.
- ⬜ **Scheduled reports** — SLA, backup status, inventory (PDF/email).
- ⬜ **Maintenance windows** — scheduled, vs today's manual mute/unmanage.
- ⬜ **Config compliance** — check configs against policy (AAA/NTP/SNMP present).

---

## 5. Phase 2 — AirWave (wireless) replacement

Big data-volume feature; the reason the data layer must land first. On AOS-8,
data comes from the controllers we already onboard:
- Sources: SNMP `wlsx*` MIBs + CLI (`show ap database` / `show ap active` /
  `show user-table` / `show ap bss-table` / `show ap arm ...`), high-frequency.
- ⬜ **AP inventory + up/down** (per-AP, grouped by controller/site).
- ⬜ **Client monitoring** — who's connected, where, signal/SNR, roaming.
- ⬜ **RF health** — channel/power/utilization/interference trends.
- ⬜ **Rogue AP detection**.
- ⬜ **Historical trends** — client counts, RF, per-AP (time-series store).
- ⬜ **Floor plans / heatmaps** (VisualRF equivalent) — stretch goal.
- ⬜ **AP/controller firmware + config templates/compliance**.

---

## 6. Open decisions
- ❓ Data layer: MongoDB (leaning) vs Postgres+TimescaleDB — see §2 checklist.
- ❓ Dashboards: Grafana vs in-app charts.
- ❓ AirWave data path on AOS-8: SNMP+CLI polling (works today) vs AMON feed.
- ❓ HA requirement level (single host + fast recovery vs active/passive).
