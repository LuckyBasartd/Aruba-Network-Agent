# Network Agent — Architecture & Roadmap

Vision: replace **SolarWinds** (wired NMS) and then **Aruba AirWave** (wireless
management) with one self-hosted, enterprise-grade system at USD. This doc
captures the architecture decisions and the phased plan. Companion to
`CLAUDE.md` (how the code works today) and `TROUBLESHOOTING.md`.

Status legend: ✅ done · 🔨 in progress · ⬜ planned · ❓ decision needed

Numbering note: "Phase 1 / Phase 2" below = the PRODUCT roadmap (parity /
AirWave). The database migration has its own internal "Step 0-3" numbering
in DATA_LAYER_SPEC.md — unrelated to these Phases.

---

> **PROD HOLD:** prod stays on v3.5.0 (JSON) until Product Phase 1
> (SolarWinds parity) is complete; then app + MongoDB promote to argos-2026
> together as one tested unit. Dev is on v3.6.0 + MongoDB.

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

### Decision: **MongoDB** ✅ (data-layer migration DONE on dev; prod pending)
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
- ✅ **Config change detection + diff** — `config_diff.py`; nightly backup emails a
    coalesced per-device diff when a config changes ([backup] change_alerts), and
    switch-detail has a per-version 'diff vs previous' viewer
    (`/api/backups/<host>/diff`). *Done.*
- ✅ **Interface-level monitoring** — SNMP ifXTable collector (GETBULK), staggered
    bounded poll task with anti-chatter controls, in/out utilization to the TS
    store, and a switch-detail Interfaces table. `[interfaces]` (off by default).
    Real CRC errors via dot3StatsFCSErrors (not ifInErrors). Metrics bounded by
    a Mongo TTL + skip-idle. See INTERFACE_MONITORING_SPEC.md.
- ✅ **MAC table + search** — hourly bridge-FDB sweep (`[l2]`), per-port MACs on
    the switch page, top-nav MAC finder (edge-port-first). `fdb.py` + Mongo `fdb`.
- ✅ **Threshold alerting engine** — rules (web UI) on interface util/CRC +
    device CPU/mem/temperature, sustained-breach + recovery emails.
    thresholds.py/thresholds_store.py/health.py + [thresholds]/[health].
- ✅ **SNMP trap receiver** — UDP-162 v2c/v3 listener; classifies PSU/temp/fan/
    VSF/link/auth traps, stores them (Traps page), emails on critical only
    (rate-limited). `trap_receiver.py` + `traps.py`, `[traps]`.
- ❌ **Syslog collector** — OUT OF SCOPE. Syslog stays on the existing Kiwi
    Syslog Server; not part of the SolarWinds replacement.
- 🟡 **Topology** — LLDP/CDP neighbor discovery + per-port device-type
    classification **done** (`lldp.py`, folded into the `[l2]` sweep; Neighbor
    column on the switch page). Remaining: build the network **map** from it.
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
