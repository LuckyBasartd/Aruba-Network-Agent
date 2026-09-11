# Spec: Interface-Level Monitoring (SolarWinds NPM parity)

Status: **DRAFT — foundation (Store metrics) built; collector/UI next.**
Depends on the data layer (MongoDB time-series). See ROADMAP.md §4.

## Goal
Per-interface visibility like SolarWinds NPM: oper/admin status, speed,
in/out utilization %, errors, discards — current values + history + (later)
threshold alerts.

## Data source (SNMP, all vendors)
Walk **ifXTable / ifTable** per managed, SNMP-capable switch:
- `ifName` (1.3.6.1.2.1.31.1.1.1.1) / `ifAlias` (…18) / `ifDescr`
- `ifHCInOctets` (…6) / `ifHCOutOctets` (…10)  ← 64-bit counters
- `ifHighSpeed` (…15, Mbit/s) / `ifOperStatus` (1.3.6.1.2.1.2.2.1.8) / `ifAdminStatus` (…7)
- `ifInErrors` (…14) / `ifOutErrors` (…20) / `ifInDiscards` (…13) / `ifOutDiscards` (…19)
Reuse the existing SNMPv3 stack (snmp.py / snmp_profiles) + the per-host profile
already resolved by the poller.

## Utilization math
Counters are monotonic; store the previous sample per (device, ifIndex).
`util% = (Δoctets × 8) / (Δseconds × ifHighSpeed × 1e6) × 100`, clamped 0–100,
computed separately for in/out. Skip on counter wrap/reset (Δ<0) or first sample.

## Cadence
New **interval task** (`Scheduler.add_interval`) every `poll_seconds` (default
300s / 5 min — NOT the 30s reachability cadence; interface walks are heavier).
Bounded concurrency (thread pool) — ties into the ROADMAP poller-scalability item.

## Storage (already built)
Time-series via `store.record_metric(device, metric, value, ts, labels)`:
- metrics: `if.<ifIndex>.in_util`, `.out_util`, `.in_err`, `.out_err`,
  `.in_disc`, `.out_disc`; labels `{ifName, ifAlias}`.
- Current snapshot for the UI: a per-device `interfaces` doc (Mongo) or a
  capped in-memory map, holding the latest row per interface.
History is Mongo-only (JsonStore metrics are no-ops).

## Surfacing
- `switch_detail`: an Interfaces table (name/alias, admin+oper, speed, in/out %,
  err/disc) with color for down/err; sparklines from `query_metrics` (last N).
- API: `GET /api/switch/<name>/interfaces` (current) + `/interfaces/history`.
- Grafana can also read the `metrics` collection directly.

## Alerting
Feeds the **threshold engine** (next roadmap item): rules on util%/errors/
oper-down → alerts via the shared notifier. Out of scope for the first cut
(collect + display first).

## Build order
1. ✅ Store metrics (record/query) — done.
2. ⬜ SNMP ifXTable walker (`interfaces.py`) — pure parse, mock-testable.
3. ⬜ Interval poll task: walk → util math (prev-sample cache) → record_metric +
   current snapshot; bounded pool; `[interfaces] enabled/poll_seconds`.
4. ⬜ UI: switch_detail table + sparklines + API.
5. ⬜ Threshold alerts (separate roadmap item).

## Open questions
- Store per-interface current state in Mongo (`interfaces` coll) vs in-memory only?
- Retention/downsampling for the metrics collection (raw 14d, 5m 90d, 1h 1y?).
- Cap interfaces per device (skip logical/SVIs, or include with a filter)?
