# Spec: Data-Access Layer + MongoDB Migration

Status: **DRAFT / approved to start Phase 0.** Companion to `ROADMAP.md` §2.
Goal: replace the single `state.json` snapshot with a swappable persistence
layer that (a) changes nothing functionally on day one, (b) unblocks history +
scale, and (c) makes MongoDB (or Postgres) a backend choice rather than a
rewrite.

---

## 1. Goals / non-goals

**Goals**
- Introduce a thin, backend-agnostic **Store** interface behind the existing
  `AgentState` public API (callers keep calling `state.xxx()` unchanged).
- Ship a **JsonStore** first that reproduces today's exact behavior (atomic
  `state.json`), so Phase 0 is a zero-risk refactor.
- Make **MongoStore** a later drop-in selected by config, with a one-time
  importer and an instant rollback toggle.
- Lay the groundwork for **time-series metrics** (interface stats, RF, clients)
  that the SolarWinds/AirWave features need.

**Non-goals (for this spec)**
- No feature work (config-diff, interface polling) — those come after Phase 0/1.
- No secrets in the DB — credentials stay Fernet-encrypted in `config.ini`.
- No forced Mongo decision to start: Phase 0 is DB-agnostic.

---

## 2. Design: keep `AgentState`, swap what's under it

`AgentState` today holds an in-memory `switches` dict (write-through) and
persists via `_save()` → whole-file atomic JSON rewrite under an `RLock`.

Refactor: keep the in-memory cache and the **entire public API**; replace the
persistence calls with a `Store`:

```
callers (poller, tasks, web)                unchanged
        │  state.register_switch(), state.update_switch(), state.to_dict(), ...
        ▼
AgentState (in-memory cache + business logic)   API-stable facade
        │  self._store.upsert_device(name, doc) / load_all() / set_runtime(...)
        ▼
Store (Protocol)  ──► JsonStore (now)  ──►  MongoStore (later)  ──► [Postgres?]
```

- For **JsonStore**, `upsert_device` still triggers the atomic full-file write
  → behavior identical to today.
- For **MongoStore**, `upsert_device` is a single `update_one({_id}, {$set})`
  → removes the global-lock/full-rewrite bottleneck at scale.

Blast radius = `state.py` only. The ~19 `state.*` call sites don't change.

---

## 3. Store interface (derived from the real AgentState surface)

```python
class Store(Protocol):
    # lifecycle
    def load_all(self) -> dict: ...          # {"switches": {...}, "runtime": {...}}
    def close(self) -> None: ...

    # per-device (maps register_switch / update_switch / *_ fields / remove)
    def upsert_device(self, name: str, doc: dict) -> None: ...
    def patch_device(self, name: str, changes: dict) -> None: ...   # $set-style
    def remove_device(self, name: str) -> bool: ...
    def get_device(self, name: str) -> Optional[dict]: ...
    def iter_devices(self) -> Iterable[dict]: ...

    # runtime singletons (backup result, arp_last_run, scanner inventory count)
    def set_runtime(self, key: str, value) -> None: ...
    def get_runtime(self, key: str): ...

    # metrics time-series (Phase 3; no-op in JsonStore)
    def record_metric(self, device: str, metric: str, value: float,
                      ts: datetime, labels: dict | None = None) -> None: ...
    def query_metrics(self, device: str, metric: str,
                      start: datetime, end: datetime) -> list: ...
```

Existing `AgentState` methods map onto this: `register_switch`/`update_switch`/
`pin_vendor`/`set_*`/`set_switch_profile`/`set_alert_mute`/`set_unmanaged`/
`set_os_version`/`set_snmp_health` → `patch_device`; `remove_switch` →
`remove_device`; `set_backup_result`/`set_device_inventory`/`set_arp_last_run`
→ `set_runtime`; `to_dict`/getters → in-memory cache (hydrated by `load_all`).

---

## 4. Data model (MongoStore)

- **`devices`** — one doc per device (switch / controller / AP later).
  `_id = name`; fields = current `SwitchState` fields + `type`
  (`switch|controller|ap`). Indexes: `host`, `vendor`, `is_down`, `type`.
- **`runtime`** — small singletons currently top-level in state.json
  (`backup`, `arp_last_run`, `scanner`). `_id = key`.
- **`metrics`** — Mongo **time-series collection** (5.0+): `timeField=ts`,
  `metaField={device, metric, labels}`. Feeds interface/RF/client history.
  TTL / downsampling for retention.
- **`config_versions`** (config-diff feature) — metadata per backup:
  `{device, ts, sha256, size, path, encrypted}`. **Config blobs stay on disk,
  encrypted** (as today); DB holds only metadata + pointer. (GridFS optional
  later.)
- **`events` / `audit`** — future; audit stays file-based for now.

**Secrets:** never stored here. State carries no passwords; credentials remain
in `config.ini` (Fernet). Mongo runs with auth + TLS.

---

## 5. Migration phases

### Phase 0 — Store abstraction + JsonStore  ⬅ START HERE (DB-agnostic, zero-risk)
- Add `aruba_agent/store/` : `base.py` (Protocol), `json_store.py`.
- Refactor `state.py` to delegate persistence to a `Store` (default JsonStore
  pointed at the existing `state.json`). **No behavior change.**
- Contract test-suite that runs against any Store impl; JsonStore passes.
- Ship dev → prod. Nothing observable changes; we've just decoupled storage.

### Phase 1 — MongoStore (opt-in)
- `[store] backend = json | mongo` (+ `uri`, `db`, TLS/auth opts). Default `json`.
- `mongo_store.py` implementing `Store`; `record_metric` writes to the TS
  collection.
- One-time importer: `--import-state-to-mongo` reads `state.json` → `devices`/
  `runtime`.
- Unit tests via **mongomock**; same contract suite, both backends.

### Phase 2 — Cutover
- Flip dev to `backend = mongo`, soak. Keep writing a periodic `state.json`
  **export** as a DR snapshot during the soak.
- Then prod. Rollback = set `backend = json` and restart (state.json still current).

### Phase 3 — Metrics/history on
- Start recording time-series (interface counters, CPU/mem, later AP/client/RF).
- Unblocks Phase 1 NMS features (graphs, thresholds) and the AirWave phase.

---

## 6. Safety, rollback, ops
- **Rollback:** the `backend` toggle + retained `state.json` export = instant revert.
- **Atomicity/consistency:** JsonStore keeps mkstemp+fsync+rename; MongoStore uses
  per-doc `$set` (no partial-file risk).
- **Mongo ops:** v7 CE, auth on, bind localhost or TLS; `mongodump` nightly;
  TS retention/downsampling policy. Decide host placement (on argos-2026 vs
  separate) — see open questions.
- **Backups of the DB** join the existing DR runbook (`DISASTER-RECOVERY.md`).

---

## 7. Testing / CI
- A single **Store contract test** parametrized over `JsonStore` and
  `MongoStore(mongomock)` — guarantees behavioral parity.
- Add to `tests/` + wire GitHub Actions (lint + pytest) as part of this work
  (ties to ROADMAP §3 "tests + CI").

---

## 8. Effort / sequence
1. **Phase 0** (self-contained; the concrete next work item) — refactor + JsonStore
   + contract tests. Safe to build now, independent of the Mongo decision.
2. Resolve Mongo **licensing + host ownership** (ROADMAP §2 checklist).
3. **Phase 1** MongoStore + importer + tests.
4. **Phase 2** cutover (dev soak → prod).
5. **Phase 3** metrics — then feature work begins.

---

## 9. Open questions
- ❓ Mongo SSPL licensing OK under USD policy? Who runs/patches/backs it up?
- ❓ Mongo on the app host (argos-2026) or a separate DB host?
- ❓ Metrics retention windows + downsampling (e.g. 15s raw 14d, 5m 90d, 1h 2y)?
- ❓ Config blobs: keep encrypted-on-disk (recommended) vs GridFS?
- ❓ Dashboards: Grafana (Mongo datasource) vs in-app charts?
