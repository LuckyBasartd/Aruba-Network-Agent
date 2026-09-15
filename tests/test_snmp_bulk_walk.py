"""
Regression tests for ``SnmpAgent.bulk_walk`` against the pysnmp 6.1 shape.

Two things broke interface monitoring during development and MUST stay locked
in CI, because they are invisible until you point the agent at a real switch:

  1. pysnmp 6.1's *synchronous* ``bulkCmd`` returns a SINGLE GETBULK PDU, not
     an auto-continuing generator. Walking a 108-port switch therefore returned
     only the first ``max_repetitions`` rows (we saw 5) unless bulk_walk
     re-issues GETBULK from the last OID. This file feeds a fake ``bulkCmd``
     that returns one page per call and asserts we still get all 108 rows.

  2. The varBindTable comes back as ROWS x COLUMNS (a list of rows, each row a
     list of ``ObjectType``), not a flat list. The ``_pairs`` parser inside
     bulk_walk handles both; both shapes are exercised here.

The fakes model a tiny two-column MIB and a GETBULK that bleeds past a column's
subtree into the next one (as real SNMP does), so the subtree-stop logic is
covered too. No real pysnmp, network, or switch is involved.
"""

from __future__ import annotations

import sys
import types
from types import SimpleNamespace

import pytest

from aruba_agent.snmp import SnmpAgent


# -- fake pysnmp object model -------------------------------------------------
# Only the surface bulk_walk actually touches. Names are chosen so that
# ``type(entry[0]).__name__ == "ObjectType"`` (the row-vs-flat discriminator in
# _pairs) behaves exactly as it does against real pysnmp.

class ObjectIdentity:
    def __init__(self, oid):
        self.oid = str(oid)


class ObjectName:
    def __init__(self, oid):
        self._oid = str(oid)

    def getOid(self):
        return self._oid

    def __str__(self):
        return self._oid


class _Value:
    def __init__(self, v):
        self._v = str(v)

    def prettyPrint(self):
        return self._v


class ObjectType:
    """Dual-purpose, like pysnmp's: a *request* wraps an ObjectIdentity; a
    *response* cell holds (ObjectName, value) and is indexable ot[0]/ot[1]."""

    def __init__(self, a, b=None):
        if isinstance(a, ObjectIdentity):        # request form
            self.oid = a.oid
            self._pair = None
        else:                                    # response form
            self._pair = (a, b)
            self.oid = str(a)

    def __getitem__(self, i):
        if self._pair is None:
            raise IndexError(i)
        return self._pair[i]


class SnmpEngine:
    def __init__(self):
        self.transportDispatcher = SimpleNamespace(closeDispatcher=lambda: None)


def _passthru(*a, **k):
    return SimpleNamespace(args=a, kwargs=k)


def _oid_tuple(oid: str):
    return tuple(int(x) for x in oid.split("."))


class _FakeMib:
    """An ordered SNMP MIB + a GETBULK that returns ONE page per call.

    ``shape`` selects how the varBindTable is packed:
      * "rows" -- list of rows, each row a list with one ObjectType (the real
        multi-column-request shape we observed on the 6300M).
      * "flat" -- a flat list of ObjectType (the other branch of _pairs).
    """

    def __init__(self, entries, shape="rows"):
        self._sorted = sorted(entries, key=lambda kv: _oid_tuple(kv[0]))
        self.shape = shape
        self.calls = 0

    def bulk_cmd(self, engine, user, target, ctx, non_rep, max_rep, req, **kw):
        self.calls += 1
        start = _oid_tuple(req.oid)
        page = [(o, v) for (o, v) in self._sorted if _oid_tuple(o) > start][:max_rep]
        cells = [ObjectType(ObjectName(o), _Value(v)) for (o, v) in page]
        if self.shape == "rows":
            vbt = [[c] for c in cells]           # rows x columns
        else:
            vbt = cells                          # flat
        return (None, None, 0, vbt)              # single PDU tuple


def _install_fake_pysnmp(monkeypatch, mib):
    hlapi = types.ModuleType("pysnmp.hlapi")
    names = dict(
        bulkCmd=mib.bulk_cmd, SnmpEngine=SnmpEngine, UsmUserData=_passthru,
        UdpTransportTarget=_passthru, ContextData=_passthru,
        ObjectType=ObjectType, ObjectIdentity=ObjectIdentity,
        usmHMACMD5AuthProtocol=object(), usmHMACSHAAuthProtocol=object(),
        usmHMAC128SHA224AuthProtocol=object(), usmHMAC192SHA256AuthProtocol=object(),
        usmHMAC256SHA384AuthProtocol=object(), usmHMAC384SHA512AuthProtocol=object(),
        usmDESPrivProtocol=object(), usmAesCfb128Protocol=object(),
        usmAesCfb192Protocol=object(), usmAesCfb256Protocol=object(),
        usmNoAuthProtocol=object(), usmNoPrivProtocol=object(),
    )
    for k, v in names.items():
        setattr(hlapi, k, v)
    pysnmp = types.ModuleType("pysnmp")
    pysnmp.hlapi = hlapi

    univ = types.ModuleType("pyasn1.type.univ")
    univ.OctetString = _passthru
    pyasn1 = types.ModuleType("pyasn1")
    pyasn1_type = types.ModuleType("pyasn1.type")
    pyasn1_type.univ = univ
    pyasn1.type = pyasn1_type

    for name, mod in {
        "pysnmp": pysnmp, "pysnmp.hlapi": hlapi,
        "pyasn1": pyasn1, "pyasn1.type": pyasn1_type, "pyasn1.type.univ": univ,
    }.items():
        monkeypatch.setitem(sys.modules, name, mod)


def _agent():
    creds = SimpleNamespace(
        username="u", auth_protocol="SHA", priv_protocol="AES128",
        auth_password="a-pass", priv_password="p-pass",
        context_engine_id="", context_name="",
    )
    profile = SimpleNamespace(creds=creds, port=161, timeout=1, retries=0)
    registry = SimpleNamespace(get=lambda n: profile, default=lambda: profile)
    return SnmpAgent(registry)


IF_NAME = "1.3.6.1.2.1.31.1.1.1.1"      # ifName column base
IF_TYPE = "1.3.6.1.2.1.2.2.1.3"         # ifType column base (sorts before ifName)
N = 108                                 # full 6300M-96 port count we validated


def _mib_entries():
    entries = []
    for i in range(1, N + 1):
        entries.append((f"{IF_NAME}.{i}", f"1/1/{i}"))
        entries.append((f"{IF_TYPE}.{i}", "6"))
    return entries


def test_bulk_walk_paginates_full_column(monkeypatch):
    """All 108 rows come back, not just the first GETBULK page -- this is the
    exact 5-vs-108 regression. max_repetitions=25 forces multiple pages."""
    mib = _FakeMib(_mib_entries(), shape="rows")
    _install_fake_pysnmp(monkeypatch, mib)
    agent = _agent()

    res = agent.bulk_walk("10.40.0.6", [IF_NAME, IF_TYPE], max_repetitions=25)

    assert res is not None
    assert len(res[IF_NAME]) == N, "pagination stopped early (pysnmp-6.1 single-PDU bug)"
    assert len(res[IF_TYPE]) == N
    assert res[IF_NAME]["1"] == "1/1/1"
    assert res[IF_NAME]["108"] == "1/1/108"
    assert set(res[IF_TYPE].values()) == {"6"}
    assert mib.calls > 2                 # genuinely multi-page, not one giant PDU


def test_bulk_walk_stops_at_subtree_boundary(monkeypatch):
    """A GETBULK that bleeds into the next column must not leak the neighbour's
    OIDs into this column's results."""
    mib = _FakeMib(_mib_entries(), shape="rows")
    _install_fake_pysnmp(monkeypatch, mib)
    agent = _agent()

    res = agent.bulk_walk("10.40.0.6", [IF_TYPE], max_repetitions=25)

    assert res is not None
    assert set(res.keys()) == {IF_TYPE}
    assert len(res[IF_TYPE]) == N
    assert all(not k.startswith("1.3.6.1.2.1.31") for k in res[IF_TYPE])


def test_bulk_walk_accepts_flat_varbind_shape(monkeypatch):
    """_pairs must also handle a flat list of ObjectType (not rows x columns)."""
    mib = _FakeMib([(f"{IF_NAME}.{i}", f"1/1/{i}") for i in range(1, N + 1)],
                   shape="flat")
    _install_fake_pysnmp(monkeypatch, mib)
    agent = _agent()

    res = agent.bulk_walk("10.40.0.6", [IF_NAME], max_repetitions=25)

    assert res is not None
    assert len(res[IF_NAME]) == N
    assert res[IF_NAME]["42"] == "1/1/42"


def test_bulk_walk_empty_bases_returns_empty(monkeypatch):
    mib = _FakeMib([], shape="rows")
    _install_fake_pysnmp(monkeypatch, mib)
    agent = _agent()
    assert agent.bulk_walk("10.40.0.6", []) == {}


def test_close_thread_event_loop_frees_loop():
    """close_thread_event_loop() must close and unbind a loop created by
    _ensure_thread_event_loop, so ThreadPoolExecutor workers don't leak fds."""
    import asyncio, threading
    from aruba_agent import snmp as _snmp

    captured = {}
    def worker():
        _snmp._ensure_thread_event_loop()
        loop = asyncio.get_event_loop()
        captured["loop"] = loop
        assert not loop.is_closed()
        _snmp.close_thread_event_loop()
        captured["closed"] = loop.is_closed()
        # a second call is a harmless no-op (loop already gone)
        _snmp.close_thread_event_loop()

    t = threading.Thread(target=worker); t.start(); t.join()
    assert captured["closed"] is True
