"""System Stats: minute rollups of CORPUSfm's own performance signals, kept for seven days (packet 1409).

Aggregates only. A bucket holds counts, sums, minima, maxima and a fixed latency histogram — never a
name, identity, host, URL, path, query, database object, response, exception text or credential. The
only strings ever stored are this module's fixed field names, the six queue-lane names, and the
coarse OData operation class / HTTP status family.

**Fail-open by construction.** Every public hook catches everything: instrumentation can never change
the return value, exception, retry, timing budget or outcome of the work it observes. A failure to
sample or persist leaves a GAP (a missing minute or a missing process sample), never an invented zero.

**One owner per process.** Hooks only fold numbers into the in-memory current minute. Rotation hands
completed minutes to a bounded pending list; only the lifecycle-owned service thread (`start`/`stop`,
called from the web lifespan) samples the process tree and appends completed minutes to disk. Importing
this module starts nothing. A restart is refused while a previous collector thread is still alive — even
one whose stop timed out — so a process never runs two. Shutdown first rotates to the current wall minute,
then flushes completed minutes only (the partial current minute is never written), with bounded waits.

**Store.** ``<state_dir>/metrics/minutes-YYYY-MM-DD.jsonl`` (UTC day of the bucket), one schema-versioned
JSON record per completed minute, appended and fsynced. A torn final line (a crash mid-append) is cut
back to the last newline when the store opens; malformed content EARLIER in a file refuses that file
for reads and is reported, without refusing startup.

**Retention.** Query visibility is exactly seven days: every read is clamped to the last 10,080 minutes,
so an expired minute is never returned. Files are removed only WHOLE — a day file is deleted once its
entire UTC day is older than the visibility start, or when its day is LATER than the current UTC day (an
artifact of a clock that ran ahead and came back; its minutes become a visible gap) — and are never
rewritten to trim expired lines. Unrecognized names are never touched. After pruning, at most eight daily
files exist (the oldest partly expired), so the physical store may hold up to eight days of minutes; with
every line and file size-bounded, disk use is at most ``MAX_STORE_BYTES``.
"""
from __future__ import annotations

import json
import logging
import math
import os
import threading
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1
RETENTION_DAYS = 7
RETENTION_MINUTES = RETENTION_DAYS * 1440            # 10,080 buckets per series
SAMPLE_INTERVAL_S = 10.0
MAX_LINE_BYTES = 8192                                 # one minute record; larger is dropped, not truncated
MAX_FILE_BYTES = 1440 * MAX_LINE_BYTES                # one UTC day of minutes at the line bound
MAX_DAY_FILES = RETENTION_DAYS + 1                    # the oldest partly expired, never rewritten
MAX_STORE_BYTES = MAX_DAY_FILES * MAX_FILE_BYTES      # the hard physical bound (~90 MiB at the line bound)
_RING_MINUTES = 180                                   # completed minutes held in memory for reads
_PENDING_MAX = 240                                    # completed minutes awaiting the writer
_WARN_EVERY_S = 600.0

#: Fixed latency histogram edges (seconds). Mergeable across minutes, so a window's percentiles come
#: from the underlying observations rather than from averaging per-minute percentiles.
LATENCY_EDGES = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0)
LANES = ("acquire", "ingest", "summarize", "index", "git_export", "reingest")
OP_CLASSES = ("read", "write", "container", "script", "other")
STATUS_FAMILIES = ("2xx", "3xx", "4xx", "5xx", "exc")

_ENABLED = os.environ.get("CORPUSFM_METRICS", "1").strip().lower() not in ("0", "off", "false", "no")


# ── bucket arithmetic ─────────────────────────────────────────────────────────────────────────────

def _stat() -> dict:
    return {"n": 0, "sum": 0.0, "min": None, "max": None}


def _stat_add(s: dict, v: float) -> None:
    s["n"] += 1
    s["sum"] += v
    s["min"] = v if s["min"] is None else min(s["min"], v)
    s["max"] = v if s["max"] is None else max(s["max"], v)


def _stat_merge(a: dict, b: dict) -> None:
    a["n"] += b.get("n", 0)
    a["sum"] += b.get("sum", 0.0)
    for k, f in (("min", min), ("max", max)):
        if b.get(k) is not None:
            a[k] = b[k] if a[k] is None else f(a[k], b[k])


def _hist() -> list:
    return [0] * (len(LATENCY_EDGES) + 1)


def _hist_add(h: list, v: float) -> None:
    for i, edge in enumerate(LATENCY_EDGES):
        if v <= edge:
            h[i] += 1
            return
    h[-1] += 1


def hist_quantile(h: list, q: float, observed_max: Optional[float] = None) -> Optional[float]:
    """The q-quantile from a merged histogram, as the upper edge of the bucket holding it (the last,
    open bucket reports the observed maximum). ``None`` with no observations — never zero."""
    total = sum(h)
    if total <= 0:
        return None
    rank = q * total
    acc = 0
    for i, c in enumerate(h):
        acc += c
        if acc >= rank and c:
            if i < len(LATENCY_EDGES):
                return LATENCY_EDGES[i] if observed_max is None else min(LATENCY_EDGES[i], observed_max)
            return observed_max
    return observed_max


def new_bucket(minute: int) -> dict:
    return {
        "v": SCHEMA_VERSION, "m": minute,
        "proc": {"samples": 0, "tree_rss_mib": _stat(), "web_rss_mib": _stat(), "tree_cpu_pct": _stat(),
                 "web_cpu_pct": _stat(), "children": _stat(), "host_avail_mib": _stat()},
        "odata": {"dur": _stat(), "hist": _hist(), "err": 0, "inflight_max": 0,
                  "cls": {c: 0 for c in OP_CLASSES}, "status": {s: 0 for s in STATUS_FAMILIES}},
        "catalog": {"passes": 0, "fail": 0, "dur": _stat(), "interval": _stat(), "changed": 0, "bytes": 0},
        "icache": {"hit": 0, "miss": 0, "inval": 0, "refresh": _stat(), "refresh_fail": 0},
        "lanes": {ln: {"start": 0, "done": 0, "fail": 0, "busy_s": 0.0, "wait": _stat()} for ln in LANES},
        "gen": {"submitted": 0, "done": 0, "fail": 0, "dur": _stat(), "active_max": 0},
        "qview": {"dur": _stat(), "err": 0, "rows": _stat()},
    }


def merge_into(acc: dict, b: dict) -> None:
    """Fold bucket ``b`` into ``acc`` (both shaped by `new_bucket`). Unknown keys are ignored, so an
    older or newer record never injects a field."""
    pa, pb = acc["proc"], b.get("proc", {})
    pa["samples"] += pb.get("samples", 0)
    for k in ("tree_rss_mib", "web_rss_mib", "tree_cpu_pct", "web_cpu_pct", "children", "host_avail_mib"):
        if k in pb:
            _stat_merge(pa[k], pb[k])
    oa, ob = acc["odata"], b.get("odata", {})
    if "dur" in ob:
        _stat_merge(oa["dur"], ob["dur"])
    for i, c in enumerate(ob.get("hist", [])[:len(oa["hist"])]):
        oa["hist"][i] += c
    oa["err"] += ob.get("err", 0)
    oa["inflight_max"] = max(oa["inflight_max"], ob.get("inflight_max", 0))
    for c in OP_CLASSES:
        oa["cls"][c] += ob.get("cls", {}).get(c, 0)
    for s in STATUS_FAMILIES:
        oa["status"][s] += ob.get("status", {}).get(s, 0)
    ca, cb = acc["catalog"], b.get("catalog", {})
    for k in ("passes", "fail", "changed", "bytes"):
        ca[k] += cb.get(k, 0)
    for k in ("dur", "interval"):
        if k in cb:
            _stat_merge(ca[k], cb[k])
    ia, ib = acc["icache"], b.get("icache", {})
    for k in ("hit", "miss", "inval", "refresh_fail"):
        ia[k] += ib.get(k, 0)
    if "refresh" in ib:
        _stat_merge(ia["refresh"], ib["refresh"])
    for ln in LANES:
        la, lb = acc["lanes"][ln], b.get("lanes", {}).get(ln, {})
        for k in ("start", "done", "fail"):
            la[k] += lb.get(k, 0)
        la["busy_s"] += lb.get("busy_s", 0.0)
        if "wait" in lb:
            _stat_merge(la["wait"], lb["wait"])
    ga, gb = acc["gen"], b.get("gen", {})
    for k in ("submitted", "done", "fail"):
        ga[k] += gb.get(k, 0)
    ga["active_max"] = max(ga["active_max"], gb.get("active_max", 0))
    if "dur" in gb:
        _stat_merge(ga["dur"], gb["dur"])
    qa, qb = acc["qview"], b.get("qview", {})
    qa["err"] += qb.get("err", 0)
    for k in ("dur", "rows"):
        if k in qb:
            _stat_merge(qa[k], qb[k])


def _valid_record(rec) -> bool:
    return (isinstance(rec, dict) and rec.get("v") == SCHEMA_VERSION and isinstance(rec.get("m"), int)
            and isinstance(rec.get("proc"), dict) and isinstance(rec.get("odata"), dict))


# ── the bounded store ─────────────────────────────────────────────────────────────────────────────

def _day_of(minute: int) -> str:
    return datetime.fromtimestamp(minute * 60, tz=timezone.utc).strftime("%Y-%m-%d")


class MinuteStore:
    """Daily JSON-lines files of completed minute records under ``root``."""

    PREFIX, SUFFIX = "minutes-", ".jsonl"

    def __init__(self, root: Path):
        self.root = Path(root)
        self.malformed: set[str] = set()

    def _path(self, day: str) -> Path:
        return self.root / f"{self.PREFIX}{day}{self.SUFFIX}"

    def _files(self) -> list[Path]:
        try:
            return sorted(p for p in self.root.glob(f"{self.PREFIX}*{self.SUFFIX}") if p.is_file())
        except OSError:
            return []

    def open(self, now_minute: int) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        for p in self._files():
            self._repair_torn_tail(p)
        self.prune(now_minute)

    @staticmethod
    def _repair_torn_tail(p: Path) -> None:
        """A crash mid-append leaves a final line without its newline. Cut back to the last complete
        record so the next append cannot weld onto it and corrupt an earlier line."""
        try:
            data = p.read_bytes()
        except OSError:
            return
        if not data or data.endswith(b"\n"):
            return
        cut = data.rfind(b"\n") + 1
        with open(p, "r+b") as fh:
            fh.truncate(cut)
            fh.flush()
            os.fsync(fh.fileno())

    @classmethod
    def _valid_day(cls, p: Path) -> Optional[str]:
        """The UTC day a store file names, or None for any name this store did not write."""
        day = p.name[len(cls.PREFIX):-len(cls.SUFFIX)]
        try:
            if len(day) == 10 and datetime.strptime(day, "%Y-%m-%d").strftime("%Y-%m-%d") == day:
                return day
        except ValueError:
            pass
        return None

    def prune(self, now_minute: int) -> int:
        """Delete whole day files whose ENTIRE UTC day precedes the visibility start, and day files LATER
        than the current UTC day (left by a clock that ran ahead). Only valid store file names; the partly
        expired oldest day is kept untouched. Afterwards at most ``MAX_DAY_FILES`` remain."""
        oldest_day = _day_of(now_minute - RETENTION_MINUTES)
        today = _day_of(now_minute)
        removed = 0
        for p in self._files():
            day = self._valid_day(p)
            if day is not None and (day < oldest_day or day > today):
                try:
                    p.unlink()
                    removed += 1
                except OSError:
                    pass
        return removed

    def append(self, bucket: dict) -> bool:
        line = json.dumps(bucket, separators=(",", ":"), allow_nan=False) + "\n"
        data = line.encode("utf-8")
        if len(data) > MAX_LINE_BYTES:
            raise ValueError("minute record exceeds the line bound")
        p = self._path(_day_of(bucket["m"]))
        try:
            size = p.stat().st_size
        except FileNotFoundError:
            size = 0
        if size + len(data) > MAX_FILE_BYTES:
            raise ValueError("day file is at its size bound")
        with open(p, "ab") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        return True

    def read(self, start_minute: int, end_minute: int) -> list[dict]:
        """Valid records with ``start <= m < end``. A torn FINAL line is ignored; malformed content
        before it refuses that file (recorded in ``malformed``)."""
        out: list[dict] = []
        lo, hi = _day_of(max(0, start_minute)), _day_of(max(0, end_minute - 1))
        for p in self._files():                          # existing files only — at most eight
            day = p.name[len(self.PREFIX):-len(self.SUFFIX)]
            if not (lo <= day <= hi):
                continue
            try:
                lines = p.read_bytes().split(b"\n")
            except OSError:
                continue
            if lines and lines[-1] == b"":
                lines = lines[:-1]
            recs, bad = [], False
            for i, raw in enumerate(lines):
                try:
                    rec = json.loads(raw)
                except ValueError:
                    rec = None
                if not _valid_record(rec):
                    if i == len(lines) - 1:
                        continue                       # torn final line: ignore only that
                    bad = True
                    break
                recs.append(rec)
            if bad:
                self.malformed.add(p.name)
                continue
            self.malformed.discard(p.name)
            out.extend(r for r in recs if start_minute <= r["m"] < end_minute)
        return out

    def disk_bytes(self) -> int:
        total = 0
        for p in self._files():
            try:
                total += p.stat().st_size
            except OSError:
                pass
        return total


# ── process-tree sampling ─────────────────────────────────────────────────────────────────────────

class _ProcessSampler:
    """The web process and its successfully sampled recursive descendants as one CORPUSfm tree. CPU
    is the delta of process CPU time between samples; a child that exits or denies access mid-sample
    is simply left out of that sample — no failure, no invented zero."""

    def __init__(self):
        import psutil
        self._psutil = psutil
        self._me = psutil.Process(os.getpid())
        self._last: dict[int, float] = {}
        self._last_wall: Optional[float] = None

    def sample(self) -> Optional[dict]:
        ps = self._psutil
        wall = time.monotonic()
        procs = [self._me]
        try:
            procs += self._me.children(recursive=True)
        except (ps.NoSuchProcess, ps.AccessDenied):
            pass
        rss = {}
        cpu = {}
        for p in procs:
            try:
                with p.oneshot():
                    rss[p.pid] = p.memory_info().rss
                    t = p.cpu_times()
                    cpu[p.pid] = t.user + t.system
            except (ps.NoSuchProcess, ps.AccessDenied, ps.ZombieProcess):
                continue
        if self._me.pid not in rss:
            return None
        out = {"web_rss_mib": rss[self._me.pid] / 1048576.0,
               "tree_rss_mib": sum(rss.values()) / 1048576.0,
               "children": float(len(rss) - 1)}
        try:
            out["host_avail_mib"] = ps.virtual_memory().available / 1048576.0
        except Exception:                                   # noqa: BLE001 — context line only
            pass
        if self._last_wall is not None and wall > self._last_wall:
            dt = wall - self._last_wall
            delta = {pid: max(0.0, c - self._last.get(pid, 0.0)) for pid, c in cpu.items()}
            out["tree_cpu_pct"] = 100.0 * sum(delta.values()) / dt
            out["web_cpu_pct"] = 100.0 * delta.get(self._me.pid, 0.0) / dt
        self._last, self._last_wall = cpu, wall
        return out


# ── the service ───────────────────────────────────────────────────────────────────────────────────

def _op_class(method: str, url: str) -> str:
    m = (method or "").upper()
    u = url or ""
    if "/$value" in u or "$value" in u:
        return "container"
    if m == "POST" and "/Script." in u:
        return "script"
    if m in ("GET", "HEAD", "OPTIONS"):
        return "read"
    if m in ("POST", "PATCH", "PUT", "DELETE"):
        return "write"
    return "other"


def _status_family(status: Optional[int]) -> str:
    if status is None:
        return "exc"
    if 200 <= status < 300:
        return "2xx"
    if 300 <= status < 400:
        return "3xx"
    if 400 <= status < 500:
        return "4xx"
    return "5xx"


class MetricsService:
    def __init__(self, *, wall: Callable[[], float] = time.time, mono: Callable[[], float] = time.monotonic):
        self._wall = wall
        self._mono = mono
        self._lock = threading.Lock()
        self._cur: Optional[dict] = None
        self._ring: deque = deque(maxlen=_RING_MINUTES)
        self._pending: deque = deque(maxlen=_PENDING_MAX)
        self._inflight = 0
        self._active_lanes: dict[str, int] = {ln: 0 for ln in LANES}
        self._gen_active = 0
        self._last_pass_mono: Optional[float] = None
        self._last_pass: Optional[dict] = None
        self._store: Optional[MinuteStore] = None
        self._store_root_fn: Optional[Callable[[], Path]] = None
        self._history_error = ""
        self._sampler: Optional[_ProcessSampler] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._life = threading.Lock()                    # serializes start/stop (lifecycle only)
        self._owner_pid: Optional[int] = None
        self._warned: dict[str, float] = {}
        self.enabled = _ENABLED

    # -- internals ---------------------------------------------------------------------------------
    def _warn(self, kind: str) -> None:
        now = self._mono()
        if now - self._warned.get(kind, -1e9) >= _WARN_EVERY_S:
            self._warned[kind] = now
            logger.warning("system stats: %s failed; the affected minute shows a gap", kind)

    def _minute(self) -> int:
        return int(self._wall() // 60)

    def _bucket(self) -> dict:
        """The current minute's bucket, rotating first if the clock moved. Called under the lock."""
        m = self._minute()
        cur = self._cur
        if cur is None or cur["m"] != m:
            if cur is not None:
                self._ring.append(cur)
                self._pending.append(cur)
            cur = self._cur = new_bucket(m)
        return cur

    def _guard(self, kind: str, fn) -> None:
        if not self.enabled:
            return
        try:
            with self._lock:
                fn(self._bucket())
        except Exception:                                   # noqa: BLE001 — fail-open, always
            self._warn(kind)

    # -- observation hooks (each fail-open) --------------------------------------------------------
    def odata_begin(self) -> Optional[float]:
        if not self.enabled:
            return None
        try:
            with self._lock:
                self._inflight += 1
                b = self._bucket()
                b["odata"]["inflight_max"] = max(b["odata"]["inflight_max"], self._inflight)
            return self._mono()
        except Exception:                                   # noqa: BLE001
            self._warn("database-call observation")
            return None

    def odata_end(self, token: Optional[float], method: str, url: str, status: Optional[int]) -> None:
        if token is None or not self.enabled:
            return
        try:
            dur = max(0.0, self._mono() - token)
            cls = _op_class(method, url)
            fam = _status_family(status)
            with self._lock:
                self._inflight = max(0, self._inflight - 1)
                o = self._bucket()["odata"]
                _stat_add(o["dur"], dur)
                _hist_add(o["hist"], dur)
                o["cls"][cls] += 1
                o["status"][fam] += 1
                if fam in ("exc", "5xx"):
                    o["err"] += 1
        except Exception:                                   # noqa: BLE001
            self._warn("database-call observation")

    def catalog_pass(self, ok: bool, duration_s: float, changed: int, bytes_read: int) -> None:
        def f(b):
            c = b["catalog"]
            now = self._mono()
            if self._last_pass_mono is not None:
                _stat_add(c["interval"], max(0.0, now - self._last_pass_mono))
            self._last_pass_mono = now
            c["passes"] += 1
            if not ok:
                c["fail"] += 1
            _stat_add(c["dur"], float(duration_s))
            c["changed"] += int(changed)
            c["bytes"] += int(bytes_read)
            self._last_pass = {"ok": bool(ok), "duration_s": float(duration_s), "at_minute": b["m"],
                               "changed": int(changed)}
        self._guard("catalog observation", f)

    def icache_hit(self) -> None:
        self._guard("cache observation", lambda b: b["icache"].__setitem__("hit", b["icache"]["hit"] + 1))

    def icache_invalidated(self) -> None:
        self._guard("cache observation", lambda b: b["icache"].__setitem__("inval", b["icache"]["inval"] + 1))

    def icache_refreshed(self, duration_s: float, ok: bool) -> None:
        def f(b):
            i = b["icache"]
            i["miss"] += 1
            _stat_add(i["refresh"], float(duration_s))
            if not ok:
                i["refresh_fail"] += 1
        self._guard("cache observation", f)

    def lane_started(self, lane: str, created_at_iso: str = "") -> None:
        def f(b):
            if lane not in LANES:
                return
            ln = b["lanes"][lane]
            ln["start"] += 1
            self._active_lanes[lane] = self._active_lanes.get(lane, 0) + 1
            if created_at_iso:
                ts = datetime.fromisoformat(created_at_iso.replace("Z", "+00:00"))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                wait = self._wall() - ts.timestamp()
                if 0.0 <= wait < 30 * 86400:
                    _stat_add(ln["wait"], wait)
        self._guard("queue-lane observation", f)

    def lane_finished(self, lane: str, completed: bool, busy_s: float) -> None:
        def f(b):
            if lane not in LANES:
                return
            ln = b["lanes"][lane]
            ln["done" if completed else "fail"] += 1
            ln["busy_s"] += max(0.0, float(busy_s))
            self._active_lanes[lane] = max(0, self._active_lanes.get(lane, 0) - 1)
        self._guard("queue-lane observation", f)

    def generation_submitted(self) -> None:
        def f(b):
            g = b["gen"]
            g["submitted"] += 1
            self._gen_active += 1
            g["active_max"] = max(g["active_max"], self._gen_active)
        self._guard("generation observation", f)

    def generation_finished(self, ok: bool, duration_s: float) -> None:
        def f(b):
            g = b["gen"]
            g["done" if ok else "fail"] += 1
            _stat_add(g["dur"], max(0.0, float(duration_s)))
            self._gen_active = max(0, self._gen_active - 1)
            g["active_max"] = max(g["active_max"], self._gen_active)
        self._guard("generation observation", f)

    def queue_view(self, duration_s: float, rows: int, ok: bool) -> None:
        def f(b):
            q = b["qview"]
            _stat_add(q["dur"], float(duration_s))
            if ok:
                _stat_add(q["rows"], float(rows))
            else:
                q["err"] += 1
        self._guard("queue-view observation", f)

    def process_sample(self, sample: Optional[dict]) -> None:
        if not sample:
            return

        def f(b):
            p = b["proc"]
            p["samples"] += 1
            for k, v in sample.items():
                if k in p and isinstance(v, (int, float)) and math.isfinite(v):
                    _stat_add(p[k], float(v))
        self._guard("process sampling", f)

    # -- lifecycle ---------------------------------------------------------------------------------
    def start(self, store_root: Optional[Callable[[], Path]] = None) -> bool:
        """Start the one service thread for this process (idempotent)."""
        if not self.enabled:
            return False
        with self._life:
            prev = self._thread
            # A previous generation still alive — including one whose stop() timed out while it was
            # blocked — refuses the restart: one collector per process, never two. (After a fork the
            # parent's thread is not alive in the child, so the child may start its own.)
            if prev is not None and prev.is_alive():
                return False
            self._stop = threading.Event()               # per generation: never revives an old thread
            self._owner_pid = os.getpid()
            if store_root is not None:
                self._store_root_fn = store_root
            return self._start_locked()

    def _start_locked(self) -> bool:
        self._open_store()
        try:
            self._sampler = _ProcessSampler()
        except Exception:                                   # noqa: BLE001
            self._sampler = None
            self._warn("process sampling")
        t = threading.Thread(target=self._run, args=(self._stop,), name="cfm-metrics", daemon=True)
        self._thread = t
        t.start()
        return True

    def _open_store(self) -> None:
        self._store, self._history_error = None, ""
        try:
            fn = self._store_root_fn
            if fn is None:
                from corpusfm.lifecycle import app_paths
                root = Path(app_paths.state_dir()) / "metrics"
            else:
                root = Path(fn())
            store = MinuteStore(root)
            store.open(self._minute())
            self._store = store
        except Exception:                                   # noqa: BLE001
            self._history_error = "unavailable"
            self._warn("history storage")

    def _run(self, stop: threading.Event) -> None:
        last_day = _day_of(self._minute())
        while not stop.wait(SAMPLE_INTERVAL_S):
            last_day = self._cycle(last_day)

    def _cycle(self, last_day: str) -> str:
        """One collector cycle: tick, then prune whenever the UTC day CHANGED — forward or backward, so a
        clock that stepped back removes the future-day files it left behind."""
        self.tick()
        day = _day_of(self._minute())
        if day != last_day and self._store is not None:
            try:
                self._store.prune(self._minute())
            except Exception:                               # noqa: BLE001
                self._warn("history pruning")
        return day

    def tick(self) -> None:
        """One service cycle: sample the process tree, rotate, persist completed minutes."""
        sample = None
        if self._sampler is not None:
            try:
                sample = self._sampler.sample()
            except Exception:                               # noqa: BLE001
                self._warn("process sampling")
        self.process_sample(sample)
        try:
            with self._lock:
                self._bucket()
        except Exception:                                   # noqa: BLE001
            self._warn("rotation")
        self.flush()

    def flush(self) -> None:
        """Append every completed minute awaiting the writer. A failed append drops that minute
        (a gap on disk; it stays readable from memory while it is recent)."""
        while True:
            with self._lock:
                if not self._pending:
                    return
                b = self._pending.popleft()
            if self._store is None:
                continue
            try:
                self._store.append(b)
            except Exception:                               # noqa: BLE001
                self._warn("history persistence")

    def stop(self, timeout: float = 0.5) -> None:
        """Signal the collector, wait at most ``timeout`` for it, rotate to the current wall minute and
        flush COMPLETED minutes; the partial current minute is never written.

        A thread that does not exit in time is KEPT as ``_thread`` (not forgotten), so ``start`` refuses
        a second collector until it has really gone. Every wait here is bounded."""
        with self._life:
            self._stop.set()
            t = self._thread
            if t is not None and t.is_alive() and t is not threading.current_thread():
                t.join(timeout)
            if t is not None and not t.is_alive():
                self._thread = None
        try:
            # A minute that became complete since the last tick is rotated out now and persisted.
            if self._lock.acquire(timeout=timeout):
                try:
                    if self.enabled and self._cur is not None:
                        self._bucket()
                finally:
                    self._lock.release()
            self.flush()
        except Exception:                                   # noqa: BLE001
            pass

    # -- reads -------------------------------------------------------------------------------------
    def snapshot(self, start_minute: int, end_minute: int) -> dict:
        """Completed minute records in ``[start, end)`` — disk plus recent memory — keyed by minute,
        duplicates (a clock that stepped back) merged. Clamped to the retention: an expired minute in
        the partly expired oldest file is never returned, whatever the caller asks for."""
        start_minute = max(start_minute, self.visible_from())
        out: dict[int, dict] = {}
        disk: list = []
        if self._store is not None:
            try:
                disk = self._store.read(start_minute, end_minute)
            except Exception:                               # noqa: BLE001
                self._warn("history read")
        with self._lock:
            mem = [b for b in list(self._ring) if start_minute <= b["m"] < end_minute]
            mem_keys = {b["m"] for b in mem}
        for rec in disk:
            if rec["m"] in mem_keys:
                continue
            if rec["m"] in out:
                merge_into(out[rec["m"]], rec)
            else:
                acc = new_bucket(rec["m"])
                merge_into(acc, rec)
                out[rec["m"]] = acc
        mem_out: dict[int, dict] = {}
        for b in mem:                                   # a stepped-back clock can repeat a minute
            acc = mem_out.setdefault(b["m"], new_bucket(b["m"]))
            merge_into(acc, b)
        out.update(mem_out)
        return out

    def visible_from(self) -> int:
        """The first minute a read may return: exactly 10,080 minutes before the current minute."""
        return self._minute() - RETENTION_MINUTES

    def capabilities(self) -> dict:
        t = self._thread
        running = t is not None and t.is_alive() and not self._stop.is_set()
        return {
            "enabled": bool(self.enabled),
            "collecting": bool(self.enabled and running),
            "history": "available" if self._store is not None else "unavailable",
            "process_metrics": self._sampler is not None,
            "retention_days": RETENTION_DAYS,
            "malformed_files": len(self._store.malformed) if self._store is not None else 0,
        }

    def live(self) -> dict:
        with self._lock:
            return {"active_lane_work": sum(self._active_lanes.values()), "generation_active": self._gen_active,
                    "last_pass": dict(self._last_pass) if self._last_pass else None,
                    "current_minute": self._cur["m"] if self._cur else None}


_service = MetricsService()


def service() -> MetricsService:
    return _service


def reset(store_root: Optional[Callable[[], Path]] = None) -> MetricsService:
    """A fresh service (tests). Stops a running one first."""
    global _service
    try:
        _service.stop(timeout=1.0)
    except Exception:                                       # noqa: BLE001
        pass
    _service = MetricsService()
    if store_root is not None:
        _service._store_root_fn = store_root
    return _service


# Module-level hooks: the observation seams call these, so a reset() never strands a stale reference.
def odata_begin():
    try:
        return _service.odata_begin()
    except Exception:                                       # noqa: BLE001 — a hook never raises
        return None


def odata_end(token, method, url, status):
    try:
        _service.odata_end(token, method, url, status)
    except Exception:                                       # noqa: BLE001 — a hook never raises
        return None


def catalog_pass(ok, duration_s, changed, bytes_read):
    try:
        _service.catalog_pass(ok, duration_s, changed, bytes_read)
    except Exception:                                       # noqa: BLE001 — a hook never raises
        return None


def icache_hit():
    try:
        _service.icache_hit()
    except Exception:                                       # noqa: BLE001 — a hook never raises
        return None


def icache_invalidated():
    try:
        _service.icache_invalidated()
    except Exception:                                       # noqa: BLE001 — a hook never raises
        return None


def icache_refreshed(duration_s, ok):
    try:
        _service.icache_refreshed(duration_s, ok)
    except Exception:                                       # noqa: BLE001 — a hook never raises
        return None


def lane_started(lane, created_at_iso=""):
    try:
        _service.lane_started(lane, created_at_iso)
    except Exception:                                       # noqa: BLE001 — a hook never raises
        return None


def lane_finished(lane, completed, busy_s):
    try:
        _service.lane_finished(lane, completed, busy_s)
    except Exception:                                       # noqa: BLE001 — a hook never raises
        return None


def generation_submitted():
    try:
        _service.generation_submitted()
    except Exception:                                       # noqa: BLE001 — a hook never raises
        return None


def generation_finished(ok, duration_s):
    try:
        _service.generation_finished(ok, duration_s)
    except Exception:                                       # noqa: BLE001 — a hook never raises
        return None


def queue_view(duration_s, rows, ok):
    try:
        _service.queue_view(duration_s, rows, ok)
    except Exception:                                       # noqa: BLE001 — a hook never raises
        return None


def start(store_root=None) -> bool:
    try:
        return _service.start(store_root)
    except Exception:                                       # noqa: BLE001 — never fail startup
        logger.warning("system stats did not start", exc_info=True)
        return False


def stop() -> None:
    try:
        _service.stop()
    except Exception:                                       # noqa: BLE001 — never delay shutdown
        pass
