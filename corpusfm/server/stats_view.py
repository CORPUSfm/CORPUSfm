"""The read model behind System → Stats (packet 1409): bounded windows of minute rollups, merged to a
resolution derived from the named range, as fixed-schema panels of numeric points.

Missing data is ``None`` — a minute with no record (the process was down, or persistence failed) or a
recorded minute without a process sample. A recorded minute with no events is a real zero for a
counter. Gauge points are means of the merged samples; counters are sums per point; latency
percentiles come from the merged histogram, never from averaging per-minute percentiles.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from corpusfm.server import metrics as M

RANGES = {"1h": (60, 1), "24h": (1440, 5), "7d": (10080, 30)}   # minutes, resolution minutes


def _iso(minute: int) -> str:
    return datetime.fromtimestamp(minute * 60, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _mean(s: dict) -> Optional[float]:
    return (s["sum"] / s["n"]) if s.get("n") else None


def _ms(v: Optional[float]) -> Optional[float]:
    return None if v is None else v * 1000.0


def _series_defs():
    """(panel id, title, unit, [(series id, label, extractor(bucket, minutes) -> value|None)])."""
    def proc(key, how="mean"):
        def f(b, _n):
            if not b["proc"]["samples"]:
                return None
            s = b["proc"][key]
            return _mean(s) if how == "mean" else s.get(how)
        return f

    def count(path):
        def f(b, _n):
            node = b
            for k in path:
                node = node[k]
            return float(node)
        return f

    def lane_sum(field):
        return lambda b, _n: float(sum(b["lanes"][ln][field] for ln in M.LANES))

    def wait_max(b, _n):
        vals = [b["lanes"][ln]["wait"]["max"] for ln in M.LANES if b["lanes"][ln]["wait"]["max"] is not None]
        return max(vals) if vals else None

    def odq(q):
        return lambda b, _n: _ms(M.hist_quantile(b["odata"]["hist"], q, b["odata"]["dur"]["max"]))

    return [
        ("memory", "CORPUSfm memory", "MiB", [
            ("tree_rss", "Process tree (web + child processes)", proc("tree_rss_mib")),
            ("web_rss", "Web process", proc("web_rss_mib"))]),
        ("cpu", "CORPUSfm CPU", "%", [
            ("tree_cpu", "Process tree (web + child processes)", proc("tree_cpu_pct")),
            ("web_cpu", "Web process", proc("web_cpu_pct"))]),
        ("host_memory", "Host available memory (context)", "MiB", [
            ("host_avail", "Host available memory", proc("host_avail_mib"))]),
        ("odata_latency", "FileMaker database calls — duration", "ms", [
            ("p50", "p50", odq(0.5)), ("p95", "p95", odq(0.95)),
            ("max", "max", lambda b, _n: _ms(b["odata"]["dur"]["max"]))]),
        ("odata_volume", "FileMaker database calls — volume", "count", [
            ("calls", "Calls", lambda b, _n: float(b["odata"]["dur"]["n"])),
            ("errors", "Errors (5xx or no response)", count(("odata", "err"))),
            ("inflight", "Peak in flight", count(("odata", "inflight_max")))]),
        ("timings", "Catalog, cache and queue-view timings", "ms", [
            ("catalog_pass", "Catalog pass (max)", lambda b, _n: _ms(b["catalog"]["dur"]["max"])),
            ("icache_refresh", "Indexed-membership refresh (max)", lambda b, _n: _ms(b["icache"]["refresh"]["max"])),
            ("qview_read", "Queue view read (max)", lambda b, _n: _ms(b["qview"]["dur"]["max"]))]),
        ("catalog_cache", "Catalog and cache events", "count", [
            ("passes", "Catalog passes", count(("catalog", "passes"))),
            ("pass_fail", "Catalog pass failures", count(("catalog", "fail"))),
            ("changed", "Changed records", count(("catalog", "changed"))),
            ("hits", "Cache hits", count(("icache", "hit"))),
            ("misses", "Cache misses", count(("icache", "miss"))),
            ("inval", "Cache invalidations", count(("icache", "inval")))]),
        ("lane_busy", "Queue lanes — busy time", "s", [
            (f"busy_{ln}", ln, (lambda ln: lambda b, _n: float(b["lanes"][ln]["busy_s"]))(ln)) for ln in M.LANES]),
        ("lane_events", "Queue lanes — work items", "count", [
            ("started", "Started", lane_sum("start")),
            ("completed", "Completed", lane_sum("done")),
            ("failed", "Failed", lane_sum("fail"))]),
        ("lane_wait", "Queue lanes — claimed-item wait", "s", [
            ("wait_max", "Longest wait before claim", wait_max)]),
        ("generation", "Generation and child processes", "count", [
            ("children", "Sampled child processes (max)", proc("children", "max")),
            ("active", "Active jobs (max)", count(("gen", "active_max"))),
            ("submitted", "Submitted", count(("gen", "submitted"))),
            ("gen_done", "Completed", count(("gen", "done"))),
            ("gen_fail", "Failed", count(("gen", "fail")))]),
        ("queue_view", "Queue view reads", "count", [
            ("reads", "Reads", lambda b, _n: float(b["qview"]["dur"]["n"])),
            ("rows", "Rows returned (max)", lambda b, _n: b["qview"]["rows"]["max"])]),
    ]


def resolve_window(range_name: str, end_minute: Optional[int], now_minute: int) -> dict:
    if range_name not in RANGES:
        raise ValueError("range")
    span, res = RANGES[range_name]
    retention_start = now_minute - M.RETENTION_MINUTES
    clamped = False
    end = now_minute if end_minute is None else int(end_minute)
    if end > now_minute:
        end, clamped = now_minute, True
    end = end - (end % res)                          # align so points are stable as time advances
    start = end - span
    if start < retention_start:
        start, clamped = retention_start - (retention_start % res), True
        end = start + span
    return {"range": range_name, "start": start, "end": end, "resolution": res, "clamped": clamped,
            "retention_start": retention_start, "now": now_minute}


def build(svc: "M.MetricsService", range_name: str, end_minute: Optional[int] = None,
          now_minute: Optional[int] = None) -> dict:
    now = int(now_minute if now_minute is not None else svc._minute())
    w = resolve_window(range_name, end_minute, now)
    recs = svc.snapshot(w["start"], w["end"])
    res = w["resolution"]
    points_t: list[int] = list(range(w["start"], w["end"], res))
    merged: list[Optional[dict]] = []
    window_acc = M.new_bucket(w["start"])
    any_rec = False
    for t in points_t:
        acc = None
        for m in range(t, t + res):
            r = recs.get(m)
            if r is None:
                continue
            if acc is None:
                acc = M.new_bucket(t)
            M.merge_into(acc, r)
        merged.append(acc)
        if acc is not None:
            any_rec = True
            M.merge_into(window_acc, acc)
    panels = []
    for pid, title, unit, sdefs in _series_defs():
        series = []
        for sid, label, fn in sdefs:
            pts = []
            vals = []
            for t, acc in zip(points_t, merged):
                v = None
                if acc is not None:
                    try:
                        v = fn(acc, res)
                    except Exception:                       # noqa: BLE001 — a bad record is a gap
                        v = None
                v = None if v is None else round(float(v), 3)
                pts.append([t * 60000, v])
                if v is not None:
                    vals.append(v)
            series.append({"id": sid, "label": label, "points": pts,
                           "min": min(vals) if vals else None,
                           "mean": round(sum(vals) / len(vals), 3) if vals else None,
                           "max": max(vals) if vals else None})
        panels.append({"id": pid, "title": title, "unit": unit, "series": series})
    od = window_acc["odata"]
    odata_window = {"calls": od["dur"]["n"], "errors": od["err"],
                    "p50_ms": _ms(M.hist_quantile(od["hist"], 0.5, od["dur"]["max"])),
                    "p95_ms": _ms(M.hist_quantile(od["hist"], 0.95, od["dur"]["max"]))}
    for k in ("p50_ms", "p95_ms"):
        if odata_window[k] is not None:
            odata_window[k] = round(odata_window[k], 3)
    return {
        "ok": True,
        "capabilities": {**svc.capabilities(), "resolution_minutes": res, "has_data": any_rec},
        "window": {"range": w["range"], "start_utc": _iso(w["start"]), "end_utc": _iso(w["end"]),
                   "start_ms": w["start"] * 60000, "end_ms": w["end"] * 60000,
                   "resolution_minutes": res, "clamped": w["clamped"],
                   "retention_start_utc": _iso(w["retention_start"]), "now_utc": _iso(w["now"]),
                   "at_now": w["end"] >= w["now"] - (w["now"] % res)},
        "odata_window": odata_window,
        "cards": _cards(svc, now),
        "panels": panels,
    }


def _cards(svc, now: int) -> dict:
    recent = svc.snapshot(now - 15, now)
    acc = M.new_bucket(now)
    for r in recent.values():
        M.merge_into(acc, r)
    live = svc.live()
    last = None
    for m in sorted(recent, reverse=True):
        if recent[m]["proc"]["samples"]:
            last = recent[m]["proc"]["tree_rss_mib"]
            break
    lp = live.get("last_pass")
    od = acc["odata"]
    return {
        "tree_rss_mib": None if not last or not last["n"] else round(last["sum"] / last["n"], 1),
        "active_background_work": live["active_lane_work"] + live["generation_active"],
        "odata_p50_ms_15m": _round(_ms(M.hist_quantile(od["hist"], 0.5, od["dur"]["max"]))),
        "odata_p95_ms_15m": _round(_ms(M.hist_quantile(od["hist"], 0.95, od["dur"]["max"]))),
        "odata_calls_15m": od["dur"]["n"],
        "last_catalog_pass": None if not lp else {"ok": lp["ok"], "duration_ms": round(lp["duration_s"] * 1000, 1),
                                                  "at_utc": _iso(lp["at_minute"]), "changed": lp["changed"]},
    }


def _round(v):
    return None if v is None else round(v, 3)
