"""Trend analysis across a chronological series of AWR reports.

A single AWR report is a snapshot; this module looks at a *series* of them
(e.g. daily AWR reports for the same instance over a couple of weeks) and
tries to answer "is this getting better or worse, and how fast?" for a set
of key metrics, using a simple linear trend. It deliberately keeps the math
simple (linear regression, no external forecasting libraries) and is honest
in its output that this is a naive projection meant to flag emerging risks
early, not a precise prediction.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional

from . import rules
from .models import AWRReport

_DATE_FORMATS = [
    "%d-%b-%y %H:%M:%S",
    "%d-%b-%Y %H:%M:%S",
    "%d-%b-%y %H:%M",
    "%d-%b-%Y %H:%M",
    "%Y-%m-%d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%y %H:%M:%S",
]


def _parse_time(text: Optional[str]) -> Optional[datetime]:
    if not text:
        return None
    text = re.sub(r"\s+", " ", text).strip()
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def _lp(report: AWRReport, *substrings: str) -> Optional[float]:
    """Fuzzy lookup into load_profile per-second values by substring, since
    exact label text drifts across Oracle versions."""
    for key, vals in report.load_profile.items():
        for s in substrings:
            if s in key:
                v = vals.get("per_second")
                if v is not None:
                    return v
    return None


def _wait_field(report: AWRReport, pattern: str, field_name: str) -> Optional[float]:
    for we in report.top_wait_events:
        if re.search(pattern, we.event or "", re.I):
            return getattr(we, field_name)
    return None


def _aas(report: AWRReport) -> Optional[float]:
    if report.info.db_time_minutes and report.info.elapsed_minutes:
        return report.info.db_time_minutes / report.info.elapsed_minutes
    return None


@dataclass
class MetricDef:
    key: str
    label: str
    unit: str
    good_direction: Optional[str]  # "up", "down", or None (context-dependent)
    extractor: Callable[[AWRReport], Optional[float]]
    critical_threshold: Optional[float] = None
    threshold_is_upper_bound: bool = True  # True: bad when value rises above; False: bad when value falls below


TRACKED_METRICS = [
    MetricDef("aas", "Average Active Sessions", "sessions", None, _aas),
    MetricDef("buffer_hit", "Buffer Cache Hit Ratio", "%", "up",
              lambda r: r.instance_efficiency.get("buffer_hit"),
              critical_threshold=rules.EFFICIENCY_THRESHOLDS["buffer_hit"][1], threshold_is_upper_bound=False),
    MetricDef("library_hit", "Library Cache Hit Ratio", "%", "up",
              lambda r: r.instance_efficiency.get("library_hit"),
              critical_threshold=rules.EFFICIENCY_THRESHOLDS["library_hit"][1], threshold_is_upper_bound=False),
    MetricDef("soft_parse", "Soft Parse Ratio", "%", "up",
              lambda r: r.instance_efficiency.get("soft_parse"),
              critical_threshold=rules.EFFICIENCY_THRESHOLDS["soft_parse"][1], threshold_is_upper_bound=False),
    MetricDef("physical_reads", "Physical Reads", "blocks/sec", "down",
              lambda r: _lp(r, "physical_read")),
    MetricDef("logical_reads", "Logical Reads", "blocks/sec", "down",
              lambda r: _lp(r, "logical_read")),
    MetricDef("redo_size", "Redo Generation", "bytes/sec", "down",
              lambda r: _lp(r, "redo_size")),
    MetricDef("hard_parses", "Hard Parses", "per sec", "down",
              lambda r: _lp(r, "hard_pars"),
              critical_threshold=rules.HARD_PARSE_CRITICAL, threshold_is_upper_bound=True),
    MetricDef("db_cpu_pct", "DB CPU (% of DB time)", "%", "down",
              lambda r: _wait_field(r, r"^db cpu$|^cpu time$", "pct_db_time"),
              critical_threshold=rules.DB_CPU_PCT_CRITICAL, threshold_is_upper_bound=True),
    MetricDef("seq_read_ms", "'db file sequential read' avg wait", "ms", "down",
              lambda r: _wait_field(r, r"^db file sequential read", "avg_wait_ms"),
              critical_threshold=rules.SEQ_READ_MS_CRITICAL, threshold_is_upper_bound=True),
]


@dataclass
class TrendPoint:
    index: int
    label: str
    value: float


@dataclass
class TrendResult:
    key: str
    label: str
    unit: str
    points: list = field(default_factory=list)      # list[TrendPoint]
    slope_per_snapshot: Optional[float] = None
    pct_change: Optional[float] = None
    direction: str = "stable"                        # improving | worsening | increasing | decreasing | stable
    forecast_note: Optional[str] = None

    @property
    def first_value(self):
        return self.points[0].value if self.points else None

    @property
    def last_value(self):
        return self.points[-1].value if self.points else None


@dataclass
class TrendAnalysis:
    labels: list                        # snapshot labels, in order
    results: list = field(default_factory=list)   # list[TrendResult]

    def emerging_risks(self):
        return [r for r in self.results if r.direction == "worsening" and r.forecast_note]


_STABLE_EPSILON_FRACTION = 0.01  # slope smaller than 1% of the metric's average value counts as "stable"


def build_trend(reports: list) -> TrendAnalysis:
    """``reports`` should already be in chronological order (oldest first)."""
    labels = []
    for i, r in enumerate(reports):
        ts = _parse_time(r.info.begin_snap_time)
        if ts:
            labels.append(ts.strftime("%Y-%m-%d %H:%M"))
        elif r.info.begin_snap_time:
            labels.append(r.info.begin_snap_time)
        else:
            labels.append(f"Report {i + 1}")

    results = []
    for mdef in TRACKED_METRICS:
        points = []
        for i, r in enumerate(reports):
            v = mdef.extractor(r)
            if v is not None:
                points.append(TrendPoint(index=i, label=labels[i], value=v))
        if len(points) < 2:
            continue

        xs = [p.index for p in points]
        ys = [p.value for p in points]
        slope = _linear_slope(xs, ys)
        first, last = ys[0], ys[-1]
        pct_change = ((last - first) / abs(first) * 100) if first not in (0, None) else None

        avg_val = sum(ys) / len(ys)
        direction = _classify_direction(slope, avg_val, mdef.good_direction)

        forecast_note = _forecast_note(mdef, points, slope, direction)

        results.append(TrendResult(
            key=mdef.key, label=mdef.label, unit=mdef.unit, points=points,
            slope_per_snapshot=slope, pct_change=pct_change, direction=direction,
            forecast_note=forecast_note,
        ))

    return TrendAnalysis(labels=labels, results=results)


def _linear_slope(xs: list, ys: list) -> float:
    n = len(xs)
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    num = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    den = sum((x - mean_x) ** 2 for x in xs)
    if den == 0:
        return 0.0
    return num / den


def _classify_direction(slope: float, avg_val: float, good_direction: Optional[str]) -> str:
    threshold = abs(avg_val) * _STABLE_EPSILON_FRACTION if avg_val else 0.0
    if abs(slope) <= max(threshold, 1e-9):
        return "stable"
    rising = slope > 0
    if good_direction is None:
        return "increasing" if rising else "decreasing"
    if good_direction == "up":
        return "improving" if rising else "worsening"
    else:  # good_direction == "down"
        return "worsening" if rising else "improving"


def _forecast_note(mdef: MetricDef, points: list, slope: float, direction: str) -> Optional[str]:
    if direction not in ("worsening", "increasing"):
        return None
    if mdef.critical_threshold is None or slope == 0:
        if direction == "worsening":
            last = points[-1].value
            first = points[0].value
            change = last - first
            return (
                f"{mdef.label} moved from {first:.2f} to {last:.2f} {mdef.unit} across the "
                f"provided reports — trending in the wrong direction. No fixed critical "
                f"threshold is defined for this metric, so treat this as a directional "
                f"signal rather than an imminent failure point."
            )
        return None

    last_point = points[-1]
    last_value = last_point.value
    threshold = mdef.critical_threshold

    if mdef.threshold_is_upper_bound:
        if slope <= 0 or last_value >= threshold:
            return _threshold_already_or_not_applicable(mdef, last_value, threshold, above=True)
        snapshots_to_cross = (threshold - last_value) / slope
    else:
        if slope >= 0 or last_value <= threshold:
            return _threshold_already_or_not_applicable(mdef, last_value, threshold, above=False)
        snapshots_to_cross = (threshold - last_value) / slope

    if snapshots_to_cross <= 0:
        return None
    if snapshots_to_cross > 100:
        return (
            f"{mdef.label} is trending toward the concerning range, but at the current rate "
            f"it would take a very large number of additional snapshots to actually cross "
            f"the critical threshold ({threshold}{mdef.unit}) — worth monitoring, not urgent."
        )

    return (
        f"At the current rate of change (based on a simple linear trend across the reports "
        f"provided), {mdef.label} is projected to cross the critical threshold "
        f"({threshold}{mdef.unit}) in roughly {snapshots_to_cross:.1f} more report period(s) "
        f"if nothing changes. This is a naive straight-line projection meant as an early "
        f"warning, not a guarantee — real systems rarely degrade in a perfectly straight "
        f"line, so re-check as new AWR reports come in."
    )


def _threshold_already_or_not_applicable(mdef: MetricDef, last_value: float, threshold: float, above: bool) -> Optional[str]:
    crossed = (last_value >= threshold) if above else (last_value <= threshold)
    if crossed:
        return (
            f"{mdef.label} has already reached a concerning level ({last_value:.2f}{mdef.unit}, "
            f"critical threshold is {threshold}{mdef.unit}) as of the most recent report in "
            f"this series — this is a current issue, not just a future risk."
        )
    return None
