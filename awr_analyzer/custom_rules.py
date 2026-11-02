"""User-defined rules: "flag it when metric X crosses Y, and here's what that
means".

Every number the parser extracts is given a dotted name, for example::

    load_profile.redo_size_bytes.per_second
    efficiency.buffer_hit
    wait.log file sync.avg_wait_ms
    tablespace.USERS.avg_read_time_ms
    sql.fu38d0tdu45js.gets_per_exec
    info.avg_active_sessions

A rule names one metric, or many at once with ``*`` / ``?`` wildcards
(``wait.*.avg_wait_ms`` checks every wait event), plus a comparison and a
warning and/or critical threshold::

    {
      "name": "slow_commits",
      "metric": "wait.log file sync.avg_wait_ms",
      "op": ">",
      "warning": 5,
      "critical": 20,
      "title": "Commits are slow ({value:.1f} ms per commit)",
      "explanation": "Users wait on every commit; our SLA needs < 5 ms.",
      "recommendations": ["Ask the storage team to check redo log latency."]
    }

Title, explanation and recommendations may use ``{value}``, ``{match}``
(the part a wildcard matched, e.g. the event name), ``{metric}``,
``{threshold}``, ``{warning}``, ``{critical}``, ``{severity}`` and
``{name}``, with normal Python format specs such as ``{value:,.0f}``.
"""

from __future__ import annotations

import operator
import re

from .models import AWRReport, Finding

OPERATORS = {
    ">": operator.gt,
    ">=": operator.ge,
    "<": operator.lt,
    "<=": operator.le,
    "==": operator.eq,
    "!=": operator.ne,
}

RULE_TEMPLATE = {
    "name": "",
    "enabled": True,
    "metric": "",
    "op": ">",
    "warning": None,
    "critical": None,
    "category": "Custom",
    "title": "",
    "explanation": "",
    "recommendations": [],
}

_WAIT_FIELDS = ("waits", "total_wait_time_sec", "avg_wait_ms", "pct_db_time")
_TS_FIELDS = ("reads", "avg_reads_per_sec", "avg_read_time_ms", "writes",
              "avg_writes_per_sec", "avg_buffer_wait_ms")
_SQL_FIELDS = ("executions", "elapsed_s", "pct_elapsed", "per_exec_s", "cpu_s", "pct_cpu",
               "pct_io", "gets", "gets_per_exec", "reads", "reads_per_exec",
               "rows_processed", "rows_per_exec")


def _is_number(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def flatten_metrics(report: AWRReport, sql_analysis=None) -> dict:
    """Every numeric value in the report, keyed by a dotted metric name."""
    metrics: dict = {}

    def put(name, value):
        if _is_number(value):
            metrics[name] = float(value)

    info = report.info
    for field in ("elapsed_minutes", "db_time_minutes", "cpus", "cores", "sockets", "memory_gb"):
        put(f"info.{field}", getattr(info, field))
    if info.db_time_minutes and info.elapsed_minutes:
        aas = info.db_time_minutes / info.elapsed_minutes
        put("info.avg_active_sessions", aas)
        if info.cpus:
            put("info.aas_per_cpu", aas / info.cpus)

    for key, cols in report.load_profile.items():
        for col, value in cols.items():
            put(f"load_profile.{key}.{col}", value)
    for key, value in report.instance_efficiency.items():
        put(f"efficiency.{key}", value)
    for we in report.top_wait_events:
        for field in _WAIT_FIELDS:
            put(f"wait.{we.event}.{field}", getattr(we, field))
    for wc in report.wait_class_stats:
        for field in _WAIT_FIELDS:
            put(f"wait_class.{wc.event}.{field}", getattr(wc, field))
    for key, values in report.time_model.items():
        for field, value in values.items():
            put(f"time_model.{key}.{field}", value)
    for key, value in report.host_cpu.items():
        put(f"host_cpu.{key}", value)
    for key, value in report.instance_cpu.items():
        put(f"instance_cpu.{key}", value)
    for ts in report.tablespace_io:
        for field in _TS_FIELDS:
            put(f"tablespace.{ts.tablespace}.{field}", getattr(ts, field))
    if sql_analysis is not None:
        for p in sql_analysis.insights:
            for field in _SQL_FIELDS:
                put(f"sql.{p.sql_id}.{field}", getattr(p, field))
    return metrics


def compile_metric_pattern(pattern: str) -> re.Pattern:
    parts = []
    for ch in pattern:
        if ch == "*":
            parts.append("(.+?)")
        elif ch == "?":
            parts.append("(.)")
        else:
            parts.append(re.escape(ch))
    return re.compile("^" + "".join(parts) + "$", re.I)


def is_wildcard(pattern: str) -> bool:
    return "*" in pattern or "?" in pattern


class _SafeDict(dict):
    def __missing__(self, key):
        return "{" + key + "}"


def render_template(template: str, ctx: dict) -> str:
    if not template:
        return ""
    try:
        return template.format_map(_SafeDict(ctx))
    except (ValueError, IndexError, AttributeError, TypeError, KeyError):
        return template


def validate_rule(rule) -> list:
    if not isinstance(rule, dict):
        return ["a rule must be an object"]
    errors = []
    if not isinstance(rule.get("name"), str) or not rule["name"].strip():
        errors.append("needs a 'name'")
    elif not re.fullmatch(r"[A-Za-z0-9_.\-]+", rule["name"]):
        errors.append("'name' may only use letters, digits, '_', '-' and '.'")
    if not isinstance(rule.get("metric"), str) or not rule["metric"].strip():
        errors.append("needs a 'metric' (e.g. 'wait.log file sync.avg_wait_ms')")
    if rule.get("op", ">") not in OPERATORS:
        errors.append(f"'op' must be one of {' '.join(OPERATORS)}")
    warn, crit = rule.get("warning"), rule.get("critical")
    if warn is None and crit is None:
        errors.append("needs a 'warning' and/or 'critical' threshold")
    for key, value in (("warning", warn), ("critical", crit)):
        if value is not None and not _is_number(value):
            errors.append(f"'{key}' must be a number")
    recs = rule.get("recommendations", [])
    if not isinstance(recs, list) or not all(isinstance(r, str) for r in recs):
        errors.append("'recommendations' must be a list of text lines")
    mm = rule.get("max_matches")
    if mm is not None and (not isinstance(mm, int) or isinstance(mm, bool) or mm < 1):
        errors.append("'max_matches' must be a whole number of at least 1")
    return errors


def match_rule(rule: dict, metrics: dict) -> list:
    """All metrics the rule's pattern matches, breached or not. Each item is
    a dict with name, value, match (wildcard capture), severity (None if not
    breached) and threshold."""
    if validate_rule(rule):
        return []
    op = OPERATORS[rule.get("op", ">")]
    warn, crit = rule.get("warning"), rule.get("critical")
    pattern = compile_metric_pattern(rule["metric"].strip())
    results = []
    for name, value in metrics.items():
        m = pattern.match(name)
        if not m:
            continue
        severity, threshold = None, None
        if crit is not None and op(value, crit):
            severity, threshold = "critical", crit
        elif warn is not None and op(value, warn):
            severity, threshold = "warning", warn
        captured = "/".join(g for g in m.groups() if g) or name
        results.append({"name": name, "value": value, "match": captured,
                        "severity": severity, "threshold": threshold})
    rank = {"critical": 0, "warning": 1, None: 2}
    results.sort(key=lambda r: (rank[r["severity"]], -abs(r["value"])))
    return results


def evaluate_rule(rule: dict, metrics: dict, default_max_matches: int = 10) -> list:
    if not isinstance(rule, dict) or not rule.get("enabled", True):
        return []
    hits = [r for r in match_rule(rule, metrics) if r["severity"]]
    cap = rule.get("max_matches") or default_max_matches
    name = rule["name"]
    wildcard = is_wildcard(rule["metric"])
    findings = []
    for hit in hits[:cap]:
        ctx = {
            "value": hit["value"], "metric": hit["name"], "match": hit["match"],
            "threshold": hit["threshold"], "severity": hit["severity"], "name": name,
            "warning": rule.get("warning"), "critical": rule.get("critical"),
            "op": rule.get("op", ">"),
        }
        title = render_template(rule.get("title", ""), ctx) or (
            f"Custom rule '{name}': {hit['match']} = {hit['value']:,.4g} "
            f"({rule.get('op', '>')} {hit['threshold']:g})"
        )
        explanation = render_template(rule.get("explanation", ""), ctx) or (
            "This finding comes from a custom rule in your configuration."
        )
        findings.append(Finding(
            severity=hit["severity"],
            category=rule.get("category") or "Custom",
            title=title,
            plain_explanation=explanation,
            technical_detail=(
                f"Custom rule '{name}': {hit['name']} = {hit['value']:,.6g} "
                f"(warning {rule.get('op', '>')} {rule.get('warning')}, "
                f"critical {rule.get('op', '>')} {rule.get('critical')})."
            ),
            recommendations=[render_template(r, ctx) for r in rule.get("recommendations") or []],
            evidence={"rule": name, "metric": hit["name"], "value": hit["value"],
                      "threshold": hit["threshold"]},
            rule_id=f"custom.{name}" + (f".{hit['match']}" if wildcard else ""),
        ))
    return findings


def evaluate_rules(rules_list: list, metrics: dict, default_max_matches: int = 10) -> list:
    findings = []
    for rule in rules_list or []:
        findings.extend(evaluate_rule(rule, metrics, default_max_matches))
    return findings
