"""Cross-references the various "SQL ordered by ..." sections of an AWR
report into a single profile per SQL_ID, and flags queries worth a
developer/DBA's attention: CPU-bound vs. I/O-bound, likely missing indexes,
poor row selectivity, high call volume, and expensive low-frequency
statements. Also looks for groups of near-identical statements that differ
only in literal values — a common sign the application isn't using bind
variables.

AWR only gives you the top N statements per metric (elapsed, CPU, gets,
reads, executions), so a statement missing from one list simply means it
wasn't in that particular top N — not that the value is zero. Profiles are
built from whatever is available and left blank (None) elsewhere.
"""

from __future__ import annotations

import re

from . import rules
from .models import AWRReport, BindVariableSuspectGroup, SQLAnalysis, SQLInsight

_LIST_NAMES = {
    "sql_by_elapsed": "Elapsed Time",
    "sql_by_cpu": "CPU Time",
    "sql_by_gets": "Buffer Gets",
    "sql_by_reads": "Physical Reads",
    "sql_by_executions": "Executions",
}

_SEVERITY_ORDER = {"critical": 0, "warning": 1, "info": 2}


def _merge(report: AWRReport) -> dict:
    profiles: dict = {}

    def get(sql_id: str) -> SQLInsight:
        if sql_id not in profiles:
            profiles[sql_id] = SQLInsight(sql_id=sql_id)
        return profiles[sql_id]

    for list_attr, label in _LIST_NAMES.items():
        for stat in getattr(report, list_attr):
            p = get(stat.sql_id)
            if label not in p.seen_in:
                p.seen_in.append(label)

            p.module = p.module or stat.module
            p.sql_text = p.sql_text or stat.sql_text

            if p.executions is None and stat.executions is not None:
                p.executions = stat.executions

            if p.elapsed_s is None:
                if list_attr == "sql_by_elapsed" and stat.value is not None:
                    p.elapsed_s = stat.value
                elif stat.elapsed_time_s is not None:
                    p.elapsed_s = stat.elapsed_time_s

            if list_attr == "sql_by_elapsed":
                if p.pct_elapsed is None and stat.pct_total is not None:
                    p.pct_elapsed = stat.pct_total
                if p.per_exec_s is None and stat.per_exec is not None:
                    p.per_exec_s = stat.per_exec

            if list_attr == "sql_by_cpu" and p.cpu_s is None and stat.value is not None:
                p.cpu_s = stat.value

            if p.pct_cpu is None and stat.pct_cpu is not None:
                p.pct_cpu = stat.pct_cpu
            if p.pct_io is None and stat.pct_io is not None:
                p.pct_io = stat.pct_io

            if list_attr == "sql_by_gets":
                if p.gets is None and stat.value is not None:
                    p.gets = stat.value
                if p.gets_per_exec is None and stat.per_exec is not None:
                    p.gets_per_exec = stat.per_exec

            if list_attr == "sql_by_reads":
                if p.reads is None and stat.value is not None:
                    p.reads = stat.value
                if p.reads_per_exec is None and stat.per_exec is not None:
                    p.reads_per_exec = stat.per_exec

            if list_attr == "sql_by_executions":
                if p.rows_processed is None and stat.rows_processed is not None:
                    p.rows_processed = stat.rows_processed
                if p.rows_per_exec is None and stat.rows_per_exec is not None:
                    p.rows_per_exec = stat.rows_per_exec

    return profiles


def _add_tag(p: SQLInsight, key: str, severity_override: str = None) -> None:
    info = rules.SQL_TAG_INFO[key]
    p.tags.append(key)
    p.notes.append(info["plain"])
    p.recommendations.extend(info["recommendations"])
    severity = severity_override or info["severity"]
    if _SEVERITY_ORDER.get(severity, 9) < _SEVERITY_ORDER.get(p.severity, 9):
        p.severity = severity


def _classify(p: SQLInsight) -> None:
    if p.pct_cpu is not None and p.pct_cpu >= rules.SQL_CPU_BOUND_PCT:
        _add_tag(p, "cpu_bound")

    if p.pct_io is not None and p.pct_io >= rules.SQL_IO_BOUND_PCT:
        _add_tag(p, "io_bound")

    if p.gets_per_exec is not None and p.gets_per_exec >= rules.SQL_GETS_PER_EXEC_WARNING:
        sev = "critical" if p.gets_per_exec >= rules.SQL_GETS_PER_EXEC_CRITICAL else "warning"
        _add_tag(p, "missing_index_suspect", sev)

    if p.reads_per_exec is not None and p.reads_per_exec >= rules.SQL_READS_PER_EXEC_WARNING:
        sev = "critical" if p.reads_per_exec >= rules.SQL_READS_PER_EXEC_CRITICAL else "warning"
        _add_tag(p, "physical_read_heavy", sev)

    if p.gets_per_exec and p.rows_per_exec:
        gets_per_row = p.gets_per_exec / p.rows_per_exec
        if gets_per_row >= rules.SQL_GETS_PER_ROW_WARNING:
            sev = "critical" if gets_per_row >= rules.SQL_GETS_PER_ROW_CRITICAL else "warning"
            _add_tag(p, "low_selectivity_suspect", sev)

    if ((p.executions or 0) >= rules.SQL_HIGH_VOLUME_EXECUTIONS
            and (p.pct_elapsed or 0) >= rules.SQL_HIGH_VOLUME_MIN_PCT_ELAPSED):
        _add_tag(p, "high_call_volume")

    if (p.executions is not None and p.executions <= rules.SQL_EXPENSIVE_SINGLE_RUN_MAX_EXECS
            and (p.per_exec_s or 0) >= rules.SQL_EXPENSIVE_SINGLE_RUN_MIN_PER_EXEC_S):
        _add_tag(p, "expensive_single_run")

    # A query dominating DB time deserves a warning/critical flag even if
    # every tag it tripped so far was only informational (e.g. high call
    # volume, expensive single run) rather than a specific tuning mechanism.
    if p.severity not in ("critical", "warning") and p.pct_elapsed is not None \
            and p.pct_elapsed >= rules.SQL_PCT_WARNING:
        sev = "critical" if p.pct_elapsed >= rules.SQL_PCT_CRITICAL else "warning"
        _add_tag(p, "high_impact", sev)

    p.recommendations = list(dict.fromkeys(p.recommendations))  # de-dupe, keep order


_LITERAL_STR_RE = re.compile(r"'[^']*'")
_LITERAL_NUM_RE = re.compile(r"\b\d+\b")


def _normalize_signature(text: str):
    if not text:
        return None
    t = _LITERAL_STR_RE.sub("?", text)
    t = _LITERAL_NUM_RE.sub("?", t)
    t = re.sub(r"\s+", " ", t).strip().lower()
    if len(t) < 12:
        return None
    return t


def _find_bind_variable_suspects(profiles: dict) -> list:
    groups: dict = {}
    for p in profiles.values():
        sig = _normalize_signature(p.sql_text)
        if not sig:
            continue
        groups.setdefault(sig, []).append(p)

    suspects = []
    for sig, plist in groups.items():
        distinct_ids = sorted({p.sql_id for p in plist})
        if len(distinct_ids) >= rules.SQL_BIND_VARIABLE_MIN_GROUP_SIZE:
            suspects.append(BindVariableSuspectGroup(
                signature=sig, sql_ids=distinct_ids,
                module=plist[0].module, sample_text=plist[0].sql_text,
            ))
    suspects.sort(key=lambda g: -len(g.sql_ids))
    return suspects


def build_sql_insights(report: AWRReport) -> SQLAnalysis:
    profiles = _merge(report)
    db_time_sec = (report.info.db_time_minutes or 0) * 60

    for p in profiles.values():
        if p.per_exec_s is None and p.elapsed_s is not None and p.executions:
            p.per_exec_s = p.elapsed_s / p.executions
        if p.pct_elapsed is None and p.elapsed_s is not None and db_time_sec:
            p.pct_elapsed = (p.elapsed_s / db_time_sec) * 100
        _classify(p)

    insights = sorted(profiles.values(), key=lambda p: (p.elapsed_s or 0), reverse=True)
    suspects = _find_bind_variable_suspects(profiles)
    return SQLAnalysis(insights=insights, bind_variable_suspects=suspects)
