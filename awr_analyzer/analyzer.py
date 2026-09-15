"""Turns a parsed :class:`~awr_analyzer.models.AWRReport` into a list of
plain-language :class:`~awr_analyzer.models.Finding` objects, plus an overall
health score.

The goal is that someone without deep Oracle experience can read a finding
top to bottom and understand: what's happening, why it matters, and what to
do about it — while a DBA can still see the exact numbers behind it.
"""

from __future__ import annotations

import re

from . import rules
from .models import AnalysisResult, AWRReport, Finding


def analyze(report: AWRReport) -> AnalysisResult:
    findings = []

    _check_efficiency(report, findings)
    _check_wait_events(report, findings)
    _check_cpu_load(report, findings)
    _check_parse_rate(report, findings)
    _check_sql(report, findings)
    _check_tablespace_io(report, findings)

    if not findings:
        findings.append(Finding(
            severity="info",
            category="General",
            title="No significant issues detected",
            plain_explanation=(
                "Based on the sections of this AWR report that could be parsed, nothing "
                "crossed the thresholds this tool checks for. That's a good sign, but it "
                "doesn't guarantee the system is problem-free — always sanity check against "
                "how users actually experienced this time window."
            ),
            technical_detail="No metric breached its configured warning/critical threshold.",
        ))

    findings.sort(key=lambda f: f.severity_rank())
    health_score = _health_score(findings)
    summary = _summary_text(report, findings, health_score)
    return AnalysisResult(report=report, findings=findings, health_score=health_score, summary=summary)


def _health_score(findings) -> int:
    score = 100
    for f in findings:
        if f.severity == "critical":
            score -= 20
        elif f.severity == "warning":
            score -= 8
        elif f.severity == "info":
            score -= 0
    return max(0, min(100, score))


def _summary_text(report: AWRReport, findings, health_score: int) -> str:
    counts = {"critical": 0, "warning": 0, "info": 0, "good": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    window = ""
    if report.info.elapsed_minutes:
        window = f" over a {report.info.elapsed_minutes:.0f}-minute window"

    if counts["critical"]:
        headline = (
            f"This AWR snapshot{window} shows {counts['critical']} critical issue(s) that "
            f"likely had a noticeable impact on performance, plus {counts['warning']} "
            f"item(s) worth reviewing."
        )
    elif counts["warning"]:
        headline = (
            f"This AWR snapshot{window} looks broadly healthy, but has {counts['warning']} "
            f"item(s) worth keeping an eye on before they become bigger problems."
        )
    else:
        headline = f"This AWR snapshot{window} does not show any significant performance issues."

    return headline


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------

def _check_efficiency(report: AWRReport, findings: list) -> None:
    for key, (warn_below, crit_below) in rules.EFFICIENCY_THRESHOLDS.items():
        value = report.instance_efficiency.get(key)
        if value is None:
            continue
        label = rules.EFFICIENCY_LABELS.get(key, key)
        explanation = rules.EFFICIENCY_EXPLANATIONS.get(key, "")
        recs = rules.EFFICIENCY_RECOMMENDATIONS.get(key, [])

        if value < crit_below:
            severity = "critical"
        elif value < warn_below:
            severity = "warning"
        else:
            continue

        findings.append(Finding(
            severity=severity,
            category="Efficiency",
            title=f"{label} is low ({value:.1f}%)",
            plain_explanation=explanation,
            technical_detail=(
                f"{label} = {value:.2f}%. Expected to normally stay above {warn_below:.0f}%; "
                f"below {crit_below:.0f}% is a strong signal of a real problem."
            ),
            recommendations=recs,
            evidence={"metric": key, "value": value,
                      "warning_threshold": warn_below, "critical_threshold": crit_below},
        ))


def _check_wait_events(report: AWRReport, findings: list) -> None:
    db_time_sec = (report.info.db_time_minutes or 0) * 60

    for we in report.top_wait_events:
        name = (we.event or "").strip()
        if not name:
            continue
        if re.search(r"cpu time|^db cpu$", name, re.I):
            continue  # handled separately by _check_cpu_load

        pct = we.pct_db_time
        if pct is None and db_time_sec and we.total_wait_time_sec is not None:
            pct = (we.total_wait_time_sec / db_time_sec) * 100

        kb = rules.lookup_wait_event(name)

        is_idle = kb is not None and kb["category"] == "Idle/Network"

        severity = None
        if pct is not None and not is_idle:
            if pct >= rules.WAIT_EVENT_PCT_CRITICAL:
                severity = "critical"
            elif pct >= rules.WAIT_EVENT_PCT_WARNING:
                severity = "warning"

        # Special-case: sequential read latency can be a problem even if it's
        # not the single biggest contributor to DB time.
        if severity is None and re.search(r"^db file sequential read", name, re.I) and we.avg_wait_ms:
            if we.avg_wait_ms >= rules.SEQ_READ_MS_CRITICAL:
                severity = "critical"
            elif we.avg_wait_ms >= rules.SEQ_READ_MS_WARNING:
                severity = "warning"

        if severity is None:
            continue

        plain = kb["plain"] if kb else (
            f"'{name}' is consuming a significant share of database time, but this tool "
            f"doesn't have specific guidance for this particular wait event yet. It's worth "
            f"researching this event name directly (Oracle's documentation and MOS notes are "
            f"good sources) to understand what it means for this workload."
        )
        recs = list(kb["recommendations"]) if kb else [
            f"Search Oracle documentation / My Oracle Support for the wait event '{name}' to "
            f"understand its specific cause.",
        ]
        category = kb["category"] if kb else "Other"

        evidence = {
            "event": name,
            "waits": we.waits,
            "total_wait_time_sec": we.total_wait_time_sec,
            "avg_wait_ms": we.avg_wait_ms,
            "pct_db_time": pct,
            "wait_class": we.wait_class,
        }

        pct_text = f"{pct:.1f}% of total DB time" if pct is not None else "a significant share of DB time"
        avg_text = f", averaging {we.avg_wait_ms:.2f} ms per wait" if we.avg_wait_ms is not None else ""

        findings.append(Finding(
            severity=severity,
            category=category,
            title=f"High wait time on '{name}' ({pct_text})",
            plain_explanation=plain,
            technical_detail=(
                f"Event '{name}': {we.waits or 0:.0f} waits, "
                f"{we.total_wait_time_sec or 0:.0f}s total wait time{avg_text}, "
                f"{pct_text}."
            ),
            recommendations=recs,
            evidence=evidence,
        ))


def _check_cpu_load(report: AWRReport, findings: list) -> None:
    cpu_pct = None
    cpu_time_s = None
    for we in report.top_wait_events:
        if re.search(r"^db cpu$|^cpu time$", (we.event or ""), re.I):
            cpu_pct = we.pct_db_time
            cpu_time_s = we.total_wait_time_sec
            break

    if cpu_pct is None:
        dbcpu = report.time_model.get("db_cpu")
        if dbcpu:
            cpu_pct = dbcpu.get("pct_db_time")
            cpu_time_s = dbcpu.get("time_s")

    if cpu_pct is None:
        return

    if cpu_pct >= rules.DB_CPU_PCT_CRITICAL:
        severity = "critical"
    elif cpu_pct >= rules.DB_CPU_PCT_WARNING:
        severity = "warning"
    else:
        return

    aas_note = ""
    cpus = report.info.cpus
    elapsed = report.info.elapsed_minutes
    db_time = report.info.db_time_minutes
    if elapsed and db_time and cpus:
        aas = db_time / elapsed
        if aas > cpus:
            aas_note = (
                f" The estimated average active sessions ({aas:.1f}) exceeds the number of "
                f"CPUs available ({cpus:.0f}), which is consistent with genuine CPU "
                f"saturation rather than just a CPU-heavy workload."
            )

    findings.append(Finding(
        severity=severity,
        category="CPU",
        title=f"Workload is CPU-bound ({cpu_pct:.1f}% of DB time)",
        plain_explanation=(
            "Most of the time the database spent working (as opposed to waiting on disk, "
            "locks, etc.) was spent actively using the CPU. This can simply mean the "
            "workload is compute-heavy, but combined with high host CPU utilization it can "
            "also mean the server doesn't have enough CPU capacity for the current load, or "
            "that SQL is doing unnecessary work (e.g. scanning far more rows than needed)."
            + aas_note
        ),
        technical_detail=f"DB CPU = {cpu_pct:.1f}% of DB time" + (f" ({cpu_time_s:.0f}s)" if cpu_time_s else ""),
        recommendations=[
            "Check host-level CPU utilization for the same window (Host CPU section) to see "
            "if the machine itself was saturated.",
            "Review 'SQL ordered by CPU Time' for statements consuming the most CPU and "
            "check their execution plans for inefficient operations (e.g. avoidable full "
            "scans, nested loop joins over large row sets).",
            "If the workload is genuinely CPU-heavy and appropriately tuned, consider "
            "whether more CPU capacity or read replicas/offloading is needed as load grows.",
        ],
        evidence={"cpu_pct_db_time": cpu_pct, "cpu_time_sec": cpu_time_s},
    ))


def _check_parse_rate(report: AWRReport, findings: list) -> None:
    hard_parse_key = next((k for k in report.load_profile if "hard_pars" in k), None)
    if not hard_parse_key:
        return
    value = report.load_profile[hard_parse_key].get("per_second")
    if value is None:
        return

    if value >= rules.HARD_PARSE_CRITICAL:
        severity = "critical"
    elif value >= rules.HARD_PARSE_WARNING:
        severity = "warning"
    else:
        return

    findings.append(Finding(
        severity=severity,
        category="Parsing",
        title=f"High hard parse rate ({value:.2f} per second)",
        plain_explanation=(
            "Hard parsing (building a brand-new execution plan for a SQL statement) is one "
            "of the most expensive things a database does. A sustained high rate almost "
            "always means the application is not reusing SQL statements — usually because "
            "it's embedding literal values directly in SQL text instead of using bind "
            "variables — forcing Oracle to treat each slightly-different statement as brand "
            "new."
        ),
        technical_detail=f"Hard parses: {value:.2f} per second.",
        recommendations=[
            "Have the application use bind variables so identical statement shapes can "
            "reuse the same parsed cursor.",
            "As a stopgap only, CURSOR_SHARING=FORCE can reduce hard parsing without "
            "application changes, but it can affect execution plan quality — treat it as "
            "temporary relief, not a fix.",
        ],
        evidence={"hard_parses_per_sec": value},
    ))


def _check_sql(report: AWRReport, findings: list) -> None:
    db_time_sec = (report.info.db_time_minutes or 0) * 60
    _check_sql_list(report.sql_by_elapsed, "elapsed time", db_time_sec, findings)


def _check_sql_list(sql_list, metric_name: str, db_time_sec: float, findings: list) -> None:
    for stat in sql_list[:5]:
        if stat.value is None:
            continue
        pct = stat.pct_total
        if pct is None and db_time_sec:
            pct = (stat.value / db_time_sec) * 100
        if pct is None:
            continue

        if pct >= rules.SQL_PCT_CRITICAL:
            severity = "critical"
        elif pct >= rules.SQL_PCT_WARNING:
            severity = "warning"
        else:
            continue

        exec_note = ""
        if stat.executions:
            per_exec = stat.per_exec if stat.per_exec is not None else (stat.value / stat.executions if stat.executions else None)
            exec_note = f" It ran {stat.executions:.0f} time(s)"
            if per_exec is not None:
                exec_note += f", averaging {per_exec:.3f}s per execution."
            else:
                exec_note += "."

        text_snippet = (stat.sql_text or "").strip()
        if len(text_snippet) > 140:
            text_snippet = text_snippet[:140] + "..."

        findings.append(Finding(
            severity=severity,
            category="SQL",
            title=f"High-impact SQL: {stat.sql_id} ({pct:.1f}% of DB time by {metric_name})",
            plain_explanation=(
                f"This single SQL statement accounts for a large share of all database "
                f"time on its own, based on {metric_name}.{exec_note} Statements like this "
                f"are usually the highest-leverage place to focus tuning effort, since "
                f"improving one query can measurably improve overall performance."
            ),
            technical_detail=(
                f"SQL_ID {stat.sql_id}: {metric_name} = {stat.value:.2f}, "
                f"{pct:.1f}% of total DB time" + (f", executions = {stat.executions:.0f}" if stat.executions else "") +
                (f", text: {text_snippet}" if text_snippet else "")
            ),
            recommendations=[
                f"Pull the execution plan for SQL_ID {stat.sql_id} (e.g. via "
                f"DBMS_XPLAN.DISPLAY_CURSOR or SQL Tuning Advisor) and look for full table "
                f"scans, poor join order, or missing indexes.",
                "If it runs very frequently with a small per-execution cost, consider "
                "whether it can be called less often (e.g. application-level caching) rather "
                "than only tuning the SQL itself.",
                "If it runs rarely but is very expensive per execution, focus on the "
                "execution plan and indexing rather than call frequency.",
            ],
            evidence={
                "sql_id": stat.sql_id, "value": stat.value, "pct_total": pct,
                "executions": stat.executions, "metric": metric_name,
            },
        ))


def _check_tablespace_io(report: AWRReport, findings: list) -> None:
    for ts in report.tablespace_io:
        ms = ts.avg_read_time_ms
        if ms is None:
            continue
        if ms >= rules.TS_READ_MS_CRITICAL:
            severity = "critical"
        elif ms >= rules.TS_READ_MS_WARNING:
            severity = "warning"
        else:
            continue

        findings.append(Finding(
            severity=severity,
            category="I/O",
            title=f"Slow storage reads on tablespace '{ts.tablespace}' ({ms:.1f} ms/read)",
            plain_explanation=(
                "This tablespace's data files are taking noticeably longer than expected to "
                "respond to read requests. Anything using this tablespace will feel slower "
                "as a direct result, regardless of how well the SQL itself is tuned."
            ),
            technical_detail=(
                f"Tablespace '{ts.tablespace}': avg read time {ms:.2f} ms"
                + (f", {ts.reads:.0f} reads" if ts.reads else "")
                + (f", {ts.avg_reads_per_sec:.1f} reads/s" if ts.avg_reads_per_sec else "")
            ),
            recommendations=[
                "Raise this with the storage/infrastructure team — this is a storage "
                "performance symptom, not something SQL tuning alone can fix.",
                "Check whether this tablespace's files sit on shared/contended storage, and "
                "whether other tablespaces on the same storage show the same symptom (if only "
                "one does, the issue may be specific to that storage path or device).",
            ],
            evidence={"tablespace": ts.tablespace, "avg_read_time_ms": ms, "reads": ts.reads},
        ))
