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
from . import sql_insights
from .models import AnalysisResult, AWRReport, Finding


def analyze(report: AWRReport) -> AnalysisResult:
    findings = []

    sql_analysis = sql_insights.build_sql_insights(report)

    _check_efficiency(report, findings)
    _check_wait_events(report, findings)
    _check_cpu_load(report, findings)
    _check_parse_rate(report, findings)
    _check_sql(sql_analysis, findings)
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
    return AnalysisResult(
        report=report, findings=findings, health_score=health_score, summary=summary,
        sql_insights=sql_analysis,
    )


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
    for we in report.top_wait_events:
        name = (we.event or "").strip()
        if not name:
            continue
        if re.search(r"cpu time|^db cpu$", name, re.I):
            continue  # handled separately by _check_cpu_load

        # Trust only the report's own "% DB time" figure. Oracle leaves this
        # blank for idle/background-style waits (job queue slaves, the
        # watchdog loop, AQ message waits, ...) precisely because their raw
        # wait time isn't comparable to DB time — computing our own ratio
        # from total_wait_time_sec / db_time_sec produces nonsensical values
        # (sometimes >100%) for exactly those events.
        pct = we.pct_db_time

        kb = rules.lookup_wait_event(name)

        is_idle = kb is not None and kb["category"] == "Idle/Network"

        severity = None
        triggered_by = None
        if pct is not None and not is_idle:
            if pct >= rules.WAIT_EVENT_PCT_CRITICAL:
                severity = "critical"
                triggered_by = "pct"
            elif pct >= rules.WAIT_EVENT_PCT_WARNING:
                severity = "warning"
                triggered_by = "pct"

        # Special-case: sequential read latency can be a problem even if it's
        # not the single biggest contributor to DB time.
        if severity is None and re.search(r"^db file sequential read", name, re.I) and we.avg_wait_ms:
            if we.avg_wait_ms >= rules.SEQ_READ_MS_CRITICAL:
                severity = "critical"
                triggered_by = "latency"
            elif we.avg_wait_ms >= rules.SEQ_READ_MS_WARNING:
                severity = "warning"
                triggered_by = "latency"

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

        if triggered_by == "latency":
            title = f"Elevated average latency on '{name}' ({we.avg_wait_ms:.2f} ms/wait)"
        else:
            title = f"High wait time on '{name}' ({pct_text})"

        findings.append(Finding(
            severity=severity,
            category=category,
            title=title,
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


def _check_sql(sql_analysis, findings: list) -> None:
    problematic = [p for p in sql_analysis.insights if p.severity in ("critical", "warning")]
    problematic.sort(key=lambda p: (p.severity_rank(), -(p.elapsed_s or 0)))

    for p in problematic[:8]:
        tag_labels = ", ".join(rules.SQL_TAG_INFO[t]["label"] for t in p.tags)

        exec_note = ""
        if p.executions:
            exec_note = f" It ran {p.executions:.0f} time(s)"
            exec_note += f", averaging {p.per_exec_s:.3f}s per execution." if p.per_exec_s is not None else "."

        text_snippet = (p.sql_text or "").strip()
        if len(text_snippet) > 140:
            text_snippet = text_snippet[:140] + "..."

        plain = " ".join(p.notes[:2]) + exec_note

        detail_parts = [f"SQL_ID {p.sql_id}"]
        if p.pct_elapsed is not None:
            detail_parts.append(f"{p.pct_elapsed:.1f}% of total DB time")
        if p.executions:
            detail_parts.append(f"{p.executions:.0f} executions")
        if p.gets_per_exec:
            detail_parts.append(f"{p.gets_per_exec:,.0f} buffer gets/exec")
        if p.reads_per_exec:
            detail_parts.append(f"{p.reads_per_exec:,.0f} physical reads/exec")
        if p.pct_cpu is not None:
            detail_parts.append(f"%CPU={p.pct_cpu:.0f}")
        if p.pct_io is not None:
            detail_parts.append(f"%IO={p.pct_io:.0f}")
        if text_snippet:
            detail_parts.append(f"text: {text_snippet}")

        findings.append(Finding(
            severity=p.severity,
            category="SQL",
            title=f"Problematic SQL {p.sql_id}: {tag_labels}",
            plain_explanation=plain,
            technical_detail=", ".join(detail_parts),
            recommendations=p.recommendations,
            evidence={
                "sql_id": p.sql_id, "tags": p.tags, "pct_elapsed": p.pct_elapsed,
                "executions": p.executions, "gets_per_exec": p.gets_per_exec,
                "reads_per_exec": p.reads_per_exec, "pct_cpu": p.pct_cpu, "pct_io": p.pct_io,
            },
        ))

    if sql_analysis.bind_variable_suspects:
        groups = sql_analysis.bind_variable_suspects[:5]
        lines = []
        for g in groups:
            id_list = ", ".join(g.sql_ids[:5]) + ("..." if len(g.sql_ids) > 5 else "")
            lines.append(f"{len(g.sql_ids)} SQL_IDs ({id_list})")

        findings.append(Finding(
            severity="warning",
            category="Parsing",
            title=f"Likely missing bind variables: {len(groups)} group(s) of near-identical SQL",
            plain_explanation=(
                "Several distinct SQL_IDs share what looks like the same statement once "
                "literal values (numbers and quoted strings) are stripped out. This is the "
                "classic signature of an application embedding literal values directly in "
                "SQL text instead of using bind variables, which forces Oracle to hard-parse "
                "and separately cache a version of the statement for every distinct value."
            ),
            technical_detail=" | ".join(lines),
            recommendations=[
                "Have the application use bind variables for these statements so identical "
                "statement shapes share one parsed cursor instead of each literal value "
                "creating a new hard-parsed copy.",
                "Check the Soft Parse Ratio and hard-parse-rate findings elsewhere in this "
                "report — this pattern is usually the direct cause of both.",
            ],
            evidence={"groups": [
                {"signature": g.signature, "sql_ids": g.sql_ids, "module": g.module}
                for g in groups
            ]},
        ))


def _check_tablespace_io(report: AWRReport, findings: list) -> None:
    for ts in report.tablespace_io:
        ms = ts.avg_read_time_ms
        if ms is None:
            continue
        if not ts.reads or ts.reads < rules.TS_MIN_READS_FOR_LATENCY_CHECK:
            continue  # too few reads in the window for the average to be a reliable signal
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
