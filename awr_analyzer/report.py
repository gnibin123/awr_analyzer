"""Renders an :class:`~awr_analyzer.models.AnalysisResult` (and, optionally,
a :class:`~awr_analyzer.forecast.TrendAnalysis`) into human-friendly output:
a self-contained HTML report, or a plain-text/Markdown report for terminals
and CI logs.
"""

from __future__ import annotations

import html as _html
from datetime import datetime

from . import rules
from .models import AnalysisResult

SEVERITY_META = {
    "critical": {"label": "Critical", "color": "#b3261e", "bg": "#fdecea"},
    "warning": {"label": "Warning", "color": "#8a5300", "bg": "#fff4e0"},
    "info": {"label": "Info", "color": "#0b5394", "bg": "#e8f0fe"},
    "good": {"label": "Good", "color": "#1e7d32", "bg": "#e6f4ea"},
}

DIRECTION_META = {
    "improving": ("improving", "#1e7d32"),
    "worsening": ("worsening", "#b3261e"),
    "increasing": ("increasing", "#8a5300"),
    "decreasing": ("decreasing", "#0b5394"),
    "stable": ("stable", "#5f6368"),
}


def _e(value) -> str:
    if value is None:
        return ""
    return _html.escape(str(value))


def _fmt(value, digits=2):
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:,.{digits}f}"
    return str(value)


def render_html(result: AnalysisResult, trend=None) -> str:
    report = result.report
    info = report.info
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    score_color = "#1e7d32" if result.health_score >= 80 else ("#8a5300" if result.health_score >= 50 else "#b3261e")

    header_rows = "".join(f"""
        <tr><th>{_e(label)}</th><td>{_e(value) if value is not None else '&mdash;'}</td></tr>
    """ for label, value in [
        ("Database", info.db_name),
        ("Instance", info.instance_name),
        ("Host", info.host_name),
        ("Platform", info.platform),
        ("Release", info.release),
        ("CPUs / Cores", f"{_fmt(info.cpus, 0)} / {_fmt(info.cores, 0)}" if info.cpus or info.cores else None),
        ("Memory (GB)", _fmt(info.memory_gb, 1) if info.memory_gb else None),
        ("Snapshot window", f"{_e(info.begin_snap_time)} &rarr; {_e(info.end_snap_time)}" if info.begin_snap_time else None),
        ("Elapsed / DB Time (min)", f"{_fmt(info.elapsed_minutes, 1)} / {_fmt(info.db_time_minutes, 1)}" if info.elapsed_minutes else None),
    ] if value)

    counts = result.counts()
    count_chips = "".join(
        f'<span class="chip chip-{sev}">{counts.get(sev, 0)} {SEVERITY_META[sev]["label"]}</span>'
        for sev in ("critical", "warning", "info", "good") if counts.get(sev)
    )

    findings_html = "".join(_render_finding(f) for f in result.findings)

    sql_html = _render_sql_insights(result.sql_insights)

    trend_html = _render_trend(trend) if trend is not None else ""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AWR Analysis Report{f' - {_e(info.db_name)}' if info.db_name else ''}</title>
<style>
  :root {{ color-scheme: light; }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    margin: 0; padding: 0 0 4rem 0; background: #f6f7f9; color: #1a1a1a; line-height: 1.5;
  }}
  .wrap {{ max-width: 960px; margin: 0 auto; padding: 0 1.25rem; }}
  header.page {{ background: #14213d; color: #fff; padding: 2rem 0; margin-bottom: 1.5rem; }}
  header.page h1 {{ margin: 0 0 0.25rem 0; font-size: 1.6rem; }}
  header.page p {{ margin: 0; opacity: 0.85; font-size: 0.9rem; }}
  .card {{ background: #fff; border: 1px solid #e2e5ea; border-radius: 10px; padding: 1.25rem 1.5rem; margin-bottom: 1.25rem; }}
  table.info th {{ text-align: left; color: #555; font-weight: 600; padding: 0.2rem 0.75rem 0.2rem 0; white-space: nowrap; vertical-align: top; }}
  table.info td {{ padding: 0.2rem 0; }}
  .score {{ font-size: 2.75rem; font-weight: 700; }}
  .score-wrap {{ display: flex; align-items: center; gap: 1.5rem; flex-wrap: wrap; }}
  .summary-text {{ font-size: 1.02rem; max-width: 620px; }}
  .chip {{ display: inline-block; padding: 0.2rem 0.65rem; border-radius: 999px; font-size: 0.8rem; font-weight: 600; margin-right: 0.4rem; }}
  .chip-critical {{ background: #fdecea; color: #b3261e; }}
  .chip-warning {{ background: #fff4e0; color: #8a5300; }}
  .chip-info {{ background: #e8f0fe; color: #0b5394; }}
  .chip-good {{ background: #e6f4ea; color: #1e7d32; }}
  h2.section-title {{ font-size: 1.15rem; margin: 2rem 0 0.75rem 0; }}
  .finding {{ border-left: 5px solid #ccc; border-radius: 6px; padding: 1rem 1.25rem; margin-bottom: 1rem; }}
  .finding h3 {{ margin: 0 0 0.4rem 0; font-size: 1.02rem; }}
  .badge {{ display: inline-block; font-size: 0.72rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.03em; padding: 0.15rem 0.5rem; border-radius: 4px; margin-right: 0.5rem; }}
  .cat-badge {{ display: inline-block; font-size: 0.72rem; font-weight: 600; padding: 0.15rem 0.5rem; border-radius: 4px; margin-right: 0.5rem; background: #eef0f3; color: #444; }}
  .plain {{ margin: 0.5rem 0; }}
  details {{ margin-top: 0.5rem; }}
  summary {{ cursor: pointer; font-size: 0.85rem; color: #444; font-weight: 600; }}
  .tech {{ background: #f5f5f5; border-radius: 6px; padding: 0.6rem 0.8rem; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.82rem; margin-top: 0.4rem; white-space: pre-wrap; }}
  ul.recs {{ margin: 0.5rem 0 0 0; padding-left: 1.2rem; }}
  ul.recs li {{ margin-bottom: 0.3rem; }}
  table.trend {{ width: 100%; border-collapse: collapse; font-size: 0.88rem; }}
  table.trend th, table.trend td {{ text-align: left; padding: 0.45rem 0.6rem; border-bottom: 1px solid #eee; }}
  table.sql-table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
  table.sql-table th {{ text-align: left; padding: 0.5rem 0.6rem; border-bottom: 2px solid #e2e5ea; white-space: nowrap; }}
  table.sql-table td {{ text-align: left; padding: 0.4rem 0.6rem; vertical-align: top; }}
  table.sql-table tr.sql-row td {{ border-top: 1px solid #eee; }}
  table.sql-table tr.sql-text-row td {{ padding: 0 0.6rem 0.6rem 0.6rem; color: #777; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.78rem; }}
  .tag-chip {{ display: inline-block; padding: 0.1rem 0.5rem; border-radius: 999px; font-size: 0.72rem; font-weight: 600; margin: 0.1rem 0.25rem 0.1rem 0; white-space: nowrap; }}
  code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.85em; }}
  .footer-note {{ color: #777; font-size: 0.8rem; margin-top: 2rem; }}
</style>
</head>
<body>
<header class="page">
  <div class="wrap">
    <h1>AWR Analysis Report</h1>
    <p>Generated {_e(generated_at)}{f' &middot; source: {_e(report.source_path)}' if report.source_path else ''}</p>
  </div>
</header>
<div class="wrap">

  <div class="card">
    <div class="score-wrap">
      <div class="score" style="color:{score_color}">{result.health_score}<span style="font-size:1rem;color:#777;">/100</span></div>
      <div class="summary-text">
        <div style="margin-bottom:0.5rem;">{count_chips}</div>
        <div>{_e(result.summary)}</div>
      </div>
    </div>
  </div>

  <div class="card">
    <table class="info">{header_rows}</table>
  </div>

  <h2 class="section-title">Findings ({len(result.findings)})</h2>
  {findings_html}

  {sql_html}

  {trend_html}

  <p class="footer-note">
    Thresholds used in this report are common DBA rules of thumb, not absolute
    physical limits — treat findings as a prioritized starting point for
    investigation, and always factor in what the report doesn't show you:
    application context, business impact, and how users actually experienced
    this time window.
  </p>
</div>
</body>
</html>
"""


def _render_finding(f) -> str:
    meta = SEVERITY_META.get(f.severity, SEVERITY_META["info"])
    recs_html = "".join(f"<li>{_e(r)}</li>" for r in f.recommendations)
    recs_block = f'<ul class="recs">{recs_html}</ul>' if f.recommendations else ""
    return f"""
    <div class="finding" style="border-left-color:{meta['color']};">
      <h3>
        <span class="badge" style="background:{meta['bg']};color:{meta['color']};">{meta['label']}</span>
        <span class="cat-badge">{_e(f.category)}</span>
        {_e(f.title)}
      </h3>
      <p class="plain">{_e(f.plain_explanation)}</p>
      {recs_block}
      <details>
        <summary>Technical detail</summary>
        <div class="tech">{_e(f.technical_detail)}</div>
      </details>
    </div>
    """


def _render_sql_insights(sql_analysis) -> str:
    if not sql_analysis or not sql_analysis.insights:
        return ""

    rank_key = lambda p: (p.severity_rank(), -(p.elapsed_s or 0))
    ranked = sorted(sql_analysis.insights, key=rank_key)
    shown = [p for p in ranked if p.tags][:15]
    if not shown:
        shown = ranked[:5]

    rows = []
    for p in shown:
        meta = SEVERITY_META.get(p.severity, SEVERITY_META["info"])
        tag_chips = "".join(
            f'<span class="tag-chip" style="background:{meta["bg"]};color:{meta["color"]};">'
            f'{_e(rules.SQL_TAG_INFO.get(t, {}).get("label", t))}</span>'
            for t in p.tags
        )
        text_full = (p.sql_text or "").strip()
        text_short = text_full[:90] + ("…" if len(text_full) > 90 else "")
        cpu_io = "&mdash;"
        if p.pct_cpu is not None or p.pct_io is not None:
            cpu_io = f"{_fmt(p.pct_cpu, 0)}% / {_fmt(p.pct_io, 0)}%"

        rows.append(f"""
        <tr class="sql-row">
          <td><code>{_e(p.sql_id)}</code></td>
          <td>{_e(p.module) if p.module else '&mdash;'}</td>
          <td>{_fmt(p.pct_elapsed, 1)}%</td>
          <td>{_fmt(p.executions, 0)}</td>
          <td>{_fmt(p.per_exec_s, 3)}</td>
          <td>{cpu_io}</td>
          <td>{_fmt(p.gets_per_exec, 0)}</td>
          <td>{tag_chips or '&mdash;'}</td>
        </tr>
        <tr class="sql-text-row"><td colspan="8">{_e(text_short) if text_short else '&mdash;'}</td></tr>
        """)

    bind_block = ""
    if sql_analysis.bind_variable_suspects:
        items = "".join(
            f"<li>{len(g.sql_ids)} SQL_IDs (module: {_e(g.module) if g.module else 'n/a'}) share what looks like "
            f"the same statement once literal values are stripped out &mdash; likely missing bind variables.</li>"
            for g in sql_analysis.bind_variable_suspects[:5]
        )
        bind_block = (
            f'<div class="card"><h3 style="margin-top:0;">Possible missing bind variables</h3>'
            f'<ul class="recs">{items}</ul></div>'
        )

    return f"""
    <h2 class="section-title">Problematic Queries ({len(shown)} of {len(sql_analysis.insights)} profiled)</h2>
    <p style="font-size:0.85rem;color:#666;">
      Built by cross-referencing the "SQL ordered by ..." sections (Elapsed Time, CPU, Gets, Reads,
      Executions). A statement missing a column below simply wasn't in that section's top list, not that
      the value is zero.
    </p>
    <div class="card">
      <table class="sql-table">
        <tr>
          <th>SQL ID</th><th>Module</th><th>% DB Time</th><th>Execs</th><th>Per-Exec (s)</th>
          <th>%CPU / %IO</th><th>Gets/Exec</th><th>Flags</th>
        </tr>
        {''.join(rows)}
      </table>
    </div>
    {bind_block}
    """


def _render_trend(trend) -> str:
    if not trend or not trend.results:
        return ""
    rows = []
    for r in trend.results:
        label, color = DIRECTION_META.get(r.direction, ("stable", "#5f6368"))
        pct = f"{r.pct_change:+.1f}%" if r.pct_change is not None else "n/a"
        rows.append(f"""
        <tr>
          <td>{_e(r.label)}</td>
          <td>{_fmt(r.first_value)} &rarr; {_fmt(r.last_value)} {_e(r.unit)}</td>
          <td>{pct}</td>
          <td style="color:{color};font-weight:600;">{label}</td>
        </tr>
        """)
    forecast_items = "".join(
        f"<li><strong>{_e(r.label)}:</strong> {_e(r.forecast_note)}</li>"
        for r in trend.results if r.forecast_note
    )
    forecast_block = (
        f'<div class="card"><h3 style="margin-top:0;">Early-warning forecasts</h3><ul class="recs">{forecast_items}</ul></div>'
        if forecast_items else ""
    )
    snapshot_list = ", ".join(_e(l) for l in trend.labels)
    return f"""
    <h2 class="section-title">Trend Across {len(trend.labels)} Reports</h2>
    <p style="font-size:0.85rem;color:#666;">Snapshots analyzed (oldest &rarr; newest): {snapshot_list}</p>
    <div class="card">
      <table class="trend">
        <tr><th>Metric</th><th>First &rarr; Last</th><th>Change</th><th>Direction</th></tr>
        {''.join(rows)}
      </table>
    </div>
    {forecast_block}
    """


def render_text(result: AnalysisResult, trend=None) -> str:
    report = result.report
    info = report.info
    lines = []
    lines.append("=" * 72)
    lines.append("AWR ANALYSIS REPORT")
    lines.append("=" * 72)
    if info.db_name or info.instance_name:
        lines.append(f"Database: {info.db_name or 'n/a'}   Instance: {info.instance_name or 'n/a'}")
    if info.host_name:
        lines.append(f"Host: {info.host_name}   Platform: {info.platform or 'n/a'}")
    if info.begin_snap_time:
        lines.append(f"Snapshot window: {info.begin_snap_time} -> {info.end_snap_time}")
    if info.elapsed_minutes:
        lines.append(f"Elapsed: {info.elapsed_minutes:.1f} min   DB Time: {info.db_time_minutes or 0:.1f} min")
    lines.append("")
    lines.append(f"Health score: {result.health_score}/100")
    lines.append(result.summary)
    lines.append("")

    for f in result.findings:
        lines.append("-" * 72)
        lines.append(f"[{f.severity.upper()}] [{f.category}] {f.title}")
        lines.append("")
        lines.append(_wrap(f.plain_explanation))
        if f.recommendations:
            lines.append("")
            lines.append("Recommended actions:")
            for r in f.recommendations:
                lines.append(f"  - {_wrap(r, indent=4)}")
        lines.append("")
        lines.append(f"  Technical detail: {f.technical_detail}")
        lines.append("")

    sql_analysis = result.sql_insights
    if sql_analysis and sql_analysis.insights:
        rank_key = lambda p: (p.severity_rank(), -(p.elapsed_s or 0))
        ranked = sorted(sql_analysis.insights, key=rank_key)
        shown = [p for p in ranked if p.tags][:15] or ranked[:5]

        lines.append("=" * 72)
        lines.append(f"PROBLEMATIC QUERIES ({len(shown)} of {len(sql_analysis.insights)} profiled)")
        lines.append("=" * 72)
        for p in shown:
            tag_labels = ", ".join(rules.SQL_TAG_INFO.get(t, {}).get("label", t) for t in p.tags) or "—"
            cpu_io = ""
            if p.pct_cpu is not None or p.pct_io is not None:
                cpu_io = f", %CPU={p.pct_cpu if p.pct_cpu is not None else 'n/a'}, %IO={p.pct_io if p.pct_io is not None else 'n/a'}"
            lines.append(f"  {p.sql_id} [{tag_labels}]")
            lines.append(f"    %DBtime={_fmt(p.pct_elapsed, 1)}, executions={_fmt(p.executions, 0)}, "
                         f"per_exec_s={_fmt(p.per_exec_s, 3)}, gets/exec={_fmt(p.gets_per_exec, 0)}{cpu_io}")
            if p.sql_text:
                lines.append(f"    text: {p.sql_text.strip()[:120]}")
            lines.append("")

        if sql_analysis.bind_variable_suspects:
            lines.append("Possible missing bind variables:")
            for g in sql_analysis.bind_variable_suspects[:5]:
                lines.append(f"  - {len(g.sql_ids)} SQL_IDs (module: {g.module or 'n/a'}) share near-identical text")
            lines.append("")

    if trend and trend.results:
        lines.append("=" * 72)
        lines.append(f"TREND ACROSS {len(trend.labels)} REPORTS")
        lines.append("=" * 72)
        lines.append("Snapshots: " + ", ".join(trend.labels))
        lines.append("")
        for r in trend.results:
            pct = f"{r.pct_change:+.1f}%" if r.pct_change is not None else "n/a"
            lines.append(f"  {r.label}: {r.first_value:.2f} -> {r.last_value:.2f} {r.unit} ({pct}, {r.direction})")
        forecasts = trend.emerging_risks()
        if forecasts:
            lines.append("")
            lines.append("Early-warning forecasts:")
            for r in forecasts:
                lines.append(f"  - {r.label}: {_wrap(r.forecast_note, indent=4)}")

    return "\n".join(lines)


def _wrap(text: str, width: int = 100, indent: int = 0) -> str:
    import textwrap
    return textwrap.fill(text, width=width, subsequent_indent=" " * indent)
