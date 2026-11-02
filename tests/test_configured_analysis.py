"""The analysis responds to every kind of customization."""

from pathlib import Path

from awr_analyzer.analyzer import analyze
from awr_analyzer.config import AnalyzerConfig
from awr_analyzer.forecast import build_trend
from awr_analyzer.parser import parse_awr_file
from awr_analyzer.report import render_html, render_text

FIXTURES = Path(__file__).parent / "fixtures"


def _problem():
    return parse_awr_file(str(FIXTURES / "sample_problem.html"))


def _ids(result):
    return {f.rule_id for f in result.findings}


def test_every_finding_has_an_id():
    result = analyze(_problem())
    assert all(f.rule_id for f in result.findings)
    assert {"efficiency.buffer_hit", "wait.db file sequential read", "tablespace.USERS",
            "sql.badsql000001", "sql.bind_variables", "parse.hard_parse_rate"} <= _ids(result)


def test_raising_a_threshold_removes_the_finding():
    cfg = AnalyzerConfig()
    cfg.set(("thresholds", "ts_read_ms_warning"), 20.0)
    assert "tablespace.TEMP" in _ids(analyze(_problem()))
    assert "tablespace.TEMP" not in _ids(analyze(_problem(), cfg))


def test_disabling_a_check():
    cfg = AnalyzerConfig()
    cfg.set(("checks", "efficiency"), False)
    result = analyze(_problem(), cfg)
    assert not any(f.category == "Efficiency" for f in result.findings)


def test_suppressed_findings_are_hidden_but_counted():
    cfg = AnalyzerConfig()
    cfg.set(("suppress",), ["tablespace.*", "efficiency.buffer_hit"])
    baseline = analyze(_problem())
    result = analyze(_problem(), cfg)
    assert not any(i.startswith("tablespace.") for i in _ids(result))
    assert {f.rule_id for f in result.suppressed} == {"tablespace.USERS", "tablespace.TEMP", "efficiency.buffer_hit"}
    assert result.health_score >= baseline.health_score
    assert "hidden by your suppress list" in render_text(result)


def test_custom_explanation_text_is_used():
    cfg = AnalyzerConfig()
    cfg.set(("efficiency", "buffer_hit", "explanation"), "Our cache is sized for 99%.")
    cfg.set(("efficiency", "buffer_hit", "recommendations"), ["Page the DBA on call."])
    f = next(f for f in analyze(_problem(), cfg).findings if f.rule_id == "efficiency.buffer_hit")
    assert f.plain_explanation == "Our cache is sized for 99%."
    assert f.recommendations == ["Page the DBA on call."]


def test_custom_wait_event_entry_overrides_and_idle_category_silences():
    cfg = AnalyzerConfig()
    cfg.set(("wait_events", "custom"), [
        {"pattern": "^log file sync", "category": "Idle/Network", "plain": "", "recommendations": []},
        {"pattern": "^db file sequential", "category": "Storage", "plain": "SAN latency; known issue.",
         "recommendations": ["See ticket STOR-12"]},
    ])
    result = analyze(_problem(), cfg)
    assert "wait.log file sync" not in _ids(result)
    seq = next(f for f in result.findings if f.rule_id == "wait.db file sequential read")
    assert seq.category == "Storage"
    assert seq.plain_explanation == "SAN latency; known issue."


def test_sql_tag_renamed_and_disabled():
    cfg = AnalyzerConfig()
    cfg.set(("sql_tags", "missing_index_suspect", "label"), "Needs an index")
    cfg.set(("sql_tags", "io_bound", "enabled"), False)
    result = analyze(_problem(), cfg)
    bad = next(p for p in result.sql_insights.insights if p.sql_id == "badsql000001")
    assert "Needs an index" in bad.tag_labels
    assert "io_bound" not in bad.tags
    assert "Needs an index" in render_html(result)


def test_ignored_sql_and_watchlist():
    cfg = AnalyzerConfig()
    cfg.set(("sql_ignore",), ["slowbatch0002"])
    cfg.set(("sql_watchlist", "badsql000001"), "Search page query")
    cfg.set(("sql_watchlist", "notinreport01"), "Nightly job")
    result = analyze(_problem(), cfg)
    assert all(p.sql_id != "slowbatch0002" for p in result.sql_insights.insights)
    watched = {w.sql_id: w for w in result.watched_sql}
    assert watched["badsql000001"].insight is not None
    assert watched["notinreport01"].insight is None
    html = render_html(result)
    assert "Watched Queries" in html and "Nightly job" in html


def test_custom_rules_run_in_the_analysis():
    cfg = AnalyzerConfig()
    cfg.set(("custom_rules",), [{"name": "redo", "metric": "load_profile.redo_size_bytes.per_second",
                                 "op": ">", "warning": 100000, "title": "Redo at {value:,.0f} B/s"}])
    result = analyze(_problem(), cfg)
    assert "Redo at 450,000 B/s" in [f.title for f in result.findings]
    cfg.set(("checks", "custom_rules"), False)
    assert "custom.redo" not in _ids(analyze(_problem(), cfg))


def test_score_weights():
    cfg = AnalyzerConfig()
    cfg.set(("score_weights",), {"critical": 1.0, "warning": 1.0, "info": 0.0})
    result = analyze(_problem(), cfg)
    counts = result.counts()
    assert result.health_score == 100 - counts["critical"] - counts["warning"]


def test_data_warehouse_preset_relaxes_sql_flags():
    oltp = analyze(_problem())
    dw = analyze(_problem(), AnalyzerConfig.from_preset("data_warehouse"))
    tags = lambda r: next(p for p in r.sql_insights.insights if p.sql_id == "badsql000001").tags  # noqa: E731
    assert "missing_index_suspect" in tags(oltp)
    assert "missing_index_suspect" not in tags(dw)


def test_trend_uses_configured_thresholds():
    reports = [parse_awr_file(str(FIXTURES / f"sample_trend_{i}.html")) for i in (1, 2, 3)]
    cfg = AnalyzerConfig()
    cfg.set(("efficiency", "buffer_hit", "critical"), 90.0)
    result = next(r for r in build_trend(reports, cfg).results if r.key == "buffer_hit")
    assert "already reached" in result.forecast_note


def test_report_shows_settings_and_finding_ids():
    cfg = AnalyzerConfig.from_preset("strict")
    result = analyze(_problem(), cfg)
    assert "preset 'strict'" in render_text(result)
    assert "Finding ID: efficiency.buffer_hit" in render_html(result)
