from pathlib import Path

from awr_analyzer.analyzer import analyze
from awr_analyzer.forecast import build_trend
from awr_analyzer.parser import parse_awr_file
from awr_analyzer.report import render_html, render_text

FIXTURES = Path(__file__).parent / "fixtures"


def test_render_html_contains_key_sections():
    report = parse_awr_file(str(FIXTURES / "sample_problem.html"))
    result = analyze(report)
    out = render_html(result)
    assert "<html" in out.lower()
    assert "PRODDB" in out
    assert "Buffer Cache Hit Ratio" in out
    assert str(result.health_score) in out


def test_render_html_escapes_sql_text():
    report = parse_awr_file(str(FIXTURES / "sample_problem.html"))
    result = analyze(report)
    out = render_html(result)
    # SQL text containing special characters should be HTML-escaped, not raw.
    assert "<script>" not in out


def test_render_text_contains_findings():
    report = parse_awr_file(str(FIXTURES / "sample_problem.html"))
    result = analyze(report)
    out = render_text(result)
    assert "AWR ANALYSIS REPORT" in out
    assert "CRITICAL" in out


def test_render_html_with_trend():
    reports = [parse_awr_file(str(FIXTURES / f"sample_trend_{i}.html")) for i in (1, 2, 3)]
    result = analyze(reports[-1])
    trend = build_trend(reports)
    out = render_html(result, trend=trend)
    assert "Trend Across 3 Reports" in out
    assert "Early-warning forecasts" in out


def test_render_text_with_trend():
    reports = [parse_awr_file(str(FIXTURES / f"sample_trend_{i}.html")) for i in (1, 2, 3)]
    result = analyze(reports[-1])
    trend = build_trend(reports)
    out = render_text(result, trend=trend)
    assert "TREND ACROSS 3 REPORTS" in out
