from pathlib import Path

from awr_analyzer.analyzer import analyze
from awr_analyzer.parser import parse_awr_file

FIXTURES = Path(__file__).parent / "fixtures"


def test_healthy_report_has_no_bad_findings():
    report = parse_awr_file(str(FIXTURES / "sample_healthy.html"))
    result = analyze(report)
    assert result.health_score == 100
    assert all(f.severity in ("info", "good") for f in result.findings)


def test_problem_report_flags_buffer_cache():
    report = parse_awr_file(str(FIXTURES / "sample_problem.html"))
    result = analyze(report)
    titles = [f.title for f in result.findings]
    assert any("Buffer Cache Hit Ratio" in t for t in titles)
    finding = next(f for f in result.findings if "Buffer Cache Hit Ratio" in f.title)
    assert finding.severity == "critical"
    assert finding.recommendations


def test_problem_report_flags_io_wait_and_sql():
    report = parse_awr_file(str(FIXTURES / "sample_problem.html"))
    result = analyze(report)
    categories = {f.category for f in result.findings}
    assert "I/O" in categories
    assert "SQL" in categories
    assert "Efficiency" in categories

    sql_findings = [f for f in result.findings if f.category == "SQL"]
    assert any("badsql000001" in f.title for f in sql_findings)


def test_problem_report_health_score_worse_than_healthy():
    healthy = analyze(parse_awr_file(str(FIXTURES / "sample_healthy.html")))
    problem = analyze(parse_awr_file(str(FIXTURES / "sample_problem.html")))
    assert problem.health_score < healthy.health_score


def test_findings_sorted_by_severity():
    report = parse_awr_file(str(FIXTURES / "sample_problem.html"))
    result = analyze(report)
    ranks = [f.severity_rank() for f in result.findings]
    assert ranks == sorted(ranks)


def test_tablespace_io_latency_flagged():
    report = parse_awr_file(str(FIXTURES / "sample_problem.html"))
    result = analyze(report)
    ts_findings = [f for f in result.findings if "tablespace" in f.title.lower()]
    assert any("USERS" in f.title for f in ts_findings)
