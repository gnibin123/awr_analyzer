from pathlib import Path

from awr_analyzer.parser import parse_awr_file

FIXTURES = Path(__file__).parent / "fixtures"


def test_parses_header_info():
    report = parse_awr_file(str(FIXTURES / "sample_healthy.html"))
    info = report.info
    assert info.db_name == "ORCLDB"
    assert info.instance_name == "orcl1"
    assert info.host_name == "dbhost01"
    assert info.platform == "Linux x86 64-bit"
    assert info.cpus == 8.0
    assert info.cores == 4.0
    assert info.memory_gb == 64.0
    assert info.elapsed_minutes == 60.0
    assert info.db_time_minutes == 25.0
    assert info.begin_snap_time == "13-Sep-24 14:00:00"
    assert info.end_snap_time == "13-Sep-24 15:00:00"


def test_parses_load_profile():
    report = parse_awr_file(str(FIXTURES / "sample_healthy.html"))
    assert "db_times" in report.load_profile
    assert report.load_profile["db_times"]["per_second"] == 12.5
    assert "redo_size_bytes" in report.load_profile
    assert report.load_profile["redo_size_bytes"]["per_second"] == 450000.0


def test_parses_instance_efficiency():
    report = parse_awr_file(str(FIXTURES / "sample_healthy.html"))
    assert report.instance_efficiency["buffer_hit"] == 99.6
    assert report.instance_efficiency["library_hit"] == 99.4
    assert report.instance_efficiency["soft_parse"] == 99.3


def test_parses_wait_events():
    report = parse_awr_file(str(FIXTURES / "sample_problem.html"))
    names = [w.event for w in report.top_wait_events]
    assert "db file sequential read" in names
    seq = next(w for w in report.top_wait_events if w.event == "db file sequential read")
    assert seq.pct_db_time == 47.4
    assert seq.avg_wait_ms == 30.0
    assert seq.waits == 900000


def test_parses_sql_stats():
    report = parse_awr_file(str(FIXTURES / "sample_problem.html"))
    assert len(report.sql_by_elapsed) == 5
    top = report.sql_by_elapsed[0]
    assert top.sql_id == "badsql000001"
    assert top.value == 22000.0
    assert top.executions == 800000
    assert top.pct_total == 38.6
    assert top.pct_cpu == 15.0
    assert top.pct_io == 80.0


def test_parses_tablespace_io():
    report = parse_awr_file(str(FIXTURES / "sample_problem.html"))
    assert len(report.tablespace_io) == 2
    users = next(t for t in report.tablespace_io if t.tablespace == "USERS")
    assert users.avg_read_time_ms == 35.0


def test_handles_missing_sections_gracefully():
    # A minimal, mostly-empty HTML file should not raise, just parse to (mostly) nothing.
    from awr_analyzer.parser import parse_awr_html
    report = parse_awr_html("<html><body><p>not an AWR report</p></body></html>")
    assert report.load_profile == {}
    assert report.top_wait_events == []
