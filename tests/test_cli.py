from pathlib import Path

from awr_analyzer.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def test_cli_analyze_writes_html(tmp_path, capsys):
    out_file = tmp_path / "out.html"
    rc = main(["analyze", str(FIXTURES / "sample_problem.html"), "-o", str(out_file)])
    assert rc == 0
    assert out_file.exists()
    content = out_file.read_text(encoding="utf-8")
    assert "AWR Analysis Report" in content
    captured = capsys.readouterr()
    assert "Health score" in captured.out


def test_cli_analyze_text_format(tmp_path):
    out_file = tmp_path / "out.txt"
    rc = main(["analyze", str(FIXTURES / "sample_healthy.html"), "-o", str(out_file), "--format", "text"])
    assert rc == 0
    content = out_file.read_text(encoding="utf-8")
    assert "AWR ANALYSIS REPORT" in content


def test_cli_analyze_json_format(tmp_path):
    import json
    out_file = tmp_path / "out.json"
    rc = main(["analyze", str(FIXTURES / "sample_healthy.html"), "-o", str(out_file), "--format", "json"])
    assert rc == 0
    payload = json.loads(out_file.read_text(encoding="utf-8"))
    assert "health_score" in payload
    assert "findings" in payload


def test_cli_trend_writes_html(tmp_path):
    out_file = tmp_path / "trend.html"
    files = [str(FIXTURES / f"sample_trend_{i}.html") for i in (1, 2, 3)]
    rc = main(["trend", *files, "-o", str(out_file)])
    assert rc == 0
    content = out_file.read_text(encoding="utf-8")
    assert "Trend Across 3 Reports" in content


def test_cli_trend_requires_two_reports(capsys):
    import pytest as _pytest
    with _pytest.raises(SystemExit):
        main(["trend", str(FIXTURES / "sample_healthy.html")])


def test_cli_missing_file_exits_cleanly(capsys):
    import pytest as _pytest
    with _pytest.raises(SystemExit):
        main(["analyze", "/nonexistent/path/report.html"])
