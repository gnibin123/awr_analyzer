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


def test_cli_analyze_with_config_and_preset(tmp_path, capsys):
    import json
    cfg_path = tmp_path / "team.json"
    cfg_path.write_text(json.dumps({"suppress": ["tablespace.*"]}))
    out_file = tmp_path / "out.txt"
    rc = main(["analyze", str(FIXTURES / "sample_problem.html"), "--config", str(cfg_path),
               "--preset", "strict", "--format", "text", "-o", str(out_file)])
    assert rc == 0
    content = out_file.read_text(encoding="utf-8")
    assert "preset 'strict'" in content
    assert "hidden by your suppress list: tablespace.TEMP, tablespace.USERS" in content
    captured = capsys.readouterr()
    assert "Using settings" in captured.err
    assert "2 hidden by settings" in captured.out


def test_cli_picks_up_default_config_file(tmp_path, monkeypatch, capsys):
    import json
    cfg_path = tmp_path / "default.json"
    cfg_path.write_text(json.dumps({"checks": {"efficiency": False}}))
    monkeypatch.setenv("AWR_ANALYZER_CONFIG", str(cfg_path))
    out_file = tmp_path / "out.json"
    main(["analyze", str(FIXTURES / "sample_problem.html"), "--format", "json", "-o", str(out_file)])
    findings = json.loads(out_file.read_text())["findings"]
    assert not any(f["category"] == "Efficiency" for f in findings)
    main(["analyze", str(FIXTURES / "sample_problem.html"), "--no-config", "--format", "json", "-o", str(out_file)])
    findings = json.loads(out_file.read_text())["findings"]
    assert any(f["category"] == "Efficiency" for f in findings)


def test_cli_invalid_config_is_rejected(tmp_path, capsys):
    import json
    import pytest as _pytest
    cfg_path = tmp_path / "bad.json"
    cfg_path.write_text(json.dumps({"thresholds": {"sql_pct_warning": "high"}}))
    with _pytest.raises(SystemExit) as exc:
        main(["analyze", str(FIXTURES / "sample_problem.html"), "--config", str(cfg_path)])
    assert exc.value.code == 2
    assert "must be a number" in capsys.readouterr().err


def test_cli_config_init_show_validate(tmp_path, capsys):
    import pytest as _pytest
    cfg_path = tmp_path / "cfg.json"
    assert main(["config", "init", str(cfg_path), "--preset", "data_warehouse"]) == 0
    assert '"preset": "data_warehouse"' in cfg_path.read_text()
    with _pytest.raises(SystemExit):
        main(["config", "init", str(cfg_path)])  # refuses to overwrite
    assert main(["config", "show", "--config", str(cfg_path)]) == 0
    assert "preset: data_warehouse" in capsys.readouterr().out
    assert main(["config", "validate", "--config", str(cfg_path)]) == 0
    assert "OK:" in capsys.readouterr().out

    cfg_path.write_text('{"custom_rules": [{"name": "x"}]}')
    with _pytest.raises(SystemExit) as exc:
        main(["config", "validate", "--config", str(cfg_path)])
    assert exc.value.code == 1


def test_cli_metrics_lists_metric_names(capsys):
    assert main(["metrics", str(FIXTURES / "sample_problem.html"), "--filter", "tablespace."]) == 0
    out = capsys.readouterr().out
    assert "tablespace.USERS.avg_read_time_ms" in out
    assert "wait." not in out
