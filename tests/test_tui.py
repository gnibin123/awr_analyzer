"""Scripted sessions through the interactive text interface."""

import io
import json
from pathlib import Path

from awr_analyzer.config import AnalyzerConfig
from awr_analyzer.tui import TUI

FIXTURES = Path(__file__).parent / "fixtures"
PROBLEM = str(FIXTURES / "sample_problem.html")


def run(inputs, cfg=None, config_path=None, report=None):
    """Run the TUI with scripted keystrokes; running out of input ends the
    session the way Ctrl+D would."""
    feed = iter(inputs)

    def fake_input(prompt=""):
        try:
            return next(feed)
        except StopIteration:
            raise EOFError

    out = io.StringIO()
    tui = TUI(config=cfg or AnalyzerConfig(), config_path=config_path, input_fn=fake_input,
              out=out, color=False)
    assert tui.run(report_path=report) == 0
    return tui, out.getvalue()


def test_quits_cleanly_on_end_of_input():
    tui, out = run([])
    assert "Main menu" in out


def test_analyze_and_open_a_finding():
    tui, out = run(["1", PROBLEM, "1", "b", "b", "q"])
    assert "Analysis of sample_problem.html" in out
    assert "Buffer Cache Hit Ratio is low" in out
    assert "What it means" in out and "What to do" in out
    assert "ID: efficiency.buffer_hit" in out


def test_hide_a_finding_and_save(tmp_path):
    path = tmp_path / "cfg.json"
    tui, out = run(["1", "h", "1", "b", "s", "", "q"], config_path=str(path), report=PROBLEM)
    saved = json.loads(path.read_text())
    assert saved["suppress"] == ["efficiency.buffer_hit"]
    assert "1 hidden by your settings" in out
    assert not tui.cfg.dirty


def test_customize_check_from_a_finding_and_auto_rerun():
    # Finding 7 is the slow USERS tablespace; raise its warning/critical thresholds.
    inputs = ["7", "c", "1", "40", "2", "60", "b", "b", "q", "n"]
    tui, out = run(inputs, report=PROBLEM)
    assert tui.cfg.threshold("ts_read_ms_warning") == 40.0
    assert tui.cfg.threshold("ts_read_ms_critical") == 60.0
    assert "Re-ran the analysis with your updated settings" in out
    assert "tablespace.USERS" not in {f.rule_id for f in tui.result.findings}


def test_threshold_menu_change_and_reset():
    inputs = ["4", "1", "1", "7.5", "b", "b"]
    tui, _ = run(inputs)
    assert tui.cfg.threshold("wait_event_pct_warning") == 7.5
    tui, _ = run(["4", "1", "d1", "b", "b"], cfg=tui.cfg)
    assert "thresholds" not in tui.cfg.overrides


def test_rejects_non_numeric_threshold():
    tui, out = run(["4", "1", "1", "lots", "b", "b"])
    assert "That's not a number" in out
    assert tui.cfg.overrides == {}


def test_checks_toggle():
    tui, _ = run(["5", "1", "b"])
    assert tui.cfg.check_enabled("efficiency") is False


def test_customize_wait_event_from_finding():
    # Finding 5 is 'db file sequential read'; option 2 edits what it means.
    inputs = ["5", "c", "2", "3", "Our SAN is slow; see ticket STOR-12.", "b", "b", "q", "n"]
    tui, out = run(inputs, report=PROBLEM)
    [entry] = tui.cfg.effective["wait_events"]["custom"]
    assert entry["pattern"] == "^db file sequential read"
    assert entry["plain"] == "Our SAN is slow; see ticket STOR-12."
    assert entry["recommendations"]  # starts from the built-in advice
    seq = next(f for f in tui.result.findings if f.rule_id == "wait.db file sequential read")
    assert seq.plain_explanation == "Our SAN is slow; see ticket STOR-12."


def test_custom_rule_from_metric_explorer_with_test():
    inputs = [
        "m", "f", "avg_wait_ms", "2",          # pick wait.db file sequential read.avg_wait_ms
        "2",                                    # generalize to wait.*.avg_wait_ms
        "", "40", "",                           # op '>', warning 40, no critical
        "slow_waits", "Slow wait: {match}", "Waits over 40 ms break our SLA.", "b",
        "b", "b", "q", "n",
    ]
    tui, out = run(inputs, report=PROBLEM)
    [rule] = tui.cfg.custom_rules()
    assert rule["metric"] == "wait.*.avg_wait_ms"
    assert rule["warning"] == 40.0 and rule["critical"] is None
    assert "5 metric(s) matched; 2 would be flagged." in out
    titles = [f.title for f in tui.result.findings]
    assert "Slow wait: enq: TX - row lock contention" in titles


def test_add_custom_rule_from_menu_and_edit_it():
    inputs = [
        "9", "a", "efficiency.buffer_hit", "<", "99", "90", "cache_rule", "", "Cache too small", "b",
        "1", "5", "95", "b", "b",
    ]
    tui, _ = run(inputs)
    [rule] = tui.cfg.custom_rules()
    assert rule["name"] == "cache_rule" and rule["op"] == "<"
    assert rule["warning"] == 95.0 and rule["critical"] == 90.0


def test_watchlist_from_query_detail():
    inputs = ["q", "1", "w", "Search page query", "b", "b", "w", "b", "q", "n"]
    tui, out = run(inputs, report=PROBLEM)
    assert tui.cfg.watchlist() == {"badsql000001": "Search page query"}
    assert "Search page query" in out


def test_sql_flag_relabel():
    tui, _ = run(["8", "3", "2", "Needs an index", "b", "b"])
    assert tui.cfg.sql_tag("missing_index_suspect")["label"] == "Needs an index"


def test_preset_and_weights():
    tui, _ = run(["11", "2", "12", "1", "30", "b"])
    assert tui.cfg.preset == "data_warehouse"
    assert tui.cfg.score_weight("critical") == 30.0


def test_export_from_review(tmp_path):
    target = tmp_path / "out.html"
    run(["x", "h", str(target), "b", "q"], report=PROBLEM)
    assert "AWR Analysis Report" in target.read_text()


def test_trend_flow(tmp_path):
    paths = [str(FIXTURES / f"sample_trend_{i}.html") for i in (1, 2, 3)]
    tui, out = run(["3", *paths, "", "b", "q"])
    assert "Trend across 3 reports" in out
    assert "Early warnings" in out


def test_quit_prompts_to_save_unsaved_changes(tmp_path):
    path = tmp_path / "cfg.json"
    run(["5", "1", "b", "q", "y", ""], config_path=str(path))
    assert json.loads(path.read_text())["checks"] == {"efficiency": False}


def test_load_and_reset(tmp_path):
    path = tmp_path / "team.json"
    path.write_text(json.dumps({"thresholds": {"hard_parse_warning": 3}}))
    tui, out = run(["l", str(path), "r", "y"])
    assert "Loaded" in out
    assert tui.cfg.overrides == {}


def test_missing_report_path_is_reported():
    _, out = run(["1", "/no/such/report.html", "q"])
    assert "File not found" in out
