from pathlib import Path

from awr_analyzer.custom_rules import (
    evaluate_rule,
    flatten_metrics,
    match_rule,
    render_template,
    validate_rule,
)
from awr_analyzer.parser import parse_awr_file
from awr_analyzer.sql_insights import build_sql_insights

FIXTURES = Path(__file__).parent / "fixtures"


def _metrics():
    report = parse_awr_file(str(FIXTURES / "sample_problem.html"))
    return flatten_metrics(report, build_sql_insights(report))


def test_flatten_metrics_names_every_section():
    m = _metrics()
    assert m["wait.log file sync.avg_wait_ms"] == 22.5
    assert m["efficiency.buffer_hit"] == 78.4
    assert m["load_profile.hard_parses_sql.per_second"] == 3.2
    assert m["tablespace.USERS.avg_read_time_ms"] == 35.0
    assert m["sql.badsql000001.gets_per_exec"] == 200000.0
    assert m["info.avg_active_sessions"] == 95.0 / 60.0


def test_wildcard_rule_creates_one_finding_per_match():
    rule = {"name": "slow_waits", "metric": "wait.*.avg_wait_ms", "op": ">", "warning": 40, "critical": 500,
            "title": "Slow wait: {match} ({value:.0f} ms)", "explanation": "{match} is over {threshold} ms",
            "recommendations": ["Check {match}"]}
    findings = evaluate_rule(rule, _metrics())
    by_title = {f.title: f for f in findings}
    assert set(by_title) == {"Slow wait: enq: TX - row lock contention (840 ms)",
                             "Slow wait: direct path write temp (73 ms)"}
    crit = by_title["Slow wait: enq: TX - row lock contention (840 ms)"]
    assert crit.severity == "critical"
    assert crit.plain_explanation == "enq: TX - row lock contention is over 500 ms"
    assert crit.recommendations == ["Check enq: TX - row lock contention"]
    assert crit.rule_id == "custom.slow_waits.enq: TX - row lock contention"
    assert crit.category == "Custom"


def test_less_than_rule_and_exact_metric():
    rule = {"name": "cache", "metric": "efficiency.buffer_hit", "op": "<", "warning": 99}
    [finding] = evaluate_rule(rule, _metrics())
    assert finding.severity == "warning"
    assert finding.rule_id == "custom.cache"
    assert "buffer_hit" in finding.title  # automatic title


def test_max_matches_caps_findings():
    rule = {"name": "any", "metric": "wait.*.waits", "op": ">=", "warning": 0, "max_matches": 2}
    assert len(evaluate_rule(rule, _metrics())) == 2


def test_disabled_or_invalid_rules_produce_nothing():
    metrics = _metrics()
    assert evaluate_rule({"name": "x", "metric": "efficiency.buffer_hit", "op": "<", "warning": 99,
                          "enabled": False}, metrics) == []
    assert evaluate_rule({"name": "x", "metric": "efficiency.buffer_hit"}, metrics) == []


def test_match_rule_reports_unflagged_matches_too():
    matches = match_rule({"name": "t", "metric": "tablespace.*.avg_read_time_ms", "op": ">", "warning": 20},
                         _metrics())
    assert {m["match"]: m["severity"] for m in matches} == {"USERS": "warning", "TEMP": None}


def test_validate_rule_messages():
    assert validate_rule({"name": "ok", "metric": "a.b", "op": ">", "warning": 1}) == []
    errors = " ".join(validate_rule({"name": "bad name!", "metric": "", "op": "=>", "warning": "x"}))
    for expected in ("'name' may only use", "needs a 'metric'", "'op' must be", "'warning' must be a number"):
        assert expected in errors
    assert "needs a 'warning' and/or 'critical'" in " ".join(validate_rule({"name": "a", "metric": "m"}))


def test_template_errors_fall_back_to_raw_text():
    assert render_template("{value:,.0f} ms", {"value": 1234.5}) == "1,234 ms"
    assert render_template("{unknown} stays", {}) == "{unknown} stays"
    assert render_template("{value:.1f}", {"value": "text"}) == "{value:.1f}"
