import json

import pytest

from awr_analyzer import rules
from awr_analyzer.config import (
    PRESETS,
    THRESHOLD_SPECS,
    AnalyzerConfig,
    ConfigError,
    resolve_config,
)


def test_defaults_come_from_rules():
    cfg = AnalyzerConfig()
    assert cfg.threshold("wait_event_pct_warning") == rules.WAIT_EVENT_PCT_WARNING
    assert cfg.threshold("ts_min_reads") == rules.TS_MIN_READS_FOR_LATENCY_CHECK
    assert cfg.efficiency()["buffer_hit"]["warning"] == rules.EFFICIENCY_THRESHOLDS["buffer_hit"][0]
    assert cfg.sql_tag("cpu_bound")["label"] == rules.SQL_TAG_INFO["cpu_bound"]["label"]
    assert all(cfg.check_enabled(name) for name in ("efficiency", "sql", "custom_rules"))


def test_every_threshold_spec_has_a_description_and_default():
    for spec in THRESHOLD_SPECS:
        assert spec.description and spec.unit and spec.group
        assert AnalyzerConfig().threshold(spec.key) == spec.default


def test_setting_default_value_removes_override():
    cfg = AnalyzerConfig()
    cfg.set(("thresholds", "seq_read_ms_warning"), 5.0)
    assert cfg.overrides == {"thresholds": {"seq_read_ms_warning": 5.0}}
    cfg.set(("thresholds", "seq_read_ms_warning"), rules.SEQ_READ_MS_WARNING)
    assert cfg.overrides == {}


def test_unset_prunes_empty_parents():
    cfg = AnalyzerConfig()
    cfg.set(("efficiency", "buffer_hit", "warning"), 90.0)
    cfg.unset(("efficiency", "buffer_hit", "warning"))
    assert cfg.overrides == {}


def test_preset_applies_and_user_override_wins():
    cfg = AnalyzerConfig.from_preset("strict")
    assert cfg.threshold("seq_read_ms_warning") == PRESETS["strict"]["overrides"]["thresholds"]["seq_read_ms_warning"]
    cfg.set(("thresholds", "seq_read_ms_warning"), 4.5)
    assert cfg.threshold("seq_read_ms_warning") == 4.5
    cfg.set_preset("oltp")
    assert cfg.preset == "oltp"
    assert cfg.threshold("seq_read_ms_warning") == 4.5  # still the user's own value


def test_save_writes_only_overrides_and_load_round_trips(tmp_path):
    cfg = AnalyzerConfig()
    cfg.set(("thresholds", "hard_parse_warning"), 2.0)
    cfg.set(("suppress",), ["wait.SQL*Net*"])
    path = tmp_path / "cfg.json"
    cfg.save(path)
    data = json.loads(path.read_text())
    assert data == {"version": 1, "thresholds": {"hard_parse_warning": 2.0}, "suppress": ["wait.SQL*Net*"]}

    loaded = AnalyzerConfig.load(path)
    assert loaded.threshold("hard_parse_warning") == 2.0
    assert loaded.is_suppressed("wait.SQL*Net message from client")
    assert not loaded.dirty


def test_dirty_tracks_difference_from_saved_state(tmp_path):
    cfg = AnalyzerConfig()
    assert not cfg.dirty
    cfg.set(("checks", "sql"), False)
    assert cfg.dirty
    cfg.set(("checks", "sql"), True)  # back to the default: nothing to save
    assert not cfg.dirty


def test_load_rejects_bad_json(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json")
    with pytest.raises(ConfigError, match="not valid JSON"):
        AnalyzerConfig.load(path)
    with pytest.raises(ConfigError, match="not found"):
        AnalyzerConfig.load(tmp_path / "missing.json")


def test_validate_reports_mistakes():
    cfg = AnalyzerConfig(overrides={
        "thresholds": {"seq_read_ms_warning": "fast", "nope": 1, "sql_pct_warning": 50},
        "wait_events": {"custom": [{"pattern": "([unclosed"}]},
        "custom_rules": [{"name": "r1", "metric": "x", "op": "~"}],
        "preset": "imaginary",
        "mystery": True,
    })
    problems = cfg.validate()
    text = "\n".join(f"{level}: {msg}" for level, msg in problems)
    assert "error: thresholds.seq_read_ms_warning must be a number" in text
    assert "thresholds.nope is not a known threshold" in text
    assert "sql_pct_warning (50) is higher than sql_pct_critical" in text
    assert "not a valid regex" in text
    assert "custom_rules[0]" in text
    assert "unknown preset 'imaginary'" in text
    assert "unknown setting 'mystery'" in text


def test_clean_config_validates():
    assert AnalyzerConfig().validate() == []
    for name in PRESETS:
        assert AnalyzerConfig.from_preset(name).validate() == []


def test_custom_wait_event_entry_takes_priority():
    cfg = AnalyzerConfig()
    cfg.set(("wait_events", "custom"), [
        {"pattern": "^log file sync", "category": "Commit/Redo", "plain": "Our storage is slow.",
         "recommendations": ["Call storage."]},
    ])
    assert cfg.lookup_wait_event("log file sync")["plain"] == "Our storage is slow."
    assert cfg.lookup_wait_event("db file sequential read")["category"] == "I/O"  # built-in still used


def test_describe_changes():
    cfg = AnalyzerConfig.from_preset("data_warehouse")
    cfg.set(("thresholds", "ts_min_reads"), 500.0)
    cfg.set(("custom_rules",), [{"name": "redo", "metric": "x", "warning": 1}])
    lines = cfg.describe_changes()
    assert "preset: data_warehouse" in lines
    assert any(line.startswith("thresholds.ts_min_reads: 100") for line in lines)
    assert any("custom_rules: 1 entry" in line and "redo" in line for line in lines)


def test_resolve_config_prefers_explicit_path(tmp_path, monkeypatch):
    path = tmp_path / "team.json"
    path.write_text(json.dumps({"thresholds": {"hard_parse_warning": 3}}))
    assert resolve_config(str(path)).threshold("hard_parse_warning") == 3

    default_path = tmp_path / "default.json"
    default_path.write_text(json.dumps({"thresholds": {"hard_parse_warning": 4}}))
    monkeypatch.setenv("AWR_ANALYZER_CONFIG", str(default_path))
    assert resolve_config().threshold("hard_parse_warning") == 4
    assert resolve_config(use_default_file=False).threshold("hard_parse_warning") == rules.HARD_PARSE_WARNING
    assert resolve_config(preset="strict").preset == "strict"
