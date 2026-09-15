from pathlib import Path

from awr_analyzer.forecast import build_trend
from awr_analyzer.parser import parse_awr_file

FIXTURES = Path(__file__).parent / "fixtures"


def _load_trend_reports():
    return [parse_awr_file(str(FIXTURES / f"sample_trend_{i}.html")) for i in (1, 2, 3)]


def test_trend_detects_worsening_buffer_hit():
    trend = build_trend(_load_trend_reports())
    result = next(r for r in trend.results if r.key == "buffer_hit")
    assert result.direction == "worsening"
    assert result.first_value == 98.5
    assert result.last_value == 88.0
    assert result.forecast_note is not None


def test_trend_detects_worsening_io_latency():
    trend = build_trend(_load_trend_reports())
    result = next(r for r in trend.results if r.key == "seq_read_ms")
    assert result.direction == "worsening"
    assert result.forecast_note is not None


def test_trend_detects_stable_metric():
    trend = build_trend(_load_trend_reports())
    result = next(r for r in trend.results if r.key == "library_hit")
    assert result.direction == "stable"
    assert result.forecast_note is None


def test_emerging_risks_only_includes_forecasted_worsening_metrics():
    trend = build_trend(_load_trend_reports())
    risks = trend.emerging_risks()
    assert risks
    for r in risks:
        assert r.direction == "worsening"
        assert r.forecast_note is not None


def test_labels_are_chronological_and_parsed():
    trend = build_trend(_load_trend_reports())
    assert trend.labels == ["2024-09-10 14:00", "2024-09-11 14:00", "2024-09-12 14:00"]
