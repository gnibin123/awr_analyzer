from pathlib import Path

from awr_analyzer.parser import parse_awr_file
from awr_analyzer.sql_insights import build_sql_insights

FIXTURES = Path(__file__).parent / "fixtures"


def _insight(sa, sql_id):
    return next(p for p in sa.insights if p.sql_id == sql_id)


def test_merges_fields_across_sql_lists():
    report = parse_awr_file(str(FIXTURES / "sample_problem.html"))
    sa = build_sql_insights(report)
    p = _insight(sa, "badsql000001")
    # elapsed_s comes from sql_by_elapsed, gets_per_exec from sql_by_gets.
    assert p.elapsed_s == 22000.0
    assert p.gets_per_exec == 200000.0
    assert p.pct_cpu == 15.0
    assert p.pct_io == 80.0
    assert "Elapsed Time" in p.seen_in
    assert "Buffer Gets" in p.seen_in


def test_flags_missing_index_suspect_as_critical():
    report = parse_awr_file(str(FIXTURES / "sample_problem.html"))
    sa = build_sql_insights(report)
    p = _insight(sa, "badsql000001")
    assert "missing_index_suspect" in p.tags
    assert "io_bound" in p.tags  # pct_io=80 >= threshold
    assert p.severity == "critical"


def test_flags_cpu_bound_and_expensive_single_run():
    report = parse_awr_file(str(FIXTURES / "sample_problem.html"))
    sa = build_sql_insights(report)
    p = _insight(sa, "slowbatch0002")
    assert "cpu_bound" in p.tags
    assert "expensive_single_run" in p.tags
    assert p.severity == "warning"  # escalated via high_impact (pct_elapsed=15.8%)


def test_healthy_report_has_no_problematic_sql():
    report = parse_awr_file(str(FIXTURES / "sample_healthy.html"))
    sa = build_sql_insights(report)
    assert all(p.severity == "info" for p in sa.insights)


def test_detects_bind_variable_suspects():
    report = parse_awr_file(str(FIXTURES / "sample_problem.html"))
    sa = build_sql_insights(report)
    assert len(sa.bind_variable_suspects) == 1
    group = sa.bind_variable_suspects[0]
    assert set(group.sql_ids) == {"literalqry001", "literalqry002", "literalqry003"}


def test_no_false_positive_bind_variable_suspects_on_distinct_queries():
    report = parse_awr_file(str(FIXTURES / "sample_healthy.html"))
    sa = build_sql_insights(report)
    assert sa.bind_variable_suspects == []


def test_insights_sorted_by_elapsed_desc():
    report = parse_awr_file(str(FIXTURES / "sample_problem.html"))
    sa = build_sql_insights(report)
    elapsed_values = [p.elapsed_s or 0 for p in sa.insights]
    assert elapsed_values == sorted(elapsed_values, reverse=True)


def test_problematic_only_includes_tagged_insights():
    report = parse_awr_file(str(FIXTURES / "sample_problem.html"))
    sa = build_sql_insights(report)
    problematic = sa.problematic()
    assert all(p.tags for p in problematic)
    assert len(problematic) < len(sa.insights)
