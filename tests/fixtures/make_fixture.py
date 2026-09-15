"""Generates synthetic-but-structurally-realistic AWR HTML fixtures for
tests. Not a real Oracle AWR report, but it mirrors the table/heading
layout closely enough to exercise the parser's heuristics honestly.
"""

from __future__ import annotations


def _load_profile_rows(overrides: dict) -> str:
    defaults = {
        "DB Time(s):": (12.5, 0.02, None, None),
        "DB CPU(s):": (8.1, 0.013, None, None),
        "Redo size (bytes):": (450000.0, 720.0, None, None),
        "Logical read (blocks):": (52000.0, 83.2, None, None),
        "Block changes:": (3100.0, 4.96, None, None),
        "Physical read (blocks):": (900.0, 1.44, None, None),
        "Physical write (blocks):": (210.0, 0.34, None, None),
        "Executes (SQL):": (610.0, 0.976, None, None),
        "Hard parses (SQL):": (0.4, 0.0006, None, None),
        "Parses (SQL):": (60.0, 0.096, None, None),
        "Transactions:": (625.0, None, None, None),
    }
    defaults.update(overrides)
    rows = []
    for label, vals in defaults.items():
        cells = "".join(f"<td>{v:,.2f}</td>" if v is not None else "<td>&nbsp;</td>" for v in vals)
        rows.append(f"<tr><td>{label}</td>{cells}</tr>")
    return "\n".join(rows)


def _efficiency_rows(overrides: dict) -> str:
    defaults = {
        "Buffer Nowait %:": 99.98, "Redo NoWait %:": 100.0,
        "Buffer  Hit   %:": 99.6, "In-memory Sort %:": 99.9,
        "Library Hit   %:": 99.4, "Soft Parse %:": 99.3,
        "Execute to Parse %:": 90.2, "Latch Hit %:": 99.9,
        "Parse CPU to Parse Elapsd %:": 88.0, "% Non-Parse CPU:": 97.5,
    }
    defaults.update(overrides)
    items = list(defaults.items())
    rows = []
    for i in range(0, len(items), 2):
        pair = items[i:i + 2]
        cells = "".join(f"<td>{label}</td><td>{value}</td>" for label, value in pair)
        rows.append(f"<tr>{cells}</tr>")
    return "\n".join(rows)


def _wait_event_rows(events: list) -> str:
    rows = []
    for e in events:
        rows.append(
            f"<tr><td>{e['event']}</td><td>{e.get('class','')}</td>"
            f"<td>{e.get('waits',0):,.0f}</td><td>{e.get('time_s',0):,.0f}</td>"
            f"<td>{e.get('avg_ms',0):,.2f}</td><td>{e.get('pct',0):,.1f}</td></tr>"
        )
    return "\n".join(rows)


def _sql_rows(items: list, metric_header: str) -> str:
    rows = []
    for s in items:
        rows.append(
            f"<tr><td>{s['value']:,.2f}</td><td>{s.get('executions',0):,.0f}</td>"
            f"<td>{s.get('per_exec',0):,.4f}</td><td>{s.get('pct',0):,.1f}</td>"
            f"<td>{s['sql_id']}</td><td>{s.get('module','')}</td><td>{s.get('text','')}</td></tr>"
        )
    return "\n".join(rows)


def _tablespace_rows(items: list) -> str:
    rows = []
    for t in items:
        rows.append(
            f"<tr><td>{t['name']}</td><td>{t.get('reads',0):,.0f}</td>"
            f"<td>{t.get('avg_reads_s',0):,.2f}</td><td>{t.get('avg_rd_ms',0):,.2f}</td>"
            f"<td>1.0</td><td>{t.get('writes',0):,.0f}</td>"
            f"<td>{t.get('avg_writes_s',0):,.2f}</td><td>0</td><td>0.0</td></tr>"
        )
    return "\n".join(rows)


def build_awr_html(
    db_name="ORCLDB", db_id="1234567890", instance="orcl1", inst_num="1",
    release="19.0.0.0.0", rac="NO",
    host_name="dbhost01", platform="Linux x86 64-bit", cpus=8, cores=4, sockets=2, memory_gb=64.0,
    begin_snap_id="1001", begin_snap_time="13-Sep-24 14:00:00",
    end_snap_id="1002", end_snap_time="13-Sep-24 15:00:00",
    elapsed_min=60.0, db_time_min=25.0,
    load_profile_overrides=None,
    efficiency_overrides=None,
    wait_events=None,
    sql_by_elapsed=None,
    tablespace_io=None,
) -> str:
    load_profile_overrides = load_profile_overrides or {}
    efficiency_overrides = efficiency_overrides or {}
    wait_events = wait_events if wait_events is not None else [
        {"event": "DB CPU", "class": "CPU", "waits": 0, "time_s": 487, "avg_ms": 0, "pct": 32.4},
        {"event": "db file sequential read", "class": "User I/O", "waits": 45000, "time_s": 190, "avg_ms": 4.2, "pct": 8.0},
        {"event": "log file sync", "class": "Commit", "waits": 6000, "time_s": 32, "avg_ms": 5.3, "pct": 2.1},
        {"event": "SQL*Net message from client", "class": "Idle", "waits": 22000, "time_s": 9800, "avg_ms": 445.0, "pct": 3.0},
    ]
    sql_by_elapsed = sql_by_elapsed if sql_by_elapsed is not None else [
        {"sql_id": "abcd1234efghi", "value": 95.5, "executions": 5000, "per_exec": 0.019, "pct": 6.3,
         "module": "OrderApp", "text": "SELECT * FROM orders WHERE status = :b1"},
        {"sql_id": "zxywv9876mnop", "value": 60.2, "executions": 12, "per_exec": 5.02, "pct": 4.0,
         "module": "BatchJob", "text": "UPDATE customer SET last_login = SYSDATE WHERE ..."},
    ]
    tablespace_io = tablespace_io if tablespace_io is not None else [
        {"name": "USERS", "reads": 42000, "avg_reads_s": 11.7, "avg_rd_ms": 6.5, "writes": 5000, "avg_writes_s": 1.4},
        {"name": "TEMP", "reads": 8000, "avg_reads_s": 2.2, "avg_rd_ms": 4.1, "writes": 3000, "avg_writes_s": 0.8},
    ]

    return f"""<!DOCTYPE html>
<html>
<head><title>WORKLOAD REPOSITORY report for {db_name}</title></head>
<body>
<h1>WORKLOAD REPOSITORY report for</h1>

<table border="1">
<tr><th>DB Name</th><th>DB Id</th><th>Instance</th><th>Inst num</th><th>Release</th><th>RAC</th></tr>
<tr><td>{db_name}</td><td>{db_id}</td><td>{instance}</td><td>{inst_num}</td><td>{release}</td><td>{rac}</td></tr>
</table>

<table border="1">
<tr><th>Host Name</th><th>Platform</th><th>CPUs</th><th>Cores</th><th>Sockets</th><th>Memory(GB)</th></tr>
<tr><td>{host_name}</td><td>{platform}</td><td>{cpus}</td><td>{cores}</td><td>{sockets}</td><td>{memory_gb}</td></tr>
</table>

<table border="1">
<tr><th>Snap Id</th><th>Snap Time</th><th>Sessions</th><th>Cursors/Session</th></tr>
<tr><td>Begin Snap:</td><td>{begin_snap_id}</td><td>{begin_snap_time}</td></tr>
<tr><td>End Snap:</td><td>{end_snap_id}</td><td>{end_snap_time}</td></tr>
</table>

<p>Elapsed: &nbsp;{elapsed_min:.2f} (mins)&nbsp;&nbsp;&nbsp;&nbsp;DB Time: &nbsp;{db_time_min:.2f} (mins)</p>

<h3>Report Summary</h3>

Load Profile

<table border="1" summary="This table displays load profile">
<tr><th>&nbsp;</th><th>Per Second</th><th>Per Transaction</th><th>Per Exec</th><th>Per Call</th></tr>
{_load_profile_rows(load_profile_overrides)}
</table>

Instance Efficiency Percentages (Target 100%)

<table border="1">
{_efficiency_rows(efficiency_overrides)}
</table>

<h3>Main Report</h3>

Top 5 Timed Foreground Events

<table border="1">
<tr><th>Event</th><th>Wait Class</th><th>Waits</th><th>Time(s)</th><th>Avg wait (ms)</th><th>% DB time</th></tr>
{_wait_event_rows(wait_events)}
</table>

SQL ordered by Elapsed Time

<table border="1">
<tr><th>Elapsed Time (s)</th><th>Executions</th><th>Elapsed Time per Exec (s)</th><th>%Total</th><th>SQL Id</th><th>SQL Module</th><th>SQL Text</th></tr>
{_sql_rows(sql_by_elapsed, "Elapsed Time (s)")}
</table>

Tablespace IO Stats

<table border="1">
<tr><th>Tablespace</th><th>Reads</th><th>Av Reads/s</th><th>Av Rd(ms)</th><th>Av Blks/Rd</th><th>Writes</th><th>Av Writes/s</th><th>Buffer Waits</th><th>Av Buf Wt(ms)</th></tr>
{_tablespace_rows(tablespace_io)}
</table>

</body>
</html>
"""


if __name__ == "__main__":
    import pathlib

    out_dir = pathlib.Path(__file__).parent

    # A broadly healthy report.
    (out_dir / "sample_healthy.html").write_text(build_awr_html(), encoding="utf-8")

    # A report with clear, multi-category problems.
    problem_html = build_awr_html(
        db_name="PRODDB", instance="prod1", host_name="dbprod01",
        elapsed_min=60.0, db_time_min=95.0,
        load_profile_overrides={
            "Hard parses (SQL):": (3.2, 0.005, None, None),
        },
        efficiency_overrides={
            "Buffer  Hit   %:": 78.4,
            "Library Hit   %:": 88.2,
            "Soft Parse %:": 72.1,
            "In-memory Sort %:": 60.0,
        },
        wait_events=[
            {"event": "db file sequential read", "class": "User I/O", "waits": 900000, "time_s": 27000, "avg_ms": 30.0, "pct": 47.4},
            {"event": "DB CPU", "class": "CPU", "waits": 0, "time_s": 12000, "avg_ms": 0, "pct": 21.1},
            {"event": "log file sync", "class": "Commit", "waits": 400000, "time_s": 9000, "avg_ms": 22.5, "pct": 15.8},
            {"event": "enq: TX - row lock contention", "class": "Application", "waits": 5000, "time_s": 4200, "avg_ms": 840.0, "pct": 7.4},
            {"event": "direct path write temp", "class": "User I/O", "waits": 30000, "time_s": 2200, "avg_ms": 73.3, "pct": 3.9},
        ],
        sql_by_elapsed=[
            {"sql_id": "badsql000001", "value": 22000.0, "executions": 800000, "per_exec": 0.0275, "pct": 38.6,
             "module": "WebApp", "text": "SELECT * FROM big_table WHERE name LIKE '%'||:b1||'%'"},
            {"sql_id": "slowbatch0002", "value": 9000.0, "executions": 4, "per_exec": 2250.0, "pct": 15.8,
             "module": "NightlyBatch", "text": "MERGE INTO fact_sales USING staging_sales ..."},
        ],
        tablespace_io=[
            {"name": "USERS", "reads": 900000, "avg_reads_s": 250.0, "avg_rd_ms": 35.0, "writes": 50000, "avg_writes_s": 13.9},
            {"name": "TEMP", "reads": 300000, "avg_reads_s": 83.3, "avg_rd_ms": 18.0, "writes": 200000, "avg_writes_s": 55.6},
        ],
    )
    (out_dir / "sample_problem.html").write_text(problem_html, encoding="utf-8")

    # A 3-report trend series with worsening buffer cache & I/O over time.
    trend_specs = [
        dict(begin_snap_time="10-Sep-24 14:00:00", end_snap_time="10-Sep-24 15:00:00",
             buffer_hit=98.5, phys_read=(900.0, 1.44), seq_avg_ms=6.0, seq_pct=20.0),
        dict(begin_snap_time="11-Sep-24 14:00:00", end_snap_time="11-Sep-24 15:00:00",
             buffer_hit=94.0, phys_read=(2200.0, 3.5), seq_avg_ms=11.0, seq_pct=28.0),
        dict(begin_snap_time="12-Sep-24 14:00:00", end_snap_time="12-Sep-24 15:00:00",
             buffer_hit=88.0, phys_read=(4100.0, 6.5), seq_avg_ms=17.0, seq_pct=36.0),
    ]
    for i, spec in enumerate(trend_specs, start=1):
        html = build_awr_html(
            begin_snap_time=spec["begin_snap_time"], end_snap_time=spec["end_snap_time"],
            load_profile_overrides={"Physical read (blocks):": (*spec["phys_read"], None, None)},
            efficiency_overrides={"Buffer  Hit   %:": spec["buffer_hit"]},
            wait_events=[
                {"event": "db file sequential read", "class": "User I/O", "waits": 45000, "time_s": 380,
                 "avg_ms": spec["seq_avg_ms"], "pct": spec["seq_pct"]},
                {"event": "DB CPU", "class": "CPU", "waits": 0, "time_s": 487, "avg_ms": 0, "pct": 32.4},
            ],
        )
        (out_dir / f"sample_trend_{i}.html").write_text(html, encoding="utf-8")

    print("Fixtures written to", out_dir)
