# AWR Analyzer

A standalone command-line tool that reads Oracle **AWR (Automatic Workload
Repository)** HTML reports and turns them into a plain-language, actionable
performance report — written so that someone without deep Oracle DBA
experience can understand what's wrong and what to do about it, while still
giving a DBA the exact numbers behind every finding.

It can also compare a **series** of AWR reports over time and forecast
metrics that are trending toward trouble, so you can catch emerging issues
(like a buffer cache that's slowly getting too small, or storage latency
creeping up) before they become outages.

## What it does

- **Parses** Oracle AWR HTML reports (from `awrrpt.sql` / `awrrpti.sql`),
  tolerant of the formatting differences between Oracle versions (11g
  through 19c/21c-style reports).
- **Analyzes** the parsed data against well-known DBA rules of thumb across:
  - Instance efficiency (buffer cache hit ratio, library cache hit ratio,
    soft parse ratio, in-memory sort ratio, latch hit ratio, ...)
  - Top wait events (I/O, commit/redo, locking, contention, RAC/cluster,
    idle waits) with a built-in knowledge base explaining what each common
    wait event actually means and what to check
  - CPU-bound workload detection
  - High hard-parse rates (usually a sign of missing bind variables)
  - High-impact SQL statements (the ones responsible for the biggest share
    of database time)
  - Tablespace I/O latency
- **Explains** every finding in plain language (what's happening and why it
  matters) plus a technical detail line with the exact numbers, a severity
  (critical / warning / info), and concrete recommended actions.
- **Forecasts** trends across multiple chronological AWR reports using a
  simple, clearly-labeled linear projection — flagging metrics moving
  toward a critical threshold and estimating how many report periods away
  that crossing is, so you get an early warning rather than a surprise.
- **Reports** as a clean, self-contained HTML page (open it in any
  browser), plain text (great for terminals/CI logs), or JSON (for feeding
  into other tooling).

This tool only reads the HTML report you give it — it never connects to a
database.

## Installation

Requires Python 3.8+.

```bash
pip install -e .
# or, without installing as a package:
pip install -r requirements.txt
```

## Usage

### Analyze a single AWR report

```bash
awr-analyzer analyze path/to/awrrpt_1_1001_1002.html
```

This writes `awrrpt_1_1001_1002_analysis.html` next to the input file and
prints a one-line health summary to the console. Open the HTML file in a
browser for the full report.

Other options:

```bash
# Pick where the report goes
awr-analyzer analyze report.html -o insights.html

# Plain text instead of HTML (good for terminals/CI)
awr-analyzer analyze report.html --format text

# Machine-readable JSON
awr-analyzer analyze report.html --format json -o insights.json
```

### Forecast trends across multiple reports

Give it 2 or more AWR reports **in chronological order** (e.g. one per day,
or one per hour) and it will analyze the most recent one normally, plus add
a trend section:

```bash
awr-analyzer trend day1.html day2.html day3.html day4.html day5.html
```

This writes `awr_trend_report.html` by default. The trend section tracks
things like buffer cache hit ratio, physical reads, hard parse rate, DB CPU
%, and I/O wait latency across the series, tells you whether each is
improving, worsening, or stable, and — for metrics with a known critical
threshold — projects roughly how many report periods away that threshold is
if the current trend continues. This is a simple straight-line projection
meant to surface early warnings, not a guarantee; it says so directly in
the output.

### Using it as a library

```python
from awr_analyzer import parse_awr_file, analyze, build_trend
from awr_analyzer.report import render_html

report = parse_awr_file("awrrpt.html")
result = analyze(report)

print(result.health_score)       # 0-100
for finding in result.findings:
    print(finding.severity, finding.title)

html = render_html(result)
```

## How to generate an AWR report

From SQL*Plus, connected as a user with the right privileges (e.g. `sys` or
a DBA-privileged account):

```sql
@?/rdbms/admin/awrrpt.sql
```

Choose `html` as the format when prompted, pick your begin/end snapshot IDs,
and give the output file a name. Then run `awr-analyzer analyze` on that
file.

## Project layout

```
awr_analyzer/
  parser.py     # HTML -> structured AWRReport data
  models.py     # Data classes: AWRReport, Finding, AnalysisResult, ...
  rules.py      # Thresholds + plain-language knowledge base
  analyzer.py   # AWRReport -> list of Findings + health score
  forecast.py   # Multiple AWRReports -> trend/forecast analysis
  report.py     # Findings/trend -> HTML / text output
  cli.py        # Command-line entry point
tests/
  fixtures/     # Synthetic AWR HTML fixtures + generator script
  test_*.py     # pytest unit tests
```

## Limitations

- Only HTML-format AWR reports are supported (not the plain-text
  `awrrpt.sql` output, and not ASH/ADDM reports).
- The parser is heuristic — it matches sections by their heading text and
  table headers rather than fixed anchors, which makes it resilient across
  Oracle versions but means an unusually customized or heavily modified AWR
  report could have sections it doesn't recognize. Unrecognized sections
  are skipped rather than causing an error.
- Thresholds are general-purpose DBA rules of thumb. Every workload is
  different — use the findings as a prioritized starting point for
  investigation, not a final diagnosis.
- Trend forecasts use a simple linear projection across the reports you
  provide; they're meant to be an early-warning signal, not a precise
  prediction.

## Running the tests

```bash
pip install -e ".[dev]"
python3 tests/fixtures/make_fixture.py   # (re)generate synthetic fixtures
pytest
```
