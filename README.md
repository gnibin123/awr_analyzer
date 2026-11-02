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
  - Tablespace I/O latency
- **Profiles individual SQL statements** by cross-referencing all five "SQL
  ordered by ..." sections (Elapsed Time, CPU, Gets, Reads, Executions) into
  one view per SQL_ID, then flags:
  - CPU-bound vs. I/O-bound statements (where a statement's own time is
    actually going)
  - Likely missing indexes / inefficient access paths (very high buffer
    gets or physical reads per execution)
  - Low-selectivity queries (reading far more blocks than the rows they
    actually return)
  - High call-volume statements worth caching/batching vs. expensive
    low-frequency statements worth a one-off tuning pass
  - Groups of near-identical statements that differ only in literal values
    — a likely sign the application isn't using bind variables
  Each flagged query gets plain-language reasoning plus concrete next
  steps (what to check in the execution plan, what kind of index might
  help, etc.), and the full ranked list — not just the ones that got
  individually called out — appears in a dedicated "Problematic Queries"
  table in the report.
- **Explains** every finding in plain language (what's happening and why it
  matters) plus a technical detail line with the exact numbers, a severity
  (critical / warning / info), and concrete recommended actions.
- **Forecasts** trends across multiple chronological AWR reports using a
  simple, clearly-labeled linear projection — flagging metrics moving
  toward a critical threshold and estimating how many report periods away
  that crossing is, so you get an early warning rather than a surprise.
- **Is fully customizable**: thresholds, which checks run, the explanation
  and advice attached to every kind of finding, your own rules on any
  metric, a SQL watchlist, and findings to hide, all from an interactive
  text interface (`awr-analyzer tui`) or a JSON settings file.
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

### Interactive mode

```bash
awr-analyzer tui                 # or: awr-analyzer tui report.html
```

A menu-driven text interface that runs in any terminal (SSH and Windows
included) with no extra dependencies. From it you can:

- **Analyze** a report and browse the findings, the problematic-queries
  table and your watched queries; open any finding for its full
  explanation, advice and technical detail; export HTML, text or JSON.
- **Jump from a finding to the setting behind it.** Press `c` on a finding
  to change its thresholds or rewrite what it says, or `h` to hide it. The
  analysis re-runs automatically when you return, so you see the effect
  straight away.
- **Explore metrics** (`m` on the review screen): every number in the
  report with its name and value. Pick one to turn it into a custom rule.
- **Run trends and forecasts** across several reports.
- **Customize** everything in the next section, then save (`s`).

### Customizing the analysis

Every decision the analysis makes can be changed, either in the interactive
mode or by editing a JSON settings file:

| What | Examples |
| --- | --- |
| **Thresholds** | When a wait event, slow tablespace, hard-parse rate or SQL statement becomes a warning or critical. Each threshold carries a description of what it means. |
| **Checks** | Turn whole areas on/off: efficiency ratios, wait events, CPU, parsing, SQL, bind variables, tablespace I/O, custom rules. |
| **Explanations and advice** | Rewrite the "what it means" and "what to do" text for efficiency ratios, wait events and SQL flags in your team's own words: runbook links, ticket numbers, who to call. |
| **Wait-event knowledge** | Add entries for events the tool doesn't know, or override built-in ones. Category `Idle/Network` marks an event as harmless idle time that is never flagged. |
| **SQL flags** | Rename, re-grade or switch off flags such as "Possible missing index". |
| **Custom rules** | Flag any metric, e.g. "warn when redo > 5 MB/s" or "critical when any wait event averages over 100 ms". |
| **SQL watchlist / ignore list** | SQL_IDs to always report with your note (e.g. "nightly batch, owned by payments team"), or to leave out entirely. |
| **Hidden findings** | Findings you've accepted, by ID: `wait.SQL*Net*`, `tablespace.UNDOTBS*`, `sql.fu38d0tdu45js`. Hidden findings are still counted in the report, so nothing disappears silently. |
| **Presets** | Starting points: `oltp` (default), `data_warehouse` (big scans expected; relaxed per-query I/O and parse thresholds), `strict` (SSD-era latency expectations). Your own changes stay on top of the preset. |
| **Health score weights** | Points lost per critical/warning/info finding, plus display limits. |

Settings are saved to `~/.awr_analyzer/config.json` (or `$AWR_ANALYZER_CONFIG`)
and the command line uses them automatically. The file holds only what you
changed, so improvements to the defaults still reach you:

```json
{
  "version": 1,
  "preset": "oltp",
  "thresholds": { "seq_read_ms_warning": 5, "seq_read_ms_critical": 12 },
  "suppress": ["wait.SQL*Net*"],
  "sql_watchlist": { "fu38d0tdu45js": "Recon report query - owned by payments team" },
  "custom_rules": [
    {
      "name": "slow_waits",
      "metric": "wait.*.avg_wait_ms",
      "op": ">",
      "warning": 40,
      "critical": 200,
      "title": "Slow wait: {match} ({value:.0f} ms per wait)",
      "explanation": "Our SLA needs every wait under 40 ms.",
      "recommendations": ["Raise a ticket with the storage team if it's I/O."]
    }
  ]
}
```

**Custom rules** name a metric, a comparison (`>`, `>=`, `<`, `<=`, `==`,
`!=`), and a `warning` and/or `critical` threshold. A `*` in the metric name
checks every match separately, producing one finding each. Titles,
explanations and advice can use `{value}`, `{match}` (what `*` matched,
e.g. the event name), `{threshold}`, `{severity}` and `{metric}`, with
format specs like `{value:,.0f}`. Metric names look like:

```
info.avg_active_sessions           info.aas_per_cpu
load_profile.redo_size_bytes.per_second
efficiency.buffer_hit              time_model.db_cpu.pct_db_time
wait.log file sync.avg_wait_ms     wait_class.User I/O.pct_db_time
tablespace.USERS.avg_read_time_ms  sql.fu38d0tdu45js.gets_per_exec
```

List every metric in a report with `awr-analyzer metrics report.html`
(add `--filter wait.` to narrow it down).

Command-line options for settings:

```bash
awr-analyzer analyze report.html --config team-settings.json   # a specific file
awr-analyzer analyze report.html --preset data_warehouse       # override the preset
awr-analyzer analyze report.html --no-config                   # built-in defaults only
awr-analyzer config init [path] [--preset strict]              # start a settings file
awr-analyzer config show [--effective]                         # what's changed (or everything)
awr-analyzer config validate                                   # catch mistakes in a hand-edited file
awr-analyzer config presets                                    # describe the presets
```

Reports show which settings were used ("Analysis settings: preset 'oltp',
3 customization(s) from ..."), and every finding carries a **finding ID**,
which is what you put in the hidden-findings list.

A settings file can be shared across a team (commit it next to your
runbooks) so everyone's analysis applies the same thresholds and the same
house explanations.

### Using it as a library

```python
from awr_analyzer import AnalyzerConfig, parse_awr_file, analyze, build_trend
from awr_analyzer.report import render_html

report = parse_awr_file("awrrpt.html")
config = AnalyzerConfig.load("team-settings.json")   # optional
result = analyze(report, config)

print(result.health_score)       # 0-100
for finding in result.findings:
    print(finding.severity, finding.rule_id, finding.title)

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
  rules.py      # Built-in thresholds + plain-language knowledge base (the defaults)
  config.py     # User settings: defaults + preset + overrides, load/save/validate
  custom_rules.py  # Metric naming and user-defined rules
  analyzer.py   # AWRReport + settings -> list of Findings + health score
  sql_insights.py  # Merges the "SQL ordered by ..." sections into per-query profiles + tags
  forecast.py   # Multiple AWRReports -> trend/forecast analysis
  report.py     # Findings/trend/SQL insights -> HTML / text output
  tui.py        # Interactive text interface
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
