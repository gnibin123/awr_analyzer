"""Interactive, text-based interface for awr-analyzer.

Run with ``awr-analyzer tui``. Everything is menu-driven and works in any
terminal (including over SSH and on Windows), with no extra dependencies.

From here you can analyze reports and browse the results, and customize
what the analysis looks for and what it tells you: thresholds, which checks
run, the explanation and advice attached to each kind of finding, your own
rules on any metric, a SQL watchlist, and findings to hide. Every finding
links straight to the settings that produced it, so the loop is: look at a
finding, adjust what it means for your system, re-run, save.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
import shutil
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from . import custom_rules, rules
from .analyzer import analyze
from .config import (
    CHECKS,
    DEFAULT_PRESET,
    LIMIT_SPECS,
    PRESETS,
    SEVERITIES,
    THRESHOLD_SPECS,
    THRESHOLD_SPECS_BY_KEY,
    AnalyzerConfig,
    ConfigError,
    default_config_path,
)
from .forecast import build_trend
from .parser import parse_awr_file
from .report import ranked_sql_rows, render_html, render_text


class _Quit(Exception):
    pass


_UNCHANGED = object()

_STYLES = {"bold": "1", "dim": "2", "red": "31", "green": "32", "yellow": "33",
           "blue": "34", "magenta": "35", "cyan": "36"}
_SEV_STYLE = {"critical": "red", "warning": "yellow", "info": "cyan", "good": "green"}
_DIRECTION_STYLE = {"worsening": "red", "improving": "green", "increasing": "yellow",
                    "decreasing": "cyan", "stable": "dim"}

WAIT_CATEGORIES = ["I/O", "Commit/Redo", "Locking", "Contention", "Memory/Temp", "RAC/Cluster",
                   "Idle/Network", "Other"]

HELP_TEXT = """\
How the analysis works
  The tool reads an AWR report, compares what it finds against thresholds,
  and turns anything that crosses one into a finding: a severity (critical,
  warning, info), a plain-language explanation, and recommended actions.
  The health score starts at 100 and loses points per finding (see
  "Health score weights").

What you can customize
  Thresholds       The numbers that turn a metric into a warning or critical.
  Checks           Turn whole areas of the analysis on or off.
  Explanations     Rewrite what a finding says and what it recommends, for
                   efficiency ratios, wait events and SQL flags, in your own
                   team's words.
  Custom rules     Flag anything the report contains: "warn when redo per
                   second exceeds X", "critical when any wait event averages
                   over 50 ms". Use the metric explorer to find metric names.
  Watchlist        SQL_IDs you always want to see, with a note.
  Ignore / hide    SQL_IDs to leave out, and findings you've accepted.
  Presets          Starting points for OLTP, data warehouse or strict
                   (SSD-era) systems. Your own changes stay on top.

Metric names (for custom rules)
  Every number is named like  wait.log file sync.avg_wait_ms  or
  sql.<sql_id>.gets_per_exec. A * matches anything, so  wait.*.avg_wait_ms
  checks every wait event separately. Open a report, then use the metric
  explorer (m) on the review screen to browse names and values.

Finding IDs (for hiding findings)
  Each finding has an ID such as  wait.log file sync, efficiency.buffer_hit,
  tablespace.USERS, sql.fu38d0tdu45js. Hide one exactly, or many with *,
  e.g.  tablespace.UNDOTBS*.

Saving
  Settings are saved as JSON holding only what you changed. The command
  line picks the saved file up automatically:
      awr-analyzer analyze report.html
  or point at another file with  --config path/to/config.json
"""


@dataclass
class Field:
    key: str
    label: str
    kind: str              # bool | float | optfloat | int | str | text | list | choice | regex
    help: str = ""
    choices: tuple = ()


def _friendly_escape(text: str) -> str:
    """Escape only real regex metacharacters, so patterns built from event
    names stay readable (re.escape also escapes spaces, '-' and ':')."""
    return re.sub(r"([.^$*+?()\[\]{}|\\])", r"\\\1", text)


def _num(v, digits: int = 2) -> str:
    if v is None:
        return "n/a"
    if isinstance(v, bool):
        return "yes" if v else "no"
    if isinstance(v, (int, float)):
        if float(v).is_integer():
            return f"{v:,.0f}"
        if abs(v) >= 100:
            return f"{v:,.0f}"
        return f"{v:,.{digits}f}"
    return str(v)


class TUI:
    def __init__(self, config: Optional[AnalyzerConfig] = None, config_path: Optional[str] = None,
                 input_fn: Callable[[str], str] = input, out=None, color: Optional[bool] = None):
        self.cfg = config or AnalyzerConfig()
        self.config_path = str(config_path or self.cfg.source_path or default_config_path())
        self.input_fn = input_fn
        self.out = out or sys.stdout
        if color is None:
            color = hasattr(self.out, "isatty") and self.out.isatty() and not os.environ.get("NO_COLOR")
        self.color = color
        self.width = max(60, min(110, shutil.get_terminal_size((100, 24)).columns - 2))

        self.report = None
        self.report_path: Optional[str] = None
        self.result = None
        self._result_settings: Optional[str] = None
        self.trend = None
        self.trend_result = None

    # ------------------------------------------------------------------ io

    def c(self, text: str, *styles: str) -> str:
        if not self.color or not styles:
            return text
        codes = ";".join(_STYLES[s] for s in styles if s in _STYLES)
        return f"\033[{codes}m{text}\033[0m"

    def p(self, text: str = "") -> None:
        print(text, file=self.out)

    def wrap(self, text: str, indent: int = 2) -> None:
        pad = " " * indent
        for para in (text or "").split("\n"):
            self.p(textwrap.fill(para, width=self.width, initial_indent=pad, subsequent_indent=pad) or "")

    def bullet(self, text: str, indent: int = 2) -> None:
        self.p(textwrap.fill(text or "", width=self.width, initial_indent=" " * indent + "- ",
                             subsequent_indent=" " * (indent + 2)))

    def header(self, title: str) -> None:
        self.p()
        self.p(self.c(title, "bold"))
        self.p(self.c("-" * min(len(title), self.width), "dim"))

    def hint(self, text: str) -> None:
        self.p(self.c(text, "dim"))

    def ask(self, prompt: str) -> str:
        try:
            return self.input_fn(prompt).strip()
        except (EOFError, KeyboardInterrupt):
            raise _Quit()

    def confirm(self, prompt: str, default: bool = False) -> bool:
        suffix = " [Y/n] " if default else " [y/N] "
        answer = self.ask(prompt + suffix).lower()
        if not answer:
            return default
        return answer in ("y", "yes")

    def ask_path(self, prompt: str) -> str:
        raw = self.ask(prompt)
        if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "'\"":
            raw = raw[1:-1]  # terminals add quotes when a file is dragged in
        return str(Path(raw).expanduser()) if raw else ""

    def sev(self, severity: str) -> str:
        return self.c(f"{severity.upper():<8}", _SEV_STYLE.get(severity, "dim"))

    def bad_choice(self) -> None:
        self.p(self.c("  Not one of the options — try again.", "yellow"))

    # --------------------------------------------------------------- main

    def run(self, report_path: Optional[str] = None) -> int:
        try:
            self.p(self.c("AWR Analyzer — interactive mode", "bold"))
            self.hint("Type the number or letter next to an option and press Enter. "
                      "'?' shows help, 'q' quits.")
            if report_path:
                self.load_and_analyze(report_path)
            self.main_menu()
        except _Quit:
            self.p()
            if self.cfg.dirty:
                self.p(self.c("Exited without saving your setting changes.", "yellow"))
        return 0

    def status_lines(self) -> None:
        saved = self.c("  [unsaved changes]", "yellow") if self.cfg.dirty else ""
        self.p(f"Settings: {self.cfg.summary_line()}{saved}")
        if self.report:
            i = self.report.info
            self.p(f"Report:   {Path(self.report_path).name}  ({i.db_name or '?'} / "
                   f"{i.instance_name or '?'}, {i.begin_snap_time or '?'})")
        else:
            self.p("Report:   none loaded")

    def main_menu(self) -> None:
        while True:
            self.header("Main menu")
            self.status_lines()
            self.p()
            self.p(self.c(" Analyze", "bold"))
            self.p("   1  Load and analyze an AWR report")
            self.p("   2  Review the last analysis")
            self.p("   3  Trend & forecast across several reports")
            self.p(self.c(" Customize what to look for and what it means", "bold"))
            self.p("   4  Thresholds — when a number becomes a warning or critical")
            self.p("   5  Checks — turn areas of the analysis on/off")
            self.p("   6  Efficiency ratios — thresholds and explanations")
            self.p("   7  Wait events — what each one means and what to do")
            self.p("   8  SQL flags — labels, severity and advice for problem queries")
            self.p("   9  Custom rules — flag any metric you care about")
            self.p("  10  Watchlist, ignored SQL and hidden findings")
            self.p("  11  Workload preset (OLTP / data warehouse / strict)")
            self.p("  12  Health score weights and display limits")
            self.p(self.c(" Settings", "bold"))
            self.p("   v  View your changes      s  Save      l  Load      r  Reset to defaults")
            self.p("   ?  Help                   q  Quit")
            cmd = self.ask("> ").lower()
            actions = {
                "1": self.prompt_analyze, "2": self.review_last, "3": self.trend_menu,
                "4": self.thresholds_menu, "5": self.checks_menu, "6": self.efficiency_menu,
                "7": self.wait_events_menu, "8": self.sql_tags_menu, "9": self.custom_rules_menu,
                "10": self.lists_menu, "11": self.presets_menu, "12": self.weights_menu,
                "v": self.view_changes, "s": self.save_config, "l": self.load_config,
                "r": self.reset_config, "?": self.show_help, "h": self.show_help,
            }
            if cmd in ("q", "quit", "exit"):
                if self.quit_ok():
                    return
            elif cmd in actions:
                actions[cmd]()
            elif cmd:
                self.bad_choice()

    def quit_ok(self) -> bool:
        if not self.cfg.dirty:
            return True
        answer = self.ask("You have unsaved setting changes. Save before quitting? [y]es / [n]o / [c]ancel: ").lower()
        if answer.startswith("y"):
            self.save_config()
            return not self.cfg.dirty
        return answer.startswith("n")

    def show_help(self) -> None:
        self.header("Help")
        for line in HELP_TEXT.splitlines():
            self.p(line)
        self.p(f"Your settings file: {self.config_path}")

    # ------------------------------------------------------------ analyze

    def prompt_analyze(self) -> None:
        path = self.ask_path("Path to the AWR HTML report (blank to cancel): ")
        if path:
            self.load_and_analyze(path)

    def load_and_analyze(self, path: str) -> None:
        if not Path(path).is_file():
            self.p(self.c(f"  File not found: {path}", "red"))
            return
        self.p(f"  Reading {path} ...")
        try:
            report = parse_awr_file(path)
        except Exception as exc:  # noqa: BLE001 - show any parse failure to the user
            self.p(self.c(f"  Couldn't parse that file: {exc}", "red"))
            return
        if not report.load_profile and not report.top_wait_events and not report.instance_efficiency:
            self.p(self.c("  Warning: very little AWR content was recognized — is this an AWR HTML "
                          "report from awrrpt.sql? Results may be incomplete.", "yellow"))
        self.report, self.report_path = report, path
        self.run_analysis()
        self.review_menu()

    def run_analysis(self) -> None:
        self.result = analyze(self.report, self.cfg)
        self._result_settings = self._settings_snapshot()

    def _settings_snapshot(self) -> str:
        return json.dumps(self.cfg.overrides, sort_keys=True, default=str)

    def review_last(self) -> None:
        if not self.result:
            self.p("  No report analyzed yet — choose 1 first.")
            return
        self.review_menu()

    def _refresh_if_settings_changed(self) -> None:
        if self.report and self._result_settings != self._settings_snapshot():
            self.run_analysis()
            self.p(self.c("  (Re-ran the analysis with your updated settings.)", "green"))

    def review_menu(self) -> None:
        while True:
            self._refresh_if_settings_changed()
            r = self.result
            counts = r.counts()
            self.header(f"Analysis of {Path(self.report_path).name}")
            score_style = "green" if r.health_score >= 80 else ("yellow" if r.health_score >= 50 else "red")
            hidden = f" — {len(r.suppressed)} hidden by your settings" if r.suppressed else ""
            self.p(f"Health score {self.c(str(r.health_score), 'bold', score_style)}/100   "
                   f"critical {counts['critical']} · warning {counts['warning']} · info {counts['info']}{hidden}")
            self.wrap(r.summary, indent=0)
            self.p()
            for i, f in enumerate(r.findings, 1):
                self.p(f"  {i:>2}  {self.sev(f.severity)} {self.c(f'{f.category:<12}', 'dim')}  {f.title}")
            self.p()
            n_sql = len(r.sql_insights.problematic()) if r.sql_insights else 0
            self.hint(f"number = finding details · q = problematic queries ({n_sql}) · "
                      f"w = watched queries ({len(r.watched_sql)})")
            self.hint("m = metric explorer · x = export report · r = re-run · b = back")
            cmd = self.ask("> ").lower()
            if cmd in ("b", ""):
                return
            if cmd == "q":
                self.queries_menu()
            elif cmd == "w":
                self.watched_view()
            elif cmd == "m":
                self.metric_explorer()
            elif cmd == "x":
                self.export(self.result)
            elif cmd == "r":
                self.run_analysis()
                self.p(self.c("  Re-ran the analysis.", "green"))
            elif cmd.isdigit() and 1 <= int(cmd) <= len(r.findings):
                self.finding_detail(r.findings[int(cmd) - 1])
            else:
                self.bad_choice()

    def finding_detail(self, f) -> None:
        while True:
            self.header(f.title)
            self.p(f"Severity: {self.sev(f.severity)}  Category: {f.category}  ID: {f.rule_id or 'n/a'}")
            self.p()
            self.p(self.c("What it means", "bold"))
            self.wrap(f.plain_explanation)
            if f.recommendations:
                self.p()
                self.p(self.c("What to do", "bold"))
                for rec in f.recommendations:
                    self.bullet(f"{rec}")
            self.p()
            self.p(self.c("Technical detail", "bold"))
            self.wrap(f.technical_detail)
            self.p()
            self.hint("c = customize the check behind this finding · h = hide findings like this · b = back")
            cmd = self.ask("> ").lower()
            if cmd in ("b", ""):
                return
            if cmd == "c":
                self.customize_for_finding(f)
                return
            if cmd == "h":
                self.hide_finding(f)
                return
            self.bad_choice()

    def hide_finding(self, f) -> None:
        if not f.rule_id:
            self.p("  This finding has no ID, so it can't be hidden.")
            return
        prefix = f.rule_id.split(".", 1)[0]
        options = [f.rule_id, f"{prefix}.*"]
        self.p("  Hide which findings?")
        self.p(f"   1  Just this one          ({options[0]})")
        self.p(f"   2  Every '{prefix}' finding  ({options[1]})")
        self.p("   3  Type my own pattern")
        cmd = self.ask("> ")
        if cmd == "1":
            pattern = options[0]
        elif cmd == "2":
            pattern = options[1]
        elif cmd == "3":
            pattern = self.ask("Pattern (* matches anything): ")
        else:
            return
        if pattern:
            self._add_to_list(("suppress",), pattern)
            self.p(self.c(f"  Hidden: {pattern}. Undo it under main menu 10 → Hidden findings.", "green"))

    def customize_for_finding(self, f) -> None:
        kind, _, rest = (f.rule_id or "").partition(".")
        if kind == "efficiency":
            self.edit_efficiency(rest)
        elif kind == "wait":
            self.p("   1  Change the thresholds for wait events")
            self.p(f"   2  Change what '{rest}' means and what to do about it")
            cmd = self.ask("> ")
            if cmd == "1":
                self.threshold_group("Wait events")
            elif cmd == "2":
                self.customize_wait_event(rest)
        elif kind == "sql" and rest == "bind_variables":
            self.threshold_group("SQL")
        elif kind == "sql":
            self.p("   1  Change the thresholds for SQL flags")
            self.p("   2  Change the labels/advice of SQL flags")
            self.p(f"   3  Add {rest} to the watchlist (with a note)")
            self.p(f"   4  Ignore {rest} in future analyses")
            cmd = self.ask("> ")
            if cmd == "1":
                self.threshold_group("SQL")
            elif cmd == "2":
                self.sql_tags_menu()
            elif cmd == "3":
                self.add_watch(rest)
            elif cmd == "4":
                self._add_to_list(("sql_ignore",), rest)
                self.p(self.c(f"  {rest} will be left out of the query analysis.", "green"))
        elif kind == "tablespace":
            self.threshold_group("Tablespace I/O")
        elif kind == "cpu":
            self.threshold_group("CPU")
        elif kind == "parse":
            self.threshold_group("Parsing")
        elif kind == "custom":
            rules_list = self.cfg.custom_rules()
            for i, rule in enumerate(rules_list):
                name = rule.get("name", "")
                if rest == name or rest.startswith(name + "."):
                    self.rule_screen(i)
                    return
            self.p("  Couldn't find that custom rule any more.")
        else:
            self.p("  There's nothing specific to customize for this finding.")

    # ------------------------------------------------------- query views

    def queries_menu(self) -> None:
        sa = self.result.sql_insights
        if not sa or not sa.insights:
            self.p("  No SQL sections were found in this report.")
            return
        while True:
            rows = ranked_sql_rows(sa, self.cfg.limit("max_sql_table_rows"))
            self.header(f"Problematic queries ({len(rows)} of {len(sa.insights)} profiled)")
            self.p(f"  {'#':>2}  {'SQL ID':<14} {'%DB':>6} {'Execs':>10} {'s/exec':>9} "
                   f"{'%CPU/%IO':>9} {'gets/exec':>10}  Flags")
            for i, q in enumerate(rows, 1):
                cpu_io = f"{_num(q.pct_cpu, 0)}/{_num(q.pct_io, 0)}"
                flags = ", ".join(q.tag_labels) or "—"
                self.p(f"  {i:>2}  {q.sql_id:<14} {_num(q.pct_elapsed, 1):>6} {_num(q.executions):>10} "
                       f"{_num(q.per_exec_s, 3):>9} {cpu_io:>9} {_num(q.gets_per_exec):>10}  "
                       f"{self.c(flags, _SEV_STYLE.get(q.severity, 'dim'))}")
            if sa.bind_variable_suspects:
                self.p()
                self.p(self.c("  Possible missing bind variables:", "bold"))
                for g in sa.bind_variable_suspects[:5]:
                    self.p(f"   - {len(g.sql_ids)} statements look identical apart from literal values: "
                           f"{', '.join(g.sql_ids[:5])}")
            self.p()
            self.hint("number = query details · b = back")
            cmd = self.ask("> ").lower()
            if cmd in ("b", ""):
                return
            if cmd.isdigit() and 1 <= int(cmd) <= len(rows):
                self.query_detail(rows[int(cmd) - 1])
            else:
                self.bad_choice()

    def query_detail(self, q) -> None:
        while True:
            self.header(f"SQL {q.sql_id}")
            self.p(f"Module: {q.module or 'n/a'}    Seen in: {', '.join(q.seen_in)}")
            self.wrap(f"Text: {(q.sql_text or 'n/a').strip()}", indent=0)
            self.p()
            pairs = [
                ("% of DB time", q.pct_elapsed), ("Elapsed (s)", q.elapsed_s), ("Executions", q.executions),
                ("Seconds per execution", q.per_exec_s), ("CPU (s)", q.cpu_s), ("% CPU", q.pct_cpu),
                ("% I/O", q.pct_io), ("Buffer gets", q.gets), ("Gets per execution", q.gets_per_exec),
                ("Physical reads", q.reads), ("Reads per execution", q.reads_per_exec),
                ("Rows processed", q.rows_processed), ("Rows per execution", q.rows_per_exec),
            ]
            for label, value in pairs:
                if value is not None:
                    self.p(f"  {label:<24} {_num(value)}")
            if q.tags:
                self.p()
                self.p(self.c(f"Flags: {', '.join(q.tag_labels)}  ({q.severity})", "bold"))
                for note in q.notes:
                    self.bullet(f"{note}")
                if q.recommendations:
                    self.p(self.c("What to do", "bold"))
                    for rec in q.recommendations:
                        self.bullet(f"{rec}")
            note = self.cfg.watchlist().get(q.sql_id)
            if note:
                self.p(self.c(f"Your note: {note}", "magenta"))
            self.p()
            self.hint("w = add to watchlist / edit note · i = ignore this SQL_ID · b = back")
            cmd = self.ask("> ").lower()
            if cmd in ("b", ""):
                return
            if cmd == "w":
                self.add_watch(q.sql_id)
            elif cmd == "i":
                self._add_to_list(("sql_ignore",), q.sql_id)
                self.p(self.c(f"  {q.sql_id} will be left out from now on.", "green"))
                return
            else:
                self.bad_choice()

    def watched_view(self) -> None:
        self.header("Watched queries")
        if not self.result.watched_sql:
            self.p("  Your watchlist is empty. Add statements from a query's detail screen, or under main menu 10.")
            return
        for w in self.result.watched_sql:
            self.p(f"  {self.c(w.sql_id, 'bold')}  {w.note}")
            q = w.insight
            if q is None:
                self.p("    not in this report's top SQL lists")
            else:
                self.p(f"    {_num(q.pct_elapsed, 1)}% of DB time, {_num(q.executions)} executions, "
                       f"{_num(q.per_exec_s, 3)} s/exec, flags: {', '.join(q.tag_labels) or 'none'}")

    def add_watch(self, sql_id: str) -> None:
        current = self.cfg.watchlist().get(sql_id, "")
        note = self.ask(f"Note for {sql_id} (what it is, who owns it){' [' + current + ']' if current else ''}: ")
        self.cfg.set(("sql_watchlist", sql_id), note or current)
        self.p(self.c(f"  {sql_id} is on your watchlist.", "green"))

    # --------------------------------------------------- metric explorer

    def metric_explorer(self) -> None:
        if not self.report:
            self.p("  Load a report first (main menu 1) — the explorer lists the metrics it contains.")
            return
        metrics = custom_rules.flatten_metrics(self.report, self.result.sql_insights if self.result else None)
        names = sorted(metrics)
        filt = ""
        while True:
            matches = [n for n in names if filt.lower() in n.lower()]
            self.header(f"Metric explorer — {len(matches)} of {len(names)} metrics"
                        + (f" containing '{filt}'" if filt else ""))
            shown = matches[:40]
            for i, name in enumerate(shown, 1):
                self.p(f"  {i:>2}  {name:<62} {_num(metrics[name])}")
            if len(matches) > len(shown):
                self.hint(f"  ... {len(matches) - len(shown)} more; narrow it down with f")
            self.p()
            self.hint("f = filter (e.g. 'wait.', 'redo', 'sql.') · number = make a custom rule from it · b = back")
            cmd = self.ask("> ")
            if cmd.lower() in ("b", ""):
                return
            if cmd.lower() == "f":
                filt = self.ask("Show metrics containing: ")
            elif cmd.isdigit() and 1 <= int(cmd) <= len(shown):
                self.add_rule(prefill_metric=shown[int(cmd) - 1])
            else:
                filt = cmd  # typing text directly filters too

    # --------------------------------------------------------------- export

    def export(self, result, trend=None) -> None:
        fmt = (self.ask("Format: [h]tml, [t]ext or [j]son? [h] ").lower() or "h")[0]
        ext = {"h": "html", "t": "txt", "j": "json"}.get(fmt)
        if not ext:
            self.bad_choice()
            return
        stem = Path(self.report_path).with_suffix("") if self.report_path else Path("awr")
        default = f"{stem}_{'trend' if trend else 'analysis'}.{ext}"
        path = self.ask_path(f"Save to [{default}]: ") or default
        if ext == "html":
            content = render_html(result, trend=trend)
        elif ext == "txt":
            content = render_text(result, trend=trend)
        else:
            payload = dataclasses.asdict(result)
            if trend:
                payload = {"analysis": payload, "trend": dataclasses.asdict(trend)}
            content = json.dumps(payload, indent=2, default=str)
        try:
            Path(path).write_text(content, encoding="utf-8")
        except OSError as exc:
            self.p(self.c(f"  Couldn't write {path}: {exc}", "red"))
            return
        self.p(self.c(f"  Wrote {Path(path).resolve()}", "green"))

    # ---------------------------------------------------------------- trend

    def trend_menu(self) -> None:
        self.header("Trend & forecast")
        self.wrap("Give two or more AWR reports for the same database, oldest first (e.g. the same "
                  "hour on consecutive days). Enter one path per line and a blank line when done.", indent=0)
        paths = []
        while True:
            path = self.ask_path(f"Report {len(paths) + 1}: ")
            if not path:
                break
            if not Path(path).is_file():
                self.p(self.c(f"  File not found: {path}", "red"))
                continue
            paths.append(path)
        if len(paths) < 2:
            self.p("  Need at least two reports for a trend.")
            return
        try:
            reports = [parse_awr_file(p) for p in paths]
        except Exception as exc:  # noqa: BLE001
            self.p(self.c(f"  Couldn't parse one of the files: {exc}", "red"))
            return
        self.trend = build_trend(reports, self.cfg)
        self.trend_result = analyze(reports[-1], self.cfg)
        self.report, self.report_path = reports[-1], paths[-1]
        self.result = self.trend_result
        self._result_settings = self._settings_snapshot()
        self.trend_view()

    def trend_view(self) -> None:
        while True:
            t = self.trend
            self.header(f"Trend across {len(t.labels)} reports")
            self.p(f"  {', '.join(t.labels)}")
            self.p()
            for r in t.results:
                pct = f"{r.pct_change:+.1f}%" if r.pct_change is not None else "n/a"
                direction = self.c(f"{r.direction:<10}", _DIRECTION_STYLE.get(r.direction, "dim"))
                self.p(f"  {r.label:<38} {_num(r.first_value):>12} → {_num(r.last_value):<12} {pct:>8}  {direction}")
            risks = [r for r in t.results if r.forecast_note]
            if risks:
                self.p()
                self.p(self.c("Early warnings", "bold"))
                for r in risks:
                    self.bullet(f"{r.label}: {r.forecast_note}")
            self.p()
            self.hint("a = review the analysis of the newest report · x = export · b = back")
            cmd = self.ask("> ").lower()
            if cmd in ("b", ""):
                return
            if cmd == "a":
                self.review_menu()
            elif cmd == "x":
                self.export(self.trend_result, trend=self.trend)
            else:
                self.bad_choice()

    # ------------------------------------------------- generic editors

    def _value_text(self, value, kind: str) -> str:
        if kind == "bool":
            return self.c("on", "green") if value else self.c("off", "dim")
        if kind == "list":
            return f"{len(value or [])} item(s)"
        if kind == "text":
            text = (value or "").replace("\n", " ")
            return (text[:60] + "...") if len(text) > 60 else (text or "—")
        if kind in ("float", "optfloat", "int"):
            return _num(value) if value is not None else "—"
        return str(value) if value not in (None, "") else "—"

    def edit_value(self, field: Field, current):
        if field.kind == "bool":
            return not bool(current)
        if field.help:
            self.wrap(field.help)
        if field.kind in ("float", "optfloat", "int"):
            clear = " · '-' = none" if field.kind == "optfloat" else ""
            raw = self.ask(f"{field.label} [{_num(current) if current is not None else '—'}] "
                           f"(blank = keep{clear}): ")
            if not raw:
                return _UNCHANGED
            if raw == "-" and field.kind == "optfloat":
                return None
            try:
                value = float(raw.replace(",", "").replace("_", ""))
            except ValueError:
                self.p(self.c("  That's not a number.", "red"))
                return _UNCHANGED
            return int(value) if field.kind == "int" else value
        if field.kind == "choice":
            for i, choice in enumerate(field.choices, 1):
                marker = " (current)" if choice == current else ""
                self.p(f"   {i}  {choice}{marker}")
            raw = self.ask("Choose (number, or type a value; blank = keep): ")
            if not raw:
                return _UNCHANGED
            if raw.isdigit() and 1 <= int(raw) <= len(field.choices):
                return field.choices[int(raw) - 1]
            return raw
        if field.kind == "list":
            new = self.edit_list(field.label, current or [])
            return _UNCHANGED if new == (current or []) else new
        if field.kind == "text":
            self.p(self.c("  Current:", "dim"))
            self.wrap(current or "—", indent=4)
        raw = self.ask(f"{field.label}{'' if field.kind == 'text' else ' [' + str(current or '') + ']'} "
                       f"(blank = keep): ")
        if not raw:
            return _UNCHANGED
        if field.kind == "regex":
            try:
                re.compile(raw)
            except re.error as exc:
                self.p(self.c(f"  Not a valid pattern: {exc}", "red"))
                return _UNCHANGED
        return raw

    def edit_record(self, title: str, record: dict, fields: list, commit: Callable[[dict, str], Optional[str]],
                    reset: Optional[Callable[[str], object]] = None, intro: str = "",
                    extra: Optional[dict] = None) -> None:
        """Generic field editor. ``commit(record, key)`` persists one change
        and may return a warning; ``reset(key)`` restores a default and
        returns it; ``extra`` maps extra command letters to (label, fn)."""
        extra = extra or {}
        while True:
            self.header(title)
            if intro:
                self.wrap(intro, indent=0)
                self.p()
            for i, f in enumerate(fields, 1):
                self.p(f"  {i:>2}  {f.label:<26} {self._value_text(record.get(f.key), f.kind)}")
            self.p()
            parts = ["number = change"]
            if reset:
                parts.append("d<number> = back to default")
            parts += [f"{k} = {label}" for k, (label, _fn) in extra.items()]
            parts.append("b = back")
            self.hint(" · ".join(parts))
            cmd = self.ask("> ").lower()
            if cmd in ("b", ""):
                return
            if cmd in extra:
                if extra[cmd][1]() is False:
                    return
                continue
            m = re.fullmatch(r"d(\d+)", cmd)
            if m and reset and 1 <= int(m.group(1)) <= len(fields):
                key = fields[int(m.group(1)) - 1].key
                record[key] = reset(key)
                continue
            if cmd.isdigit() and 1 <= int(cmd) <= len(fields):
                f = fields[int(cmd) - 1]
                value = self.edit_value(f, record.get(f.key))
                if value is _UNCHANGED:
                    continue
                record[f.key] = value
                warning = commit(record, f.key)
                if warning:
                    self.p(self.c(f"  Note: {warning}", "yellow"))
                continue
            self.bad_choice()

    def edit_list(self, title: str, items: list) -> list:
        items = list(items)
        while True:
            self.p(self.c(f"  {title}:", "bold"))
            if not items:
                self.p("    (empty)")
            for i, item in enumerate(items, 1):
                self.wrap(f"{i:>2}. {item}", indent=4)
            self.hint("  a = add · e<n> = edit · d<n> = delete · c = clear · b = done")
            cmd = self.ask("> ").lower()
            if cmd in ("b", ""):
                return items
            if cmd == "a":
                text = self.ask("New line: ")
                if text:
                    items.append(text)
            elif cmd == "c":
                items = []
            elif re.fullmatch(r"[ed]\d+", cmd) and 1 <= int(cmd[1:]) <= len(items):
                idx = int(cmd[1:]) - 1
                if cmd[0] == "d":
                    items.pop(idx)
                else:
                    text = self.ask("Replace with (blank = keep): ")
                    if text:
                        items[idx] = text
            else:
                self.bad_choice()

    def _add_to_list(self, path: tuple, value: str) -> None:
        items = list(self.cfg.get(path, []) or [])
        if value not in items:
            items.append(value)
            self.cfg.set(path, items)

    def _path_committer(self, prefix: tuple):
        def commit(record, key):
            self.cfg.set(prefix + (key,), record[key])
            return None
        return commit

    def _path_resetter(self, prefix: tuple):
        def reset(key):
            self.cfg.unset(prefix + (key,))
            return self.cfg.get(prefix + (key,))
        return reset

    # ---------------------------------------------------------- thresholds

    def thresholds_menu(self) -> None:
        groups = []
        for spec in THRESHOLD_SPECS:
            if spec.group not in groups:
                groups.append(spec.group)
        while True:
            self.header("Thresholds")
            self.wrap("Thresholds decide when a number becomes a finding. Pick an area to see each "
                      "threshold, what it means, and its current and default value.", indent=0)
            for i, g in enumerate(groups, 1):
                specs = [s for s in THRESHOLD_SPECS if s.group == g]
                changed = sum(1 for s in specs if self.cfg.is_overridden(("thresholds", s.key)))
                note = self.c(f"  ({changed} changed)", "magenta") if changed else ""
                self.p(f"  {i:>2}  {g:<16} {len(specs)} thresholds{note}")
            self.p()
            self.hint("number = open · b = back   (efficiency ratios have their own screen: main menu 6)")
            cmd = self.ask("> ").lower()
            if cmd in ("b", ""):
                return
            if cmd.isdigit() and 1 <= int(cmd) <= len(groups):
                self.threshold_group(groups[int(cmd) - 1])
            else:
                self.bad_choice()

    def threshold_group(self, group: str) -> None:
        specs = [s for s in THRESHOLD_SPECS if s.group == group]
        base = self.cfg.base()["thresholds"]
        while True:
            self.header(f"Thresholds — {group}")
            for i, s in enumerate(specs, 1):
                value = self.cfg.threshold(s.key)
                mark = self.c(" *", "magenta") if self.cfg.is_overridden(("thresholds", s.key)) else ""
                self.p(f"  {i:>2}  {_num(value):>12} {s.unit:<20} {s.key}{mark}")
                self.hint(f"        {s.description}")
            self.p()
            self.hint("number = change · d<number> = back to default · b = back   (* = changed by you)")
            cmd = self.ask("> ").lower()
            if cmd in ("b", ""):
                return
            m = re.fullmatch(r"d(\d+)", cmd)
            if m and 1 <= int(m.group(1)) <= len(specs):
                self.cfg.unset(("thresholds", specs[int(m.group(1)) - 1].key))
                continue
            if cmd.isdigit() and 1 <= int(cmd) <= len(specs):
                s = specs[int(cmd) - 1]
                self.wrap(f"{s.key}: {s.description}")
                self.hint(f"  default: {_num(base.get(s.key, s.default))} {s.unit}")
                value = self.edit_value(Field(s.key, s.key, "float"), self.cfg.threshold(s.key))
                if value is _UNCHANGED:
                    continue
                if value < 0:
                    self.p(self.c("  Thresholds can't be negative.", "red"))
                    continue
                self.cfg.set(("thresholds", s.key), value)
                for level, msg in self.cfg.validate():
                    if s.key in msg:
                        self.p(self.c(f"  Note: {msg}", "yellow"))
                continue
            self.bad_choice()

    # -------------------------------------------------------------- checks

    def checks_menu(self) -> None:
        names = list(CHECKS)
        while True:
            self.header("Checks")
            self.wrap("Turn whole areas of the analysis on or off. A check that's off produces no "
                      "findings at all.", indent=0)
            for i, name in enumerate(names, 1):
                on = self.cfg.check_enabled(name)
                box = self.c("[on] ", "green") if on else self.c("[off]", "dim")
                self.p(f"  {i:>2}  {box} {name:<15} {CHECKS[name]}")
            self.p()
            self.hint("number = switch on/off · b = back")
            cmd = self.ask("> ").lower()
            if cmd in ("b", ""):
                return
            if cmd.isdigit() and 1 <= int(cmd) <= len(names):
                name = names[int(cmd) - 1]
                self.cfg.set(("checks", name), not self.cfg.check_enabled(name))
            else:
                self.bad_choice()

    # ---------------------------------------------------------- efficiency

    def efficiency_menu(self) -> None:
        while True:
            eff = self.cfg.efficiency()
            keys = list(eff)
            self.header("Efficiency ratios")
            self.wrap("Percentages where higher is better. A value below 'warning' is flagged as a "
                      "warning, below 'critical' as critical.", indent=0)
            for i, key in enumerate(keys, 1):
                e = eff[key]
                state = "" if e.get("enabled", True) else self.c(" (off)", "dim")
                mark = self.c(" *", "magenta") if self.cfg.is_overridden(("efficiency", key)) else ""
                self.p(f"  {i:>2}  {e.get('label', key):<28} warn < {_num(e['warning']):>5}  "
                       f"crit < {_num(e['critical']):>5}{state}{mark}")
            self.p()
            self.hint("number = edit thresholds, explanation and advice · b = back")
            cmd = self.ask("> ").lower()
            if cmd in ("b", ""):
                return
            if cmd.isdigit() and 1 <= int(cmd) <= len(keys):
                self.edit_efficiency(keys[int(cmd) - 1])
            else:
                self.bad_choice()

    def edit_efficiency(self, key: str) -> None:
        if key not in self.cfg.efficiency():
            self.p("  Unknown efficiency metric.")
            return
        prefix = ("efficiency", key)
        record = dict(self.cfg.efficiency()[key])
        fields = [
            Field("enabled", "Check enabled", "bool"),
            Field("warning", "Warning below (%)", "float", "Values below this are flagged as a warning."),
            Field("critical", "Critical below (%)", "float", "Values below this are flagged as critical."),
            Field("label", "Display name", "str"),
            Field("explanation", "What it means", "text",
                  "The plain-language explanation shown with the finding."),
            Field("recommendations", "What to do", "list"),
        ]
        self.edit_record(f"Efficiency ratio: {record.get('label', key)}", record, fields,
                         self._path_committer(prefix), self._path_resetter(prefix))

    # --------------------------------------------------------- wait events

    def _custom_wait_entries(self) -> list:
        return [dict(e) for e in self.cfg.get(("wait_events", "custom"), []) or []]

    def _save_custom_wait_entries(self, entries: list) -> None:
        self.cfg.set(("wait_events", "custom"), entries)

    def wait_events_menu(self) -> None:
        while True:
            self.header("Wait events — what they mean and what to do")
            self.wrap("When a wait event takes a big share of DB time, the finding explains it using "
                      "the first entry whose pattern matches the event name. Your own entries are "
                      "checked first, so they override the built-in text. Give an event the category "
                      "'Idle/Network' to treat it as harmless idle time that is never flagged.",
                      indent=0)
            self.p()
            self.p(f"   1  Your entries ({len(self._custom_wait_entries())})")
            self.p(f"   2  Built-in explanations ({len(rules.WAIT_EVENT_KB)}) — copy one to customize it")
            self.p("   3  Add an entry for a wait event")
            self.p("   4  Test: which explanation applies to an event name?")
            self.p("   5  Thresholds for wait events")
            self.hint("b = back")
            cmd = self.ask("> ").lower()
            if cmd in ("b", ""):
                return
            if cmd == "1":
                self.custom_wait_list()
            elif cmd == "2":
                self.builtin_wait_list()
            elif cmd == "3":
                name = self.ask("Wait event name, as it appears in the report (e.g. 'gc cr multi block request'): ")
                if name:
                    self.customize_wait_event(name)
            elif cmd == "4":
                name = self.ask("Event name: ")
                if name:
                    info = self.cfg.lookup_wait_event(name)
                    source = next((src for pat, inf, src in self.cfg.wait_event_kb() if pat.search(name)), None)
                    if info:
                        self.p(f"  Matches a {source} entry — category {info['category']}:")
                        self.wrap(info["plain"], indent=4)
                    else:
                        self.p("  No entry matches; findings for it will use generic advice.")
            elif cmd == "5":
                self.threshold_group("Wait events")
            else:
                self.bad_choice()

    def custom_wait_list(self) -> None:
        while True:
            entries = self._custom_wait_entries()
            self.header("Your wait-event entries")
            if not entries:
                self.p("  None yet. Add one from the previous screen, or customize a built-in one.")
            for i, e in enumerate(entries, 1):
                self.p(f"  {i:>2}  {e.get('pattern', ''):<40} [{e.get('category', 'Other')}]")
            self.p()
            self.hint("number = edit · d<number> = delete · b = back")
            cmd = self.ask("> ").lower()
            if cmd in ("b", ""):
                return
            m = re.fullmatch(r"d(\d+)", cmd)
            if m and 1 <= int(m.group(1)) <= len(entries):
                entries.pop(int(m.group(1)) - 1)
                self._save_custom_wait_entries(entries)
            elif cmd.isdigit() and 1 <= int(cmd) <= len(entries):
                self.edit_wait_entry(int(cmd) - 1)
            else:
                self.bad_choice()

    def builtin_wait_list(self) -> None:
        while True:
            self.header("Built-in wait-event explanations")
            for i, (pattern, info) in enumerate(rules.WAIT_EVENT_KB, 1):
                self.p(f"  {i:>2}  {pattern:<52} [{info['category']}]")
            self.p()
            self.hint("number = view and customize · b = back")
            cmd = self.ask("> ").lower()
            if cmd in ("b", ""):
                return
            if cmd.isdigit() and 1 <= int(cmd) <= len(rules.WAIT_EVENT_KB):
                pattern, info = rules.WAIT_EVENT_KB[int(cmd) - 1]
                self.header(pattern)
                self.p(f"Category: {info['category']}")
                self.wrap(info["plain"])
                for rec in info["recommendations"]:
                    self.bullet(f"{rec}")
                if self.confirm("Make your own copy to edit?"):
                    entries = self._custom_wait_entries()
                    entries.append({"pattern": pattern, "category": info["category"],
                                    "plain": info["plain"], "recommendations": list(info["recommendations"])})
                    self._save_custom_wait_entries(entries)
                    self.edit_wait_entry(len(entries) - 1)
            else:
                self.bad_choice()

    def customize_wait_event(self, event_name: str) -> None:
        entries = self._custom_wait_entries()
        for i, e in enumerate(entries):
            try:
                if re.search(e.get("pattern", ""), event_name, re.I):
                    self.edit_wait_entry(i)
                    return
            except re.error:
                continue
        info = self.cfg.lookup_wait_event(event_name) or {}
        entries.append({
            "pattern": "^" + _friendly_escape(event_name),
            "category": info.get("category", "Other"),
            "plain": info.get("plain", ""),
            "recommendations": list(info.get("recommendations", [])),
        })
        self._save_custom_wait_entries(entries)
        self.p(self.c(f"  Created your own entry for '{event_name}', starting from the current text.", "green"))
        self.edit_wait_entry(len(entries) - 1)

    def edit_wait_entry(self, index: int) -> None:
        entries = self._custom_wait_entries()
        record = entries[index]
        fields = [
            Field("pattern", "Matches event names", "regex",
                  "A regular expression matched against the event name, ignoring case. "
                  "'^log file sync' matches events starting with 'log file sync'; "
                  "'^enq: TX' matches every TX enqueue event."),
            Field("category", "Category", "choice",
                  "'Idle/Network' means harmless idle time: the event is never flagged.",
                  choices=tuple(WAIT_CATEGORIES)),
            Field("plain", "What it means", "text"),
            Field("recommendations", "What to do", "list"),
        ]

        def commit(rec, key):
            current = self._custom_wait_entries()
            current[index] = rec
            self._save_custom_wait_entries(current)

        self.edit_record(f"Wait-event entry: {record.get('pattern')}", record, fields, commit)

    # ------------------------------------------------------------ SQL tags

    def sql_tags_menu(self) -> None:
        tags = list(self.cfg.effective["sql_tags"])
        while True:
            self.header("SQL flags")
            self.wrap("Each problem query gets one or more flags. Change a flag's name, severity, "
                      "explanation and advice, or switch it off. The numbers that trigger each flag "
                      "are under Thresholds → SQL.", indent=0)
            for i, tag in enumerate(tags, 1):
                t = self.cfg.sql_tag(tag)
                state = "" if t.get("enabled", True) else self.c(" (off)", "dim")
                mark = self.c(" *", "magenta") if self.cfg.is_overridden(("sql_tags", tag)) else ""
                self.p(f"  {i:>2}  {t.get('label', tag):<30} {self.sev(t.get('severity', 'info'))}{state}{mark}")
            self.p()
            self.hint("number = edit · t = SQL thresholds · b = back")
            cmd = self.ask("> ").lower()
            if cmd in ("b", ""):
                return
            if cmd == "t":
                self.threshold_group("SQL")
            elif cmd.isdigit() and 1 <= int(cmd) <= len(tags):
                tag = tags[int(cmd) - 1]
                prefix = ("sql_tags", tag)
                record = dict(self.cfg.sql_tag(tag))
                tiered = tag in ("missing_index_suspect", "physical_read_heavy",
                                 "low_selectivity_suspect", "high_impact")
                fields = [
                    Field("enabled", "Flag enabled", "bool"),
                    Field("label", "Display name", "str"),
                    Field("severity", "Severity", "choice",
                          "For this flag, this is the severity below the critical threshold; above "
                          "it the flag is always critical." if tiered else "",
                          choices=SEVERITIES),
                    Field("plain", "What it means", "text"),
                    Field("recommendations", "What to do", "list"),
                ]
                self.edit_record(f"SQL flag: {record.get('label', tag)}", record, fields,
                                 self._path_committer(prefix), self._path_resetter(prefix))
            else:
                self.bad_choice()

    # -------------------------------------------------------- custom rules

    def _rules(self) -> list:
        return [dict(r) for r in self.cfg.custom_rules()]

    def _save_rules(self, rules_list: list) -> None:
        self.cfg.set(("custom_rules",), rules_list)

    def custom_rules_menu(self) -> None:
        while True:
            rules_list = self._rules()
            self.header("Custom rules")
            self.wrap("Your own checks on any number in the report: pick a metric, say when it's a "
                      "warning or critical, and write what it means and what to do. Use * in the "
                      "metric name to check many at once (e.g. every wait event).", indent=0)
            self.p()
            if not rules_list:
                self.p("  No custom rules yet.")
            for i, r in enumerate(rules_list, 1):
                state = self.c("on ", "green") if r.get("enabled", True) else self.c("off", "dim")
                bad = self.c("  (invalid)", "red") if custom_rules.validate_rule(r) else ""
                self.p(f"  {i:>2}  {state} {r.get('name', '?'):<22} {r.get('metric', '')} "
                       f"{r.get('op', '>')} warn {_num(r.get('warning'))} / crit {_num(r.get('critical'))}{bad}")
            self.p()
            self.hint("a = add a rule · e = examples · number = open · b = back")
            cmd = self.ask("> ").lower()
            if cmd in ("b", ""):
                return
            if cmd == "a":
                self.add_rule()
            elif cmd == "e":
                self.rule_examples()
            elif cmd.isdigit() and 1 <= int(cmd) <= len(rules_list):
                self.rule_screen(int(cmd) - 1)
            else:
                self.bad_choice()

    def rule_examples(self) -> None:
        self.header("Custom rule examples")
        examples = [
            ("Any wait event averaging over 20 ms (one finding per event)",
             "wait.*.avg_wait_ms  >  warning 20  critical 100"),
            ("Redo generation above 5 MB/s", "load_profile.redo_size_bytes.per_second  >  warning 5000000"),
            ("More active sessions than CPUs", "info.aas_per_cpu  >  warning 0.8  critical 1.0"),
            ("Any statement doing over 1M buffer gets per execution",
             "sql.*.gets_per_exec  >  warning 1000000"),
            ("Undo tablespace reads slower than 10 ms", "tablespace.UNDOTBS*.avg_read_time_ms  >  warning 10"),
            ("Buffer cache hit ratio below 99% (stricter than default)", "efficiency.buffer_hit  <  warning 99"),
        ]
        for title, rule in examples:
            self.p(f"  - {title}")
            self.p(self.c(f"      {rule}", "cyan"))
        self.p()
        self.wrap("In a rule's title, explanation and advice you can use {value}, {match} (what * "
                  "matched, e.g. the event name), {threshold}, {severity} and {metric}. Format "
                  "numbers like {value:,.0f} or {value:.1f}.", indent=0)

    def add_rule(self, prefill_metric: Optional[str] = None) -> None:
        self.header("New custom rule")
        metric = prefill_metric
        if metric:
            parts = metric.split(".")
            if len(parts) >= 3 and parts[0] in ("wait", "sql", "tablespace", "wait_class", "time_model"):
                general = ".".join([parts[0], "*", parts[-1]])
                self.p(f"   1  Just this metric:         {metric}")
                self.p(f"   2  The same for every item:  {general}")
                if self.ask("Which? [1] ") == "2":
                    metric = general
        else:
            self.wrap("Metric to check — e.g. 'wait.*.avg_wait_ms' or 'load_profile.redo_size_bytes.per_second'. "
                      "Tip: open a report and use the metric explorer (m) on the review screen to "
                      "browse every metric name with its current value.", indent=0)
            metric = self.ask("Metric: ")
            if not metric:
                return
        op = self.ask("Flag when the value is  >  >=  <  <=  ==  !=   [>] ") or ">"
        warning = self.edit_value(Field("warning", "Warning threshold", "optfloat"), None)
        critical = self.edit_value(Field("critical", "Critical threshold", "optfloat"), None)
        warning = None if warning is _UNCHANGED else warning
        critical = None if critical is _UNCHANGED else critical
        default_name = re.sub(r"[^A-Za-z0-9_]+", "_", metric.replace("*", "any")).strip("_")[:40] or "rule"
        name = self.ask(f"Short name for the rule [{default_name}]: ") or default_name
        title = self.ask("Finding title (blank = automatic; you can use {value} and {match}): ")
        explanation = self.ask("What it means — the explanation shown with the finding: ")
        recs = self.edit_list("What to do (optional)", [])
        rule = {"name": name, "enabled": True, "metric": metric, "op": op, "warning": warning,
                "critical": critical, "category": "Custom", "title": title,
                "explanation": explanation, "recommendations": recs}
        errors = custom_rules.validate_rule(rule)
        if errors:
            self.p(self.c("  This rule isn't valid yet: " + "; ".join(errors), "red"))
            if not self.confirm("Keep it anyway and fix it later?"):
                return
        rules_list = self._rules()
        rules_list.append(rule)
        self._save_rules(rules_list)
        self.p(self.c(f"  Added rule '{name}'.", "green"))
        if self.report:
            self.test_rule(rule)

    def rule_screen(self, index: int) -> None:
        rules_list = self._rules()
        if not 0 <= index < len(rules_list):
            return
        record = dict(rules_list[index])
        fields = [
            Field("enabled", "Rule enabled", "bool"),
            Field("name", "Name", "str"),
            Field("metric", "Metric (* = wildcard)", "str"),
            Field("op", "Comparison", "choice", choices=tuple(custom_rules.OPERATORS)),
            Field("warning", "Warning threshold", "optfloat"),
            Field("critical", "Critical threshold", "optfloat"),
            Field("category", "Category", "str"),
            Field("title", "Finding title", "text", "Blank = automatic. Can use {value}, {match}, {threshold}."),
            Field("explanation", "What it means", "text"),
            Field("recommendations", "What to do", "list"),
        ]

        def commit(rec, key):
            current = self._rules()
            current[index] = rec
            self._save_rules(current)
            errors = custom_rules.validate_rule(rec)
            return ("this rule is skipped until fixed: " + "; ".join(errors)) if errors else None

        def delete():
            if self.confirm(f"Delete rule '{record.get('name')}'?"):
                current = self._rules()
                current.pop(index)
                self._save_rules(current)
                return False
            return None

        self.edit_record(f"Custom rule: {record.get('name')}", record, fields, commit,
                         extra={"t": ("test on the loaded report", lambda: self.test_rule(record)),
                                "x": ("delete", delete)})

    def test_rule(self, rule: dict) -> None:
        if not self.report:
            self.p("  Load a report first to test rules against it.")
            return
        errors = custom_rules.validate_rule(rule)
        if errors:
            self.p(self.c("  Can't test: " + "; ".join(errors), "red"))
            return
        metrics = custom_rules.flatten_metrics(self.report, self.result.sql_insights if self.result else None)
        matches = custom_rules.match_rule(rule, metrics)
        flagged = [m for m in matches if m["severity"]]
        self.header(f"Testing '{rule.get('name')}' on {Path(self.report_path).name}")
        if not matches:
            self.p(self.c("  The metric pattern matched nothing in this report. Check the name with the "
                          "metric explorer.", "yellow"))
            return
        self.p(f"  {len(matches)} metric(s) matched; {len(flagged)} would be flagged.")
        for m in matches[:20]:
            status = self.sev(m["severity"]) if m["severity"] else self.c("ok      ", "dim")
            self.p(f"   {status} {m['name']:<60} {_num(m['value'])}")
        if len(matches) > 20:
            self.hint(f"   ... and {len(matches) - 20} more")

    # ---------------------------------------------- watchlist / ignore / hide

    def lists_menu(self) -> None:
        while True:
            self.header("Watchlist, ignored SQL and hidden findings")
            self.p(f"   1  SQL watchlist ({len(self.cfg.watchlist())}) — statements always reported, with your note")
            self.p(f"   2  Ignored SQL_IDs ({len(self.cfg.ignored_sql_ids())}) — left out of the query analysis")
            self.p(f"   3  Hidden findings ({len(self.cfg.get(('suppress',), []))}) — findings you've accepted")
            self.hint("b = back")
            cmd = self.ask("> ").lower()
            if cmd in ("b", ""):
                return
            if cmd == "1":
                self.watchlist_editor()
            elif cmd == "2":
                self.simple_list_editor(("sql_ignore",), "Ignored SQL_IDs",
                                        "These statements are left out of the query table and findings.")
            elif cmd == "3":
                self.simple_list_editor(("suppress",), "Hidden findings",
                                        "Findings whose ID matches a pattern here are hidden (and counted "
                                        "as hidden in reports). IDs look like 'wait.log file sync', "
                                        "'efficiency.buffer_hit', 'tablespace.USERS', 'sql.<sql_id>', "
                                        "'custom.<rule name>'. Use * as a wildcard: 'tablespace.UNDOTBS*'.")
            else:
                self.bad_choice()

    def watchlist_editor(self) -> None:
        while True:
            items = sorted(self.cfg.watchlist().items())
            self.header("SQL watchlist")
            if not items:
                self.p("  Empty.")
            for i, (sql_id, note) in enumerate(items, 1):
                self.p(f"  {i:>2}  {sql_id:<16} {note}")
            self.hint("a = add · e<n> = edit note · d<n> = remove · b = back")
            cmd = self.ask("> ").lower()
            if cmd in ("b", ""):
                return
            if cmd == "a":
                sql_id = self.ask("SQL_ID: ")
                if sql_id:
                    self.add_watch(sql_id)
            elif re.fullmatch(r"[ed]\d+", cmd) and 1 <= int(cmd[1:]) <= len(items):
                sql_id = items[int(cmd[1:]) - 1][0]
                if cmd[0] == "d":
                    self.cfg.unset(("sql_watchlist", sql_id))
                else:
                    self.add_watch(sql_id)
            else:
                self.bad_choice()

    def simple_list_editor(self, path: tuple, title: str, intro: str) -> None:
        self.header(title)
        self.wrap(intro, indent=0)
        current = list(self.cfg.get(path, []) or [])
        new = self.edit_list(title, current)
        if new != current:
            self.cfg.set(path, new)

    # ------------------------------------------------- presets / weights

    def presets_menu(self) -> None:
        names = list(PRESETS)
        self.header("Workload preset")
        self.wrap("A preset is a starting set of thresholds for a type of system. Any changes you've "
                  "made yourself stay on top of whichever preset you choose.", indent=0)
        for i, name in enumerate(names, 1):
            current = self.c("  (current)", "green") if name == self.cfg.preset else ""
            self.p(f"  {i:>2}  {name}{current}")
            self.hint(f"        {PRESETS[name]['description']}")
        cmd = self.ask("Choose a preset (blank = keep): ")
        if cmd.isdigit() and 1 <= int(cmd) <= len(names):
            self.cfg.set_preset(names[int(cmd) - 1])
            self.p(self.c(f"  Preset is now '{self.cfg.preset}'.", "green"))
        elif cmd:
            self.bad_choice()

    def weights_menu(self) -> None:
        record = {f"score_{k}": v for k, v in self.cfg.effective["score_weights"].items()}
        record.update({f"limit_{k}": v for k, v in self.cfg.effective["limits"].items()})
        fields = [
            Field("score_critical", "Points per critical", "float",
                  "Health score starts at 100 and loses this many points per critical finding."),
            Field("score_warning", "Points per warning", "float"),
            Field("score_info", "Points per info", "float"),
        ] + [Field(f"limit_{k}", k.replace("_", " ").capitalize(), "int", desc)
             for k, (_default, desc) in LIMIT_SPECS.items()]

        def path_for(key):
            group, _, name = key.partition("_")
            return ("score_weights", name) if group == "score" else ("limits", name)

        def commit(rec, key):
            if rec[key] is not None and rec[key] < 0:
                return "negative values don't make sense here"
            self.cfg.set(path_for(key), rec[key])

        def reset(key):
            self.cfg.unset(path_for(key))
            return self.cfg.get(path_for(key))

        self.edit_record("Health score weights and display limits", record, fields, commit, reset)

    # ------------------------------------------------------ save / load

    def view_changes(self) -> None:
        self.header("Your changes from the defaults")
        changes = self.cfg.describe_changes()
        if not changes:
            self.p("  None — you're using the built-in defaults.")
        for line in changes:
            self.wrap(line)
        problems = self.cfg.validate()
        if problems:
            self.p()
            self.p(self.c("Problems in these settings:", "bold"))
            for level, msg in problems:
                self.p(self.c(f"  {level}: {msg}", "red" if level == "error" else "yellow"))
        self.p()
        if self.ask("Show the saved-file JSON? [y/N] ").lower().startswith("y"):
            self.p(self.cfg.to_json())

    def save_config(self) -> None:
        errors = [m for lvl, m in self.cfg.validate() if lvl == "error"]
        if errors:
            for msg in errors:
                self.p(self.c(f"  error: {msg}", "red"))
            if not self.confirm("These settings have errors. Save anyway?"):
                return
        path = self.ask_path(f"Save settings to [{self.config_path}]: ") or self.config_path
        try:
            saved = self.cfg.save(path)
        except OSError as exc:
            self.p(self.c(f"  Couldn't save: {exc}", "red"))
            return
        self.config_path = saved
        self.p(self.c(f"  Saved to {saved}", "green"))
        if Path(saved).expanduser().resolve() != default_config_path().expanduser().resolve():
            self.hint(f"  Use it from the command line with:  awr-analyzer analyze report.html --config {saved}")

    def load_config(self) -> None:
        if self.cfg.dirty and not self.confirm("Discard your unsaved changes and load another file?"):
            return
        path = self.ask_path(f"Load settings from [{self.config_path}]: ") or self.config_path
        try:
            cfg = AnalyzerConfig.load(path)
        except ConfigError as exc:
            self.p(self.c(f"  {exc}", "red"))
            return
        for level, msg in cfg.validate():
            self.p(self.c(f"  {level}: {msg}", "red" if level == "error" else "yellow"))
        self.cfg, self.config_path = cfg, path
        self.p(self.c(f"  Loaded {path}: {cfg.summary_line()}", "green"))

    def reset_config(self) -> None:
        if self.confirm("Reset every setting to the built-in defaults? (Your saved file is untouched until you save.)"):
            self.cfg.reset_all()
            self.p(self.c("  Back to defaults.", "green"))


def run_tui(config: Optional[AnalyzerConfig] = None, config_path: Optional[str] = None,
            report_path: Optional[str] = None) -> int:
    return TUI(config=config, config_path=config_path).run(report_path=report_path)
