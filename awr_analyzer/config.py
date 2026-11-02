"""User-customizable analysis configuration.

Everything the analyzer decides — which checks run, the thresholds that
turn a number into a warning or a critical finding, the plain-language
explanation and recommended actions attached to each kind of finding, extra
rules of the user's own, and which findings to hide — comes from an
:class:`AnalyzerConfig`.

The effective configuration is built in three layers:

1. built-in defaults (from :mod:`awr_analyzer.rules`),
2. an optional preset tuned for a workload type (``oltp``, ``data_warehouse``,
   ``strict``),
3. the user's own overrides.

Only layer 3 is saved to disk, so a config file holds exactly what the user
changed and later improvements to the defaults still reach them.
"""

from __future__ import annotations

import copy
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from . import rules

CONFIG_VERSION = 1
CONFIG_ENV_VAR = "AWR_ANALYZER_CONFIG"
SEVERITIES = ("critical", "warning", "info")


class ConfigError(Exception):
    pass


@dataclass(frozen=True)
class ThresholdSpec:
    key: str
    default: float
    unit: str
    group: str
    description: str


THRESHOLD_SPECS = [
    ThresholdSpec("wait_event_pct_warning", rules.WAIT_EVENT_PCT_WARNING, "% of DB time", "Wait events",
                  "A single wait event using at least this share of DB time is flagged as a warning."),
    ThresholdSpec("wait_event_pct_critical", rules.WAIT_EVENT_PCT_CRITICAL, "% of DB time", "Wait events",
                  "A single wait event using at least this share of DB time is flagged as critical."),
    ThresholdSpec("seq_read_ms_warning", rules.SEQ_READ_MS_WARNING, "ms", "Wait events",
                  "Average 'db file sequential read' latency (single-block disk read) that counts as slow."),
    ThresholdSpec("seq_read_ms_critical", rules.SEQ_READ_MS_CRITICAL, "ms", "Wait events",
                  "Average 'db file sequential read' latency that counts as critically slow."),
    ThresholdSpec("db_cpu_pct_warning", rules.DB_CPU_PCT_WARNING, "% of DB time", "CPU",
                  "Share of DB time spent on CPU at which the workload is called CPU-bound (warning)."),
    ThresholdSpec("db_cpu_pct_critical", rules.DB_CPU_PCT_CRITICAL, "% of DB time", "CPU",
                  "Share of DB time spent on CPU at which the workload is called CPU-bound (critical)."),
    ThresholdSpec("hard_parse_warning", rules.HARD_PARSE_WARNING, "per second", "Parsing",
                  "Hard parses per second that suggest SQL isn't being reused (warning)."),
    ThresholdSpec("hard_parse_critical", rules.HARD_PARSE_CRITICAL, "per second", "Parsing",
                  "Hard parses per second that suggest SQL isn't being reused (critical)."),
    ThresholdSpec("ts_read_ms_warning", rules.TS_READ_MS_WARNING, "ms", "Tablespace I/O",
                  "Average tablespace read time that counts as slow storage (warning)."),
    ThresholdSpec("ts_read_ms_critical", rules.TS_READ_MS_CRITICAL, "ms", "Tablespace I/O",
                  "Average tablespace read time that counts as slow storage (critical)."),
    ThresholdSpec("ts_min_reads", rules.TS_MIN_READS_FOR_LATENCY_CHECK, "reads", "Tablespace I/O",
                  "Tablespaces with fewer reads than this in the window are skipped: the average "
                  "isn't reliable from a handful of reads."),
    ThresholdSpec("sql_pct_warning", rules.SQL_PCT_WARNING, "% of DB time", "SQL",
                  "A single statement using at least this share of DB time is flagged (warning)."),
    ThresholdSpec("sql_pct_critical", rules.SQL_PCT_CRITICAL, "% of DB time", "SQL",
                  "A single statement using at least this share of DB time is flagged (critical)."),
    ThresholdSpec("sql_cpu_bound_pct", rules.SQL_CPU_BOUND_PCT, "% of statement time", "SQL",
                  "A statement spending at least this share of its own time on CPU is tagged CPU-bound."),
    ThresholdSpec("sql_io_bound_pct", rules.SQL_IO_BOUND_PCT, "% of statement time", "SQL",
                  "A statement spending at least this share of its own time on I/O is tagged I/O-bound."),
    ThresholdSpec("sql_gets_per_exec_warning", rules.SQL_GETS_PER_EXEC_WARNING, "buffer gets", "SQL",
                  "Logical reads per execution that suggest a missing index (warning)."),
    ThresholdSpec("sql_gets_per_exec_critical", rules.SQL_GETS_PER_EXEC_CRITICAL, "buffer gets", "SQL",
                  "Logical reads per execution that suggest a missing index (critical)."),
    ThresholdSpec("sql_reads_per_exec_warning", rules.SQL_READS_PER_EXEC_WARNING, "physical reads", "SQL",
                  "Disk reads per execution that count as heavy (warning)."),
    ThresholdSpec("sql_reads_per_exec_critical", rules.SQL_READS_PER_EXEC_CRITICAL, "physical reads", "SQL",
                  "Disk reads per execution that count as heavy (critical)."),
    ThresholdSpec("sql_gets_per_row_warning", rules.SQL_GETS_PER_ROW_WARNING, "gets per row", "SQL",
                  "Blocks read per row returned that suggest poor selectivity (warning)."),
    ThresholdSpec("sql_gets_per_row_critical", rules.SQL_GETS_PER_ROW_CRITICAL, "gets per row", "SQL",
                  "Blocks read per row returned that suggest poor selectivity (critical)."),
    ThresholdSpec("sql_high_volume_executions", rules.SQL_HIGH_VOLUME_EXECUTIONS, "executions", "SQL",
                  "Executions in the window above which a statement counts as high call volume."),
    ThresholdSpec("sql_high_volume_min_pct_elapsed", rules.SQL_HIGH_VOLUME_MIN_PCT_ELAPSED, "% of DB time", "SQL",
                  "A high-volume statement is only flagged if it also uses at least this share of DB time."),
    ThresholdSpec("sql_expensive_single_run_max_execs", rules.SQL_EXPENSIVE_SINGLE_RUN_MAX_EXECS, "executions", "SQL",
                  "Statements run at most this many times count as low-frequency."),
    ThresholdSpec("sql_expensive_single_run_min_per_exec_s", rules.SQL_EXPENSIVE_SINGLE_RUN_MIN_PER_EXEC_S, "seconds", "SQL",
                  "A low-frequency statement is flagged as expensive if each run takes at least this long."),
    ThresholdSpec("sql_bind_variable_min_group_size", rules.SQL_BIND_VARIABLE_MIN_GROUP_SIZE, "statements", "SQL",
                  "How many near-identical statements (differing only in literals) it takes to suspect "
                  "missing bind variables."),
]
THRESHOLD_SPECS_BY_KEY = {s.key: s for s in THRESHOLD_SPECS}

# Pairs where both values describe the same check; used to warn about a
# warning threshold that is stricter than its critical one.
_HIGHER_IS_WORSE_PAIRS = [
    ("wait_event_pct_warning", "wait_event_pct_critical"),
    ("seq_read_ms_warning", "seq_read_ms_critical"),
    ("db_cpu_pct_warning", "db_cpu_pct_critical"),
    ("hard_parse_warning", "hard_parse_critical"),
    ("ts_read_ms_warning", "ts_read_ms_critical"),
    ("sql_pct_warning", "sql_pct_critical"),
    ("sql_gets_per_exec_warning", "sql_gets_per_exec_critical"),
    ("sql_reads_per_exec_warning", "sql_reads_per_exec_critical"),
    ("sql_gets_per_row_warning", "sql_gets_per_row_critical"),
]

CHECKS = {
    "efficiency": "Instance efficiency ratios (buffer cache hit, soft parse, ...)",
    "wait_events": "Top wait events: where sessions spent time waiting",
    "cpu_load": "Whether the workload as a whole is CPU-bound",
    "parse_rate": "Hard parse rate",
    "sql": "Problematic individual SQL statements",
    "bind_variables": "Near-identical statements that suggest missing bind variables",
    "tablespace_io": "Slow storage reads per tablespace",
    "custom_rules": "Your own custom rules",
}

LIMIT_SPECS = {
    "max_sql_findings": (8, "How many problematic statements become individual findings."),
    "max_sql_table_rows": (15, "How many statements the Problematic Queries table shows."),
    "max_custom_rule_matches": (10, "Default cap on findings a single wildcard custom rule can produce."),
}

PRESETS = {
    "oltp": {
        "description": (
            "Default. Transaction processing: short, selective queries where most reads "
            "should come from memory."
        ),
        "overrides": {},
    },
    "data_warehouse": {
        "description": (
            "Reporting and analytics: big scans, direct-path reads and ad-hoc literal SQL are "
            "expected, so per-query I/O and parsing thresholds are relaxed and cache-hit "
            "ratios count for less."
        ),
        "overrides": {
            "thresholds": {
                "sql_gets_per_exec_warning": 1_000_000.0,
                "sql_gets_per_exec_critical": 10_000_000.0,
                "sql_reads_per_exec_warning": 100_000.0,
                "sql_reads_per_exec_critical": 1_000_000.0,
                "sql_gets_per_row_warning": 100_000.0,
                "sql_gets_per_row_critical": 1_000_000.0,
                "sql_io_bound_pct": 80.0,
                "hard_parse_warning": 5.0,
                "hard_parse_critical": 20.0,
                "sql_expensive_single_run_min_per_exec_s": 300.0,
            },
            "efficiency": {
                "buffer_hit": {"warning": 80.0, "critical": 50.0},
                "soft_parse": {"warning": 80.0, "critical": 50.0},
                "execute_to_parse": {"warning": 30.0, "critical": 10.0},
                "in_memory_sort": {"warning": 85.0, "critical": 60.0},
            },
        },
    },
    "strict": {
        "description": (
            "Tighter thresholds for latency-sensitive systems on fast (SSD/NVMe) storage."
        ),
        "overrides": {
            "thresholds": {
                "wait_event_pct_warning": 5.0,
                "wait_event_pct_critical": 15.0,
                "seq_read_ms_warning": 3.0,
                "seq_read_ms_critical": 8.0,
                "ts_read_ms_warning": 5.0,
                "ts_read_ms_critical": 12.0,
                "sql_pct_warning": 5.0,
                "sql_pct_critical": 15.0,
                "sql_gets_per_exec_warning": 5_000.0,
                "sql_gets_per_exec_critical": 50_000.0,
                "hard_parse_warning": 0.5,
                "hard_parse_critical": 2.0,
                "db_cpu_pct_warning": 60.0,
                "db_cpu_pct_critical": 80.0,
            },
            "efficiency": {"buffer_hit": {"warning": 98.0, "critical": 92.0}},
        },
    },
}
DEFAULT_PRESET = "oltp"


def _builtin_defaults() -> dict:
    efficiency = {}
    for key, (warn, crit) in rules.EFFICIENCY_THRESHOLDS.items():
        efficiency[key] = {
            "enabled": True,
            "warning": warn,
            "critical": crit,
            "label": rules.EFFICIENCY_LABELS.get(key, key),
            "explanation": rules.EFFICIENCY_EXPLANATIONS.get(key, ""),
            "recommendations": list(rules.EFFICIENCY_RECOMMENDATIONS.get(key, [])),
        }
    sql_tags = {}
    for tag, info in rules.SQL_TAG_INFO.items():
        sql_tags[tag] = {
            "enabled": True,
            "label": info["label"],
            "severity": info["severity"],
            "plain": info["plain"],
            "recommendations": list(info["recommendations"]),
        }
    return {
        "version": CONFIG_VERSION,
        "preset": DEFAULT_PRESET,
        "checks": {name: True for name in CHECKS},
        "thresholds": {s.key: s.default for s in THRESHOLD_SPECS},
        "efficiency": efficiency,
        "wait_events": {"custom": []},
        "sql_tags": sql_tags,
        "custom_rules": [],
        "suppress": [],
        "sql_watchlist": {},
        "sql_ignore": [],
        "score_weights": {"critical": 20.0, "warning": 8.0, "info": 0.0},
        "limits": {k: v[0] for k, v in LIMIT_SPECS.items()},
    }


DEFAULTS = _builtin_defaults()


def deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge ``override`` into a copy of ``base``. Nested dicts
    merge key by key; anything else (numbers, strings, lists) replaces."""
    out = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


_MISSING = object()     # returned when a path doesn't exist
_NO_DEFAULT = object()  # "raise instead of returning a default"


def _get_path(d: dict, path: tuple, default=_NO_DEFAULT):
    cur = d
    for part in path:
        if not isinstance(cur, dict) or part not in cur:
            if default is _NO_DEFAULT:
                raise KeyError("/".join(path))
            return default
        cur = cur[part]
    return cur


def default_config_path() -> Path:
    env = os.environ.get(CONFIG_ENV_VAR)
    if env:
        return Path(env).expanduser()
    return Path.home() / ".awr_analyzer" / "config.json"


class AnalyzerConfig:
    """Holds the user's overrides and exposes the merged effective config."""

    def __init__(self, overrides: Optional[dict] = None, source_path: Optional[str] = None):
        self.overrides: dict = copy.deepcopy(overrides or {})
        self.source_path = source_path
        self._effective: Optional[dict] = None
        self._wait_kb_cache = None
        self._saved = self._snapshot()

    # ------------------------------------------------------------------ io

    @classmethod
    def load(cls, path) -> "AnalyzerConfig":
        p = Path(path).expanduser()
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise ConfigError(f"config file not found: {p}")
        except json.JSONDecodeError as exc:
            raise ConfigError(f"{p} is not valid JSON (line {exc.lineno}, column {exc.colno}): {exc.msg}")
        if not isinstance(data, dict):
            raise ConfigError(f"{p} must contain a JSON object at the top level")
        return cls(overrides=data, source_path=str(p))

    @classmethod
    def from_preset(cls, preset: str) -> "AnalyzerConfig":
        if preset not in PRESETS:
            raise ConfigError(f"unknown preset '{preset}' (choose from: {', '.join(PRESETS)})")
        cfg = cls()
        cfg.set_preset(preset)
        cfg.mark_clean()
        return cfg

    def save(self, path=None) -> str:
        target = Path(path or self.source_path or default_config_path()).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        payload = dict(self.overrides)
        payload["version"] = CONFIG_VERSION
        target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self.source_path = str(target)
        self.mark_clean()
        return str(target)

    def to_json(self, effective: bool = False) -> str:
        data = self.effective if effective else self.overrides
        return json.dumps(data, indent=2, sort_keys=True)

    # ------------------------------------------------------------- merging

    @property
    def preset(self) -> str:
        preset = self.overrides.get("preset", DEFAULT_PRESET)
        return preset if preset in PRESETS else DEFAULT_PRESET

    def base(self) -> dict:
        """Defaults plus the active preset, without the user's overrides."""
        return deep_merge(DEFAULTS, PRESETS[self.preset]["overrides"])

    @property
    def effective(self) -> dict:
        if self._effective is None:
            self._effective = deep_merge(self.base(), self.overrides)
        return self._effective

    def _invalidate(self) -> None:
        self._effective = None
        self._wait_kb_cache = None

    def _snapshot(self) -> str:
        return json.dumps(self.overrides, sort_keys=True, default=str)

    @property
    def dirty(self) -> bool:
        """True when the settings differ from what was last loaded or saved."""
        return self._snapshot() != self._saved

    def mark_clean(self) -> None:
        self._saved = self._snapshot()

    # ----------------------------------------------------------- read API

    def threshold(self, key: str) -> float:
        value = self.effective["thresholds"].get(key)
        if value is None:
            return THRESHOLD_SPECS_BY_KEY[key].default
        return float(value)

    def check_enabled(self, name: str) -> bool:
        return bool(self.effective["checks"].get(name, True))

    def efficiency(self) -> dict:
        return self.effective["efficiency"]

    def sql_tag(self, tag: str) -> dict:
        return self.effective["sql_tags"].get(tag) or {
            "enabled": True, "label": tag, "severity": "info", "plain": "", "recommendations": [],
        }

    def limit(self, name: str) -> int:
        return int(self.effective["limits"].get(name, LIMIT_SPECS[name][0]))

    def score_weight(self, severity: str) -> float:
        return float(self.effective["score_weights"].get(severity, 0.0))

    def custom_rules(self) -> list:
        return self.effective.get("custom_rules") or []

    def watchlist(self) -> dict:
        return self.effective.get("sql_watchlist") or {}

    def ignored_sql_ids(self) -> set:
        return {s.strip().lower() for s in self.effective.get("sql_ignore") or [] if s.strip()}

    def wait_event_kb(self) -> list:
        """User-defined wait-event entries first (so they win), then the
        built-in knowledge base. Each item: (compiled regex, info dict, source)."""
        if self._wait_kb_cache is None:
            kb = []
            for entry in self.effective["wait_events"].get("custom") or []:
                try:
                    pattern = re.compile(entry["pattern"], re.I)
                except (re.error, KeyError, TypeError):
                    continue
                kb.append((pattern, {
                    "category": entry.get("category") or "Other",
                    "plain": entry.get("plain") or "",
                    "recommendations": list(entry.get("recommendations") or []),
                }, "custom"))
            for pattern, info in rules.WAIT_EVENT_KB:
                kb.append((re.compile(pattern, re.I), info, "builtin"))
            self._wait_kb_cache = kb
        return self._wait_kb_cache

    def lookup_wait_event(self, event_name: str) -> Optional[dict]:
        for pattern, info, _source in self.wait_event_kb():
            if pattern.search(event_name):
                return info
        return None

    def is_suppressed(self, rule_id: str) -> bool:
        from fnmatch import fnmatchcase
        rid = (rule_id or "").lower()
        return any(fnmatchcase(rid, pat.lower()) for pat in self.effective.get("suppress") or [])

    # ---------------------------------------------------------- write API

    def get(self, path: tuple, default=None):
        return _get_path(self.effective, path, default)

    def is_overridden(self, path: tuple) -> bool:
        return _get_path(self.overrides, path, _MISSING) is not _MISSING

    def set(self, path: tuple, value) -> None:
        """Set an override. Setting a value equal to the default (or the
        preset's value) removes the override instead, keeping the saved
        file down to genuine customizations."""
        base_value = _get_path(self.base(), path, _MISSING)
        if path != ("preset",) and base_value is not _MISSING and base_value == value:
            self.unset(path)
            return
        cur = self.overrides
        for part in path[:-1]:
            nxt = cur.get(part)
            if not isinstance(nxt, dict):
                nxt = {}
                cur[part] = nxt
            cur = nxt
        cur[path[-1]] = copy.deepcopy(value)
        self._invalidate()

    def unset(self, path: tuple) -> None:
        parents = []
        cur = self.overrides
        for part in path[:-1]:
            if not isinstance(cur, dict) or part not in cur:
                return
            parents.append((cur, part))
            cur = cur[part]
        if isinstance(cur, dict) and path[-1] in cur:
            del cur[path[-1]]
            # prune now-empty parent dicts
            for parent, key in reversed(parents):
                if parent[key] == {}:
                    del parent[key]
            self._invalidate()

    def reset_all(self) -> None:
        self.overrides = {}
        self._invalidate()

    def set_preset(self, name: str) -> None:
        if name not in PRESETS:
            raise ConfigError(f"unknown preset '{name}'")
        if name == DEFAULT_PRESET:
            self.unset(("preset",))
        else:
            self.set(("preset",), name)

    # --------------------------------------------------------- inspection

    def describe_changes(self) -> list:
        """Human-readable list of what differs from the active preset's defaults."""
        lines = []
        if self.preset != DEFAULT_PRESET:
            lines.append(f"preset: {self.preset}")
        base = self.base()

        def walk(over, path):
            for key, value in sorted(over.items()):
                p = path + (key,)
                if p in (("preset",), ("version",)):
                    continue
                if isinstance(value, dict) and isinstance(_get_path(base, p, None), dict):
                    walk(value, p)
                    continue
                old = _get_path(base, p, None)
                if isinstance(value, list) and value and all(isinstance(v, dict) for v in value):
                    names = [str(v.get("name") or v.get("pattern") or "?") for v in value]
                    lines.append(f"{'.'.join(p)}: {len(value)} entr{'y' if len(value) == 1 else 'ies'} "
                                 f"({_short(', '.join(names))})")
                    continue
                shown = _short(value)
                if old is None:
                    lines.append(f"{'.'.join(p)} = {shown}")
                else:
                    lines.append(f"{'.'.join(p)}: {_short(old)} -> {shown}")

        walk(self.overrides, ())
        return lines

    def validate(self) -> list:
        """Returns a list of (level, message); level is 'error' or 'warning'."""
        from .custom_rules import validate_rule

        problems = []
        known_top = set(DEFAULTS) | {"version"}
        for key in self.overrides:
            if key not in known_top:
                problems.append(("warning", f"unknown setting '{key}' is ignored"))

        if self.overrides.get("preset", DEFAULT_PRESET) not in PRESETS:
            problems.append(("error", f"unknown preset '{self.overrides.get('preset')}' "
                                      f"(choose from: {', '.join(PRESETS)})"))

        eff = self.effective
        for key, value in (self.overrides.get("thresholds") or {}).items():
            if key not in THRESHOLD_SPECS_BY_KEY:
                problems.append(("warning", f"thresholds.{key} is not a known threshold and is ignored"))
            elif not _is_number(value):
                problems.append(("error", f"thresholds.{key} must be a number, got {value!r}"))
        for warn_key, crit_key in _HIGHER_IS_WORSE_PAIRS:
            w, c = eff["thresholds"].get(warn_key), eff["thresholds"].get(crit_key)
            if _is_number(w) and _is_number(c) and w > c:
                problems.append(("warning", f"thresholds.{warn_key} ({w}) is higher than "
                                            f"{crit_key} ({c}); the warning level will never fire"))

        for name, value in (self.overrides.get("checks") or {}).items():
            if name not in CHECKS:
                problems.append(("warning", f"checks.{name} is not a known check"))
            elif not isinstance(value, bool):
                problems.append(("error", f"checks.{name} must be true or false"))

        for key, entry in (eff.get("efficiency") or {}).items():
            if not isinstance(entry, dict):
                problems.append(("error", f"efficiency.{key} must be an object"))
                continue
            w, c = entry.get("warning"), entry.get("critical")
            if not _is_number(w) or not _is_number(c):
                problems.append(("error", f"efficiency.{key} needs numeric 'warning' and 'critical'"))
            elif w < c:
                problems.append(("warning", f"efficiency.{key}: lower is worse here, so 'warning' ({w}) "
                                            f"should be above 'critical' ({c})"))

        for i, entry in enumerate((eff.get("wait_events") or {}).get("custom") or []):
            where = f"wait_events.custom[{i}]"
            if not isinstance(entry, dict) or not entry.get("pattern"):
                problems.append(("error", f"{where} needs a 'pattern'"))
                continue
            try:
                re.compile(entry["pattern"])
            except re.error as exc:
                problems.append(("error", f"{where}: pattern {entry['pattern']!r} is not a valid regex ({exc})"))
            if not isinstance(entry.get("recommendations", []), list):
                problems.append(("error", f"{where}.recommendations must be a list"))

        for tag, entry in (eff.get("sql_tags") or {}).items():
            if isinstance(entry, dict) and entry.get("severity") not in SEVERITIES:
                problems.append(("error", f"sql_tags.{tag}.severity must be one of {', '.join(SEVERITIES)}"))

        seen = set()
        for i, rule in enumerate(eff.get("custom_rules") or []):
            for msg in validate_rule(rule):
                problems.append(("error", f"custom_rules[{i}] ({rule.get('name', '?') if isinstance(rule, dict) else '?'}): {msg}"))
            name = rule.get("name") if isinstance(rule, dict) else None
            if name in seen:
                problems.append(("warning", f"custom rule name '{name}' is used more than once"))
            seen.add(name)

        if not all(isinstance(s, str) for s in eff.get("suppress") or []):
            problems.append(("error", "suppress must be a list of text patterns"))
        if not isinstance(eff.get("sql_watchlist"), dict):
            problems.append(("error", "sql_watchlist must map SQL_IDs to notes"))
        for sev, w in (eff.get("score_weights") or {}).items():
            if not _is_number(w):
                problems.append(("error", f"score_weights.{sev} must be a number"))
        for name, v in (eff.get("limits") or {}).items():
            if name in LIMIT_SPECS and (not _is_number(v) or v < 0):
                problems.append(("error", f"limits.{name} must be a non-negative number"))
        return problems

    def summary_line(self) -> str:
        n = len(self.describe_changes())
        if self.preset != DEFAULT_PRESET:
            n -= 1
        where = f" from {self.source_path}" if self.source_path else ""
        return f"preset '{self.preset}', {n} customization(s){where}"


def _is_number(v) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _short(value, width: int = 60) -> str:
    text = json.dumps(value) if not isinstance(value, str) else repr(value)
    return text if len(text) <= width else text[: width - 3] + "..."


def resolve_config(path: Optional[str] = None, preset: Optional[str] = None,
                   use_default_file: bool = True) -> AnalyzerConfig:
    """Config resolution used by the CLI: an explicit path wins, then the
    default config file if it exists, then built-in defaults. ``preset``
    (if given) overrides whatever preset the file chose."""
    if path:
        cfg = AnalyzerConfig.load(path)
    elif use_default_file and default_config_path().exists():
        cfg = AnalyzerConfig.load(default_config_path())
    else:
        cfg = AnalyzerConfig()
    if preset:
        cfg.set_preset(preset)
        cfg.mark_clean()
    return cfg
