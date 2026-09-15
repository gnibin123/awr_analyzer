"""Data structures used to hold the information extracted from an AWR report."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SnapshotInfo:
    db_name: Optional[str] = None
    db_id: Optional[str] = None
    instance_name: Optional[str] = None
    instance_number: Optional[str] = None
    host_name: Optional[str] = None
    platform: Optional[str] = None
    release: Optional[str] = None
    rac: Optional[str] = None
    cpus: Optional[float] = None
    cores: Optional[float] = None
    sockets: Optional[float] = None
    memory_gb: Optional[float] = None
    begin_snap_id: Optional[str] = None
    begin_snap_time: Optional[str] = None
    end_snap_id: Optional[str] = None
    end_snap_time: Optional[str] = None
    elapsed_minutes: Optional[float] = None
    db_time_minutes: Optional[float] = None


@dataclass
class WaitEvent:
    event: str
    waits: Optional[float] = None
    total_wait_time_sec: Optional[float] = None
    avg_wait_ms: Optional[float] = None
    pct_db_time: Optional[float] = None
    wait_class: Optional[str] = None


@dataclass
class SQLStat:
    sql_id: str
    value: Optional[float] = None          # the primary sort metric (elapsed, cpu, gets, reads, execs)
    executions: Optional[float] = None
    per_exec: Optional[float] = None
    pct_total: Optional[float] = None
    module: Optional[str] = None
    sql_text: Optional[str] = None


@dataclass
class TablespaceIOStat:
    tablespace: str
    reads: Optional[float] = None
    avg_reads_per_sec: Optional[float] = None
    avg_read_time_ms: Optional[float] = None
    writes: Optional[float] = None
    avg_writes_per_sec: Optional[float] = None
    avg_buffer_wait_ms: Optional[float] = None


@dataclass
class AWRReport:
    source_path: Optional[str] = None
    info: SnapshotInfo = field(default_factory=SnapshotInfo)

    load_profile: dict = field(default_factory=dict)
    instance_efficiency: dict = field(default_factory=dict)
    host_cpu: dict = field(default_factory=dict)
    instance_cpu: dict = field(default_factory=dict)
    time_model: dict = field(default_factory=dict)

    top_wait_events: list = field(default_factory=list)          # list[WaitEvent]
    wait_class_stats: list = field(default_factory=list)          # list[WaitEvent] (aggregated by class)

    sql_by_elapsed: list = field(default_factory=list)            # list[SQLStat]
    sql_by_cpu: list = field(default_factory=list)
    sql_by_gets: list = field(default_factory=list)
    sql_by_reads: list = field(default_factory=list)
    sql_by_executions: list = field(default_factory=list)

    tablespace_io: list = field(default_factory=list)             # list[TablespaceIOStat]

    undo_stats: dict = field(default_factory=dict)

    raw_section_titles: list = field(default_factory=list)        # for debugging / coverage reporting

    def metric(self, name: str, default=None):
        """Convenience accessor into load_profile per-second values."""
        entry = self.load_profile.get(name)
        if entry is None:
            return default
        return entry.get("per_second", default)


# Severity ordering, worst first. Kept as a plain list (rather than an Enum)
# so it is trivial to sort on and to serialize to JSON/HTML.
SEVERITY_ORDER = ["critical", "warning", "info", "good"]


@dataclass
class Finding:
    """A single, self-contained insight produced by the analyzer.

    Written so that someone with little Oracle background can read
    ``plain_explanation`` and ``recommendations`` and know what is wrong and
    what to do about it, while ``technical_detail`` keeps the precise
    numbers for a DBA who wants to dig further.
    """

    severity: str                       # critical | warning | info | good
    category: str                       # e.g. "CPU", "I/O", "Memory", "SQL", "Locking"
    title: str
    plain_explanation: str
    technical_detail: str
    recommendations: list = field(default_factory=list)
    evidence: dict = field(default_factory=dict)

    def severity_rank(self) -> int:
        try:
            return SEVERITY_ORDER.index(self.severity)
        except ValueError:
            return len(SEVERITY_ORDER)


@dataclass
class AnalysisResult:
    report: AWRReport
    findings: list = field(default_factory=list)      # list[Finding]
    health_score: int = 100
    summary: str = ""

    def findings_by_severity(self, severity: str):
        return [f for f in self.findings if f.severity == severity]

    def counts(self) -> dict:
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts
