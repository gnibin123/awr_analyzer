"""Domain knowledge used by the analyzer: thresholds and a plain-language
knowledge base about common Oracle wait events.

The thresholds here are widely used DBA rules of thumb, not hard physical
limits — the analyzer uses them to flag things worth a human's attention,
not to make a final diagnosis. Every generated finding says *why* the
number is a problem and what to check next, so a reader without Oracle
background can act on it and a DBA can validate it quickly.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Instance efficiency thresholds: (warning_below, critical_below)
# All values are percentages, higher is better, except where noted.
# ---------------------------------------------------------------------------
EFFICIENCY_THRESHOLDS = {
    "buffer_hit": (95.0, 85.0),
    "library_hit": (95.0, 90.0),
    "soft_parse": (95.0, 80.0),
    "latch_hit": (99.0, 95.0),
    "in_memory_sort": (95.0, 75.0),
    "non_parse_cpu": (95.0, 85.0),
    "execute_to_parse": (70.0, 40.0),
    "redo_nowait": (99.0, 95.0),
    "buffer_nowait": (99.0, 95.0),
}

EFFICIENCY_LABELS = {
    "buffer_hit": "Buffer Cache Hit Ratio",
    "library_hit": "Library Cache Hit Ratio",
    "soft_parse": "Soft Parse Ratio",
    "latch_hit": "Latch Hit Ratio",
    "in_memory_sort": "In-Memory Sort Ratio",
    "non_parse_cpu": "Non-Parse CPU Ratio",
    "execute_to_parse": "Execute-to-Parse Ratio",
    "redo_nowait": "Redo NoWait Ratio",
    "buffer_nowait": "Buffer NoWait Ratio",
}

EFFICIENCY_EXPLANATIONS = {
    "buffer_hit": (
        "This measures how often Oracle finds the data block it needs already sitting in "
        "memory (the buffer cache) instead of having to read it from disk. A lower number "
        "means the database is doing more physical disk reads than it should, which is "
        "usually much slower than reading from memory."
    ),
    "library_hit": (
        "This measures how often Oracle can reuse an already-parsed SQL statement instead "
        "of parsing it again from scratch. Parsing is expensive CPU work, so a low ratio "
        "here means the database is wasting effort re-parsing SQL it has already seen."
    ),
    "soft_parse": (
        "A 'soft parse' reuses an existing parsed version of a SQL statement; a 'hard "
        "parse' builds a brand new execution plan, which is much more expensive and also "
        "briefly locks shared memory structures. A low soft parse ratio usually means the "
        "application is not using bind variables and is sending slightly different SQL "
        "text every time (e.g. literals baked into the SQL instead of ':1', ':2', ...)."
    ),
    "latch_hit": (
        "Latches are lightweight internal locks Oracle uses to protect shared memory "
        "structures. A low hit ratio means sessions are frequently having to wait/spin for "
        "a latch, which points to internal contention, often from parsing or hot buffer "
        "access."
    ),
    "in_memory_sort": (
        "Sorting data (for ORDER BY, GROUP BY, joins, etc.) is fastest in memory (PGA). "
        "When it doesn't fit, Oracle spills the sort to the temporary tablespace on disk, "
        "which is much slower. A low ratio means sorts are frequently spilling to disk."
    ),
    "non_parse_cpu": (
        "This is the share of CPU time spent actually running SQL versus parsing it. A low "
        "value means a disproportionate amount of CPU is being burned on parsing rather "
        "than doing real work."
    ),
    "execute_to_parse": (
        "This compares how many times a parsed statement was executed versus how many "
        "times it had to be parsed. A low ratio means statements are parsed almost as "
        "often as they're executed — i.e. cursors are not being reused efficiently."
    ),
    "redo_nowait": (
        "Measures how often a session had to wait for space in the redo log buffer before "
        "it could write. Frequent waits point to a redo log buffer that is too small or a "
        "high-throughput write workload outpacing log flushing."
    ),
    "buffer_nowait": (
        "Measures how often a session got instant access to a buffer without waiting. "
        "Frequent waits point to contention for specific data blocks."
    ),
}

EFFICIENCY_RECOMMENDATIONS = {
    "buffer_hit": [
        "Check whether the SGA / buffer cache is undersized for the working set; consider "
        "increasing db_cache_size or enabling automatic memory management with a higher "
        "SGA target.",
        "Look at the 'SQL ordered by Reads' section for statements doing large numbers of "
        "physical reads and check whether they are missing useful indexes or doing full "
        "table scans that could be avoided.",
        "Confirm storage latency is not the underlying cause — a healthy cache should "
        "absorb most reads regardless of disk speed, but a rising working set will show up "
        "here first.",
    ],
    "library_hit": [
        "Increase shared_pool_size if the shared pool is undersized for the number of "
        "distinct SQL statements in use.",
        "Reduce unnecessary hard parsing (see Soft Parse Ratio) since that is the most "
        "common cause of library cache churn.",
    ],
    "soft_parse": [
        "Have the application use bind variables instead of embedding literal values "
        "directly in SQL text (e.g. WHERE id = :1 instead of WHERE id = 12345).",
        "Consider setting CURSOR_SHARING=FORCE as a temporary mitigation while the "
        "application is fixed to use bind variables properly (it has trade-offs, so treat "
        "it as a stopgap, not a permanent fix).",
        "Review the 'SQL ordered by Executions' and 'SQL ordered by Parse Calls' data for "
        "statements that are parsed almost as often as they run.",
    ],
    "latch_hit": [
        "Identify the specific latch(es) involved (check Top Wait Events for entries like "
        "'latch: shared pool' or 'latch: cache buffers chains') and address the underlying "
        "cause — usually excessive hard parsing or a small number of very 'hot' blocks.",
    ],
    "in_memory_sort": [
        "Increase PGA_AGGREGATE_TARGET (or PGA_AGGREGATE_LIMIT on newer versions) so more "
        "sort/hash work can complete in memory.",
        "Review SQL doing large sorts or hash joins (ORDER BY, GROUP BY, DISTINCT, joins on "
        "unindexed columns) — a supporting index can sometimes avoid the sort entirely.",
        "Check temp tablespace sizing and I/O performance since spills are landing there.",
    ],
    "non_parse_cpu": [
        "Same remediation as Soft Parse Ratio: reduce hard-parse volume by fixing "
        "application SQL to use bind variables.",
    ],
    "execute_to_parse": [
        "Check whether the application is closing cursors too aggressively (e.g. not using "
        "session_cached_cursors, or explicitly closing/reopening cursors between "
        "executions instead of reusing them).",
        "Increase session_cached_cursors / open_cursors if appropriate for the workload.",
    ],
    "redo_nowait": [
        "Increase log_buffer size.",
        "Investigate whether redo generation (see Load Profile 'Redo size') is unusually "
        "high for this workload and whether it can be reduced (e.g. NOLOGGING for bulk "
        "loads where appropriate, reducing unnecessary commits).",
    ],
    "buffer_nowait": [
        "Look for 'buffer busy waits' in the Top Wait Events section — this usually points "
        "to a small number of frequently-updated ('hot') blocks, which can sometimes be "
        "addressed with a different index structure (e.g. reverse key index) or by reducing "
        "contention in the application.",
    ],
}


# ---------------------------------------------------------------------------
# Wait event knowledge base. Keys are matched against the event name with
# re.search(..., re.I), first match wins, so keep more specific patterns
# ahead of generic ones.
# ---------------------------------------------------------------------------
WAIT_EVENT_KB = [
    (r"^db file sequential read", {
        "category": "I/O",
        "plain": (
            "The database is waiting on single-block disk reads — the classic pattern for "
            "index lookups fetching one row at a time. Some of this is normal, but a high "
            "average wait time means the underlying storage is responding slowly, and a "
            "high total time means a lot of the workload is spent waiting on it."
        ),
        "recommendations": [
            "Check average wait time: under ~5-10ms is typically healthy for spinning disk, "
            "under ~1-2ms for SSD/flash storage. Higher than that points to a storage "
            "performance problem worth raising with the storage/infrastructure team.",
            "Look at 'SQL ordered by Reads' for the specific statements driving these waits "
            "and confirm they're using efficient indexes (not scanning far more rows than "
            "needed before filtering).",
            "If the working set doesn't fit in the buffer cache, consider whether more "
            "memory would let more of these reads be served from cache instead of disk.",
        ],
    }),
    (r"^db file scattered read|^direct path read(?! temp)", {
        "category": "I/O",
        "plain": (
            "The database is waiting on multi-block reads, which typically happen during "
            "full table scans or full/fast full index scans. A large amount of time here "
            "often means queries are reading far more data than they need to."
        ),
        "recommendations": [
            "Review 'SQL ordered by Reads' / 'SQL ordered by Gets' for statements doing "
            "large scans, and check whether a missing index would let them avoid the scan.",
            "For genuinely large reporting/batch queries, verify this is expected and that "
            "parallel query or partitioning could speed it up rather than eliminate it.",
            "Confirm statistics are up to date — the optimizer may be choosing a full scan "
            "because it doesn't have accurate information about table/index size.",
        ],
    }),
    (r"^log file sync", {
        "category": "Commit/Redo",
        "plain": (
            "Sessions are waiting for their COMMIT to be confirmed as safely written to the "
            "redo log. This wait happens on every commit, so a high value usually means "
            "either the redo log storage is slow, or the application is committing far more "
            "often than necessary (e.g. after every single row instead of batching)."
        ),
        "recommendations": [
            "Check where redo log files are placed — they should be on fast, low-latency "
            "storage, ideally separate from data files to avoid contention.",
            "Review application commit frequency; batching multiple changes into fewer "
            "commits (where business logic allows) significantly reduces this wait.",
            "Compare with the 'log file parallel write' wait time — if that is also high, "
            "the bottleneck is genuinely the redo write I/O path, not the application.",
        ],
    }),
    (r"^log file parallel write", {
        "category": "Commit/Redo",
        "plain": (
            "This is the time LGWR (the log writer background process) spends physically "
            "writing redo entries to disk. High values point directly at slow storage for "
            "the redo logs."
        ),
        "recommendations": [
            "Move redo log files to faster storage (low-latency SSD/NVMe is ideal).",
            "Verify redo logs aren't sharing a disk/array with heavily-used data files.",
        ],
    }),
    (r"^log file switch", {
        "category": "Commit/Redo",
        "plain": (
            "Sessions are stalling because Oracle is waiting for a redo log switch to "
            "complete — often because checkpointing or archiving hasn't caught up (a "
            "condition often called 'checkpoint incomplete' or 'log file switch (archiving "
            "needed)'). This can bring write activity to a near-halt."
        ),
        "recommendations": [
            "Add more redo log groups and/or increase their size so Oracle has more room "
            "before it must switch and wait.",
            "If waiting on archiving, check the archive destination for space or "
            "performance issues (e.g. a slow or full archive log filesystem/backup target).",
        ],
    }),
    (r"^free buffer waits?", {
        "category": "I/O",
        "plain": (
            "A session needed a free slot in the buffer cache to read a block into, but "
            "every slot was occupied by 'dirty' (modified) blocks not yet written to disk. "
            "This typically means the database writer (DBWR) can't keep up, or the buffer "
            "cache is too small for the write volume."
        ),
        "recommendations": [
            "Check disk write performance for the data files — this is often the true root "
            "cause even though it shows up as a 'buffer' wait.",
            "Consider increasing the buffer cache size, or enabling multiple database "
            "writer processes (DB_WRITER_PROCESSES) if the host has spare CPU.",
        ],
    }),
    (r"^buffer busy wait", {
        "category": "Contention",
        "plain": (
            "Multiple sessions are trying to access the same data block at the same time "
            "(a 'hot block'). This is common on small lookup tables, sequences implemented "
            "as tables, or indexes with monotonically increasing keys."
        ),
        "recommendations": [
            "Identify the hot object (check the segment statistics / 'Segments by Buffer "
            "Busy Waits' section if present in the full report).",
            "For indexes on sequential keys, consider a reverse key index or hash "
            "partitioning to spread inserts across more blocks.",
            "Ensure ASSM (Automatic Segment Space Management) is in use for affected "
            "tablespaces.",
        ],
    }),
    (r"^direct path write temp|^direct path read temp", {
        "category": "Memory/Temp",
        "plain": (
            "The database is spilling sort, hash-join, or temp-table work to the temporary "
            "tablespace on disk because it didn't fit in memory (PGA)."
        ),
        "recommendations": [
            "Increase PGA_AGGREGATE_TARGET / PGA_AGGREGATE_LIMIT so more of this work can "
            "stay in memory.",
            "Review the SQL involved for large sorts, joins, or GROUP BY operations that "
            "might benefit from a supporting index or a rewritten query.",
            "Make sure the temp tablespace itself is on reasonably fast storage.",
        ],
    }),
    (r"^enq: TX", {
        "category": "Locking",
        "plain": (
            "Sessions are waiting on row-level transaction locks — typically because "
            "another session already has the same row(s) locked (e.g. two sessions trying "
            "to update the same row) or there's a unique index/constraint conflict."
        ),
        "recommendations": [
            "Look for blocking sessions during the snapshot window (ASH/blocking session "
            "history if available) to find which transaction is holding the lock.",
            "Review application logic for long-running transactions that hold row locks "
            "longer than necessary, and consider shorter transactions / earlier commits.",
        ],
    }),
    (r"^enq: HW", {
        "category": "Contention",
        "plain": (
            "Sessions are waiting while Oracle allocates new extents above a segment's high "
            "water mark — common with many concurrent inserts into the same table."
        ),
        "recommendations": [
            "Ensure the table uses Automatic Segment Space Management (ASSM).",
            "For very high insert concurrency, consider hash partitioning the table to "
            "spread inserts across multiple segments.",
        ],
    }),
    (r"^enq: ", {
        "category": "Locking",
        "plain": (
            "Sessions are waiting on an internal Oracle enqueue (lock) of some kind. The "
            "specific enqueue type (shown in the event name) determines the cause — this is "
            "worth investigating with a DBA since enqueue waits usually point to a specific, "
            "identifiable contention point."
        ),
        "recommendations": [
            "Identify the exact enqueue type from the event name and look it up — each type "
            "(TX, TM, HW, SQ, etc.) has a distinct, well-documented cause.",
        ],
    }),
    (r"^latch: shared pool|^latch: library cache", {
        "category": "Contention",
        "plain": (
            "Sessions are contending for internal memory structures related to SQL parsing "
            "and the shared pool. This is almost always a symptom of excessive hard "
            "parsing."
        ),
        "recommendations": [
            "Fix application SQL to use bind variables (see Soft Parse Ratio finding if "
            "present).",
            "Consider increasing shared_pool_size if the pool is simply undersized.",
        ],
    }),
    (r"^latch", {
        "category": "Contention",
        "plain": (
            "Sessions are contending for an internal memory latch. The specific latch name "
            "indicates which internal structure is contended."
        ),
        "recommendations": [
            "Identify the specific latch name and research its typical cause; many latch "
            "contention issues trace back to hard parsing or hot-block access patterns.",
        ],
    }),
    (r"^cursor: pin S wait on X|^library cache: mutex X", {
        "category": "Contention",
        "plain": (
            "Sessions are waiting for exclusive access to a SQL cursor that another session "
            "is currently parsing or modifying — usually a sign of heavy hard-parsing "
            "pressure on a small set of statements."
        ),
        "recommendations": [
            "Reduce hard parsing (bind variables, adequate shared_pool_size).",
            "Check for a single statement being hard-parsed extremely frequently and "
            "consider pinning it or fixing the root cause of the reparsing.",
        ],
    }),
    (r"^gc buffer busy|^gc cr request|^gc current block", {
        "category": "RAC/Cluster",
        "plain": (
            "This is a RAC (Real Application Clusters) interconnect wait — the instance is "
            "waiting on a block or cache-fusion message from another instance in the "
            "cluster."
        ),
        "recommendations": [
            "Check the interconnect network for latency/throughput issues (dedicated, "
            "low-latency private network is required for healthy RAC performance).",
            "Look for cross-instance contention on the same hot objects and consider "
            "application-level partitioning of workload by instance if feasible.",
        ],
    }),
    (r"^SQL\*Net message from client|^SQL\*Net more data from client", {
        "category": "Idle/Network",
        "plain": (
            "This is an 'idle' wait — the database is simply waiting for the client "
            "application to send its next request. It is not itself a performance problem "
            "for the database, though a very large value can indicate application-side "
            "think time or network latency between the app and the database worth "
            "investigating separately."
        ),
        "recommendations": [
            "Generally safe to ignore for database tuning purposes; if unexpectedly high, "
            "investigate the application/network path rather than the database.",
        ],
    }),
]


def lookup_wait_event(event_name: str):
    for pattern, info in WAIT_EVENT_KB:
        if re.search(pattern, event_name, re.I):
            return info
    return None


# Thresholds for how much of DB time a single wait event needs to represent
# before we call it out.
WAIT_EVENT_PCT_WARNING = 10.0
WAIT_EVENT_PCT_CRITICAL = 25.0

# Thresholds for db file sequential read average wait, in ms.
SEQ_READ_MS_WARNING = 10.0
SEQ_READ_MS_CRITICAL = 20.0

# CPU-bound threshold: % of DB time spent on CPU.
DB_CPU_PCT_WARNING = 70.0
DB_CPU_PCT_CRITICAL = 90.0

# SQL contribution thresholds (% of total DB time / total metric).
SQL_PCT_WARNING = 10.0
SQL_PCT_CRITICAL = 25.0

# Tablespace IO latency thresholds, ms.
TS_READ_MS_WARNING = 15.0
TS_READ_MS_CRITICAL = 30.0

# Hard parse rate (parses per second) thresholds.
HARD_PARSE_WARNING = 1.0
HARD_PARSE_CRITICAL = 5.0
