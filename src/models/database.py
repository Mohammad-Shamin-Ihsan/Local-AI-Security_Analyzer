"""
SQLite database schema and operations.
Stores findings, attack patterns, and analysis state.
"""
import aiosqlite
import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone


class Database:
    """Async SQLite database manager for security analysis."""

    def __init__(self, db_path: Path):
        self.db_path = db_path

    async def initialize(self) -> None:
        """Create database tables if they don't exist."""
        async with aiosqlite.connect(self.db_path) as db:
            # Raw findings from each chunk
            await db.execute("""
                CREATE TABLE IF NOT EXISTS chunk_findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id TEXT NOT NULL,
                    chunk_id INTEGER NOT NULL,
                    finding_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    source_ip TEXT,
                    username TEXT,
                    endpoint TEXT,
                    evidence_lines TEXT NOT NULL,
                    timestamp_first TEXT,
                    timestamp_last TEXT,
                    description TEXT NOT NULL,
                    raw_evidence TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(analysis_id, chunk_id, finding_type, source_ip, username, endpoint)
                )
            """)

            # Correlated attack patterns across chunks
            await db.execute("""
                CREATE TABLE IF NOT EXISTS attack_patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id TEXT NOT NULL,
                    pattern_type TEXT NOT NULL,
                    source_ip TEXT,
                    username TEXT,
                    endpoint TEXT,
                    severity TEXT NOT NULL,
                    event_count INTEGER DEFAULT 1,
                    evidence_lines TEXT NOT NULL,
                    timestamp_first TEXT,
                    timestamp_last TEXT,
                    status TEXT DEFAULT 'active',
                    description TEXT NOT NULL,
                    recommendation TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)

            # Analysis state for resume capability
            await db.execute("""
                CREATE TABLE IF NOT EXISTS analysis_state (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id TEXT UNIQUE NOT NULL,
                    log_file_path TEXT NOT NULL,
                    total_chunks INTEGER NOT NULL,
                    processed_chunks INTEGER DEFAULT 0,
                    status TEXT DEFAULT 'pending',
                    started_at TIMESTAMP,
                    completed_at TIMESTAMP,
                    error_message TEXT
                )
            """)

            # Chunk processing status for idempotency
            await db.execute("""
                CREATE TABLE IF NOT EXISTS chunk_status (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id TEXT NOT NULL,
                    chunk_id INTEGER NOT NULL,
                    status TEXT DEFAULT 'pending',
                    error_message TEXT,
                    processed_at TIMESTAMP,
                    UNIQUE(analysis_id, chunk_id)
                )
            """)

            await db.commit()

    async def create_analysis(
        self,
        analysis_id: str,
        log_file_path: str,
        total_chunks: int
    ) -> None:
        """Create an analysis, or reset its state when resuming it."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO analysis_state
                (analysis_id, log_file_path, total_chunks, status, started_at)
                VALUES (?, ?, ?, 'running', ?)
                ON CONFLICT(analysis_id) DO UPDATE SET
                    log_file_path = excluded.log_file_path,
                    total_chunks = excluded.total_chunks,
                    status = 'running',
                    completed_at = NULL,
                    error_message = NULL
                """,
                (
                    analysis_id,
                    log_file_path,
                    total_chunks,
                    datetime.now(timezone.utc).isoformat()
                )
            )
            await db.commit()

    async def save_chunk_findings(
        self,
        analysis_id: str,
        chunk_id: int,
        findings: List[Dict[str, Any]],
        mark_completed: bool = True,
    ) -> None:
        """Save chunk findings and optionally mark the model call complete."""
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT status FROM chunk_status WHERE analysis_id = ? AND chunk_id = ?",
                (analysis_id, chunk_id)
            ) as cursor:
                previous = await cursor.fetchone()

            for finding in findings:
                identity = (
                    analysis_id,
                    chunk_id,
                    finding.get("type"),
                    finding.get("source_ip"),
                    finding.get("username"),
                    finding.get("endpoint"),
                )
                async with db.execute(
                    """
                    SELECT id, evidence_lines, raw_evidence, description,
                           timestamp_first, timestamp_last, severity
                    FROM chunk_findings
                    WHERE analysis_id = ? AND chunk_id = ? AND finding_type = ?
                      AND source_ip IS ? AND username IS ? AND endpoint IS ?
                    """,
                    identity
                ) as cursor:
                    existing = await cursor.fetchone()

                lines = sorted(set(finding.get("lines", [])))
                evidence = finding.get("evidence", {})
                metadata = {
                    key: finding[key]
                    for key in ("auth_result", "recommendation", "reason", "endpoints")
                    if key in finding
                }
                description = finding.get("description") or finding.get("reason") or ""
                first_time = finding.get("timestamp_first")
                last_time = finding.get("timestamp_last")
                severity = finding.get("severity", "Low")
                if existing:
                    lines = sorted(set(lines).union(json.loads(existing[1])))
                    old_data = json.loads(existing[2]) if existing[2] else {}
                    if isinstance(old_data, dict) and "_metadata" in old_data:
                        old_metadata = old_data["_metadata"]
                        old_evidence = old_data.get("evidence", {})
                    else:
                        old_metadata = {}
                        old_evidence = old_data
                    if isinstance(old_evidence, dict) and isinstance(evidence, dict):
                        evidence = {**old_evidence, **evidence}
                    metadata = {**old_metadata, **metadata}
                    if not description:
                        description = existing[3]
                    first_time = first_time or existing[4]
                    last_time = last_time or existing[5]
                    severity_rank = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
                    if severity_rank.get(existing[6], 0) > severity_rank.get(severity, 0):
                        severity = existing[6]
                    await db.execute(
                        """
                        UPDATE chunk_findings
                        SET severity = ?, evidence_lines = ?, timestamp_first = ?,
                            timestamp_last = ?, description = ?, raw_evidence = ?
                        WHERE id = ?
                        """,
                        (
                            severity,
                            json.dumps(lines),
                            first_time,
                            last_time,
                            description,
                            json.dumps(
                                {"evidence": evidence, "_metadata": metadata},
                                ensure_ascii=False
                            ),
                            existing[0],
                        )
                    )
                else:
                    await db.execute(
                        """
                        INSERT INTO chunk_findings
                        (analysis_id, chunk_id, finding_type, severity, source_ip,
                         username, endpoint, evidence_lines, timestamp_first,
                         timestamp_last, description, raw_evidence)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            analysis_id,
                            chunk_id,
                            finding.get("type"),
                            finding.get("severity"),
                            finding.get("source_ip"),
                            finding.get("username"),
                            finding.get("endpoint"),
                            json.dumps(lines),
                            first_time,
                            last_time,
                            description,
                            json.dumps(
                                {"evidence": evidence, "_metadata": metadata},
                                ensure_ascii=False
                            ),
                        )
                    )

            if mark_completed:
                await db.execute(
                    """
                    INSERT INTO chunk_status
                    (analysis_id, chunk_id, status, error_message, processed_at)
                    VALUES (?, ?, 'completed', NULL, ?)
                    ON CONFLICT(analysis_id, chunk_id) DO UPDATE SET
                        status = 'completed',
                        error_message = NULL,
                        processed_at = excluded.processed_at
                    """,
                    (analysis_id, chunk_id, datetime.now(timezone.utc).isoformat())
                )

                if not previous or previous[0] != "completed":
                    await db.execute(
                        """
                        UPDATE analysis_state
                        SET processed_chunks = processed_chunks + 1
                        WHERE analysis_id = ?
                        """,
                        (analysis_id,)
                    )

            await db.commit()

    async def mark_chunk_failed(
        self,
        analysis_id: str,
        chunk_id: int,
        error_message: str
    ) -> None:
        """Persist a failed chunk without discarding earlier successful results."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                INSERT INTO chunk_status
                (analysis_id, chunk_id, status, error_message)
                VALUES (?, ?, 'failed', ?)
                ON CONFLICT(analysis_id, chunk_id) DO UPDATE SET
                    status = 'failed',
                    error_message = excluded.error_message
                """,
                (analysis_id, chunk_id, error_message[:1000])
            )
            await db.commit()

    async def get_chunk_status(
        self,
        analysis_id: str,
        chunk_id: int
    ) -> Optional[str]:
        """Check if chunk has already been processed (for idempotency)."""
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                "SELECT status FROM chunk_status WHERE analysis_id = ? AND chunk_id = ?",
                (analysis_id, chunk_id)
            ) as cursor:
                row = await cursor.fetchone()
                return row[0] if row else None

    async def get_analysis_progress(self, analysis_id: str) -> Dict[str, Any]:
        """Get current analysis progress."""
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                """
                SELECT total_chunks, processed_chunks, status, error_message
                FROM analysis_state
                WHERE analysis_id = ?
                """,
                (analysis_id,)
            ) as cursor:
                row = await cursor.fetchone()
                if row:
                    return {
                        "total_chunks": row[0],
                        "processed_chunks": row[1],
                        "status": row[2],
                        "error_message": row[3]
                    }
                return {}

    async def get_chunk_findings(
        self,
        analysis_id: str,
        chunk_id: int
    ) -> List[Dict[str, Any]]:
        """Load the durable findings for a single completed chunk."""
        findings = await self.get_all_findings(analysis_id)
        return [
            finding for finding in findings
            if finding.get("chunk_id") == chunk_id
        ]

    async def get_all_findings(self, analysis_id: str) -> List[Dict[str, Any]]:
        """Retrieve all findings for an analysis."""
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(
                """
                SELECT chunk_id, finding_type, severity, source_ip, username, endpoint,
                       evidence_lines, timestamp_first, timestamp_last,
                       description, raw_evidence
                FROM chunk_findings
                WHERE analysis_id = ?
                ORDER BY timestamp_first
                """,
                (analysis_id,)
            ) as cursor:
                findings = []
                async for row in cursor:
                    stored = json.loads(row[10]) if row[10] else {}
                    if isinstance(stored, dict) and "_metadata" in stored:
                        evidence = stored.get("evidence", {})
                        metadata = stored["_metadata"]
                    else:
                        evidence = stored
                        metadata = {}
                    findings.append({
                        "chunk_id": row[0],
                        "type": row[1],
                        "severity": row[2],
                        "source_ip": row[3],
                        "username": row[4],
                        "endpoint": row[5],
                        "lines": json.loads(row[6]),
                        "timestamp_first": row[7],
                        "timestamp_last": row[8],
                        "description": row[9],
                        "evidence": evidence,
                        **metadata,
                    })
                return findings

    async def complete_analysis(
        self,
        analysis_id: str,
        success: bool = True,
        error_message: Optional[str] = None
    ) -> None:
        """Mark analysis as completed or failed."""
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                """
                UPDATE analysis_state
                SET status = ?,
                    completed_at = ?,
                    error_message = ?
                WHERE analysis_id = ?
                """,
                (
                    'completed' if success else 'failed',
                    datetime.now(timezone.utc).isoformat(),
                    error_message,
                    analysis_id
                )
            )
            await db.commit()
