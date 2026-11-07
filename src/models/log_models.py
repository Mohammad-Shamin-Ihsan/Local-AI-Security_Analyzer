"""
Data models for log entries and chunks.
"""
from dataclasses import dataclass
from typing import Dict, Any, Optional, List


@dataclass
class LogEntry:
    """
    Represents a single log line with metadata.

    Attributes:
        line_number: Original line number in the file (1-indexed)
        data: Parsed JSON data (None if malformed)
        raw_text: Original raw text of the line
        is_malformed: True if JSON parsing failed
        parse_error: Error message if parsing failed
        token_count: Estimated token count for this entry
    """
    line_number: int
    raw_text: str
    token_count: int
    data: Optional[Dict[str, Any]] = None
    is_malformed: bool = False
    parse_error: Optional[str] = None
    segment_index: Optional[int] = None
    segment_count: Optional[int] = None

    @property
    def is_fragment(self) -> bool:
        return self.segment_index is not None

    def __repr__(self) -> str:
        status = "malformed" if self.is_malformed else "valid"
        return f"LogEntry(line={self.line_number}, {status}, {self.token_count} tokens)"


@dataclass
class LogChunk:
    """
    Represents a chunk of log entries that fits within token budget.

    Attributes:
        chunk_id: Zero-indexed chunk identifier
        start_line: First line number in this chunk
        end_line: Last line number in this chunk
        entries: List of log entries in this chunk
        token_count: Total token count for all entries
        has_oversized_entries: True if any entry exceeded max chunk size
        has_malformed_entries: True if any entry failed to parse
    """
    chunk_id: int
    start_line: int
    end_line: int
    entries: List[LogEntry]
    token_count: int
    has_oversized_entries: bool = False
    has_malformed_entries: bool = False

    def __post_init__(self):
        """Calculate flags from entries."""
        self.has_malformed_entries = any(e.is_malformed for e in self.entries)

    def __repr__(self) -> str:
        flags = []
        if self.has_oversized_entries:
            flags.append("oversized")
        if self.has_malformed_entries:
            flags.append("malformed")

        flag_str = f" [{', '.join(flags)}]" if flags else ""
        return (
            f"LogChunk(id={self.chunk_id}, lines={self.start_line}-{self.end_line}, "
            f"entries={len(self.entries)}, tokens={self.token_count}{flag_str})"
        )
