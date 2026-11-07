"""
Log file chunking service.
Splits log files into token-aware chunks while preserving line numbers.
"""
import json
from pathlib import Path
from typing import Any, Dict, List

from src.models.log_models import LogEntry, LogChunk
from src.utils.tokenizer import token_counter
from src.config import Config


class LogChunker:
    """
    Chunks log files into token-limited segments.

    Design principles:
    - Never load entire file into memory (stream line-by-line)
    - Preserve original line numbers for all entries
    - Handle malformed JSON gracefully (preserve raw text)
    - Handle oversized entries (single entry > max_tokens)
    - Maintain chronological order
    """

    def __init__(self, max_chunk_tokens: int = None):
        """
        Initialize chunker.

        Args:
            max_chunk_tokens: Maximum tokens per chunk (default from config)
        """
        self.max_chunk_tokens = (
            Config.MAX_CHUNK_TOKENS if max_chunk_tokens is None else max_chunk_tokens
        )
        if self.max_chunk_tokens < 1:
            raise ValueError("max_chunk_tokens must be positive")

    def parse_log_file(self, file_path: Path) -> List[LogChunk]:
        """
        Parse and chunk a log file.

        Args:
            file_path: Path to log file (.log or .txt with JSONL format)

        Returns:
            List of LogChunk objects

        Raises:
            FileNotFoundError: If file doesn't exist
            UnicodeDecodeError: If file is not valid UTF-8
        """
        if not file_path.exists():
            raise FileNotFoundError(f"Log file not found: {file_path}")

        chunks: List[LogChunk] = []
        current_entries: List[LogEntry] = []
        current_tokens = 0

        with open(file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, start=1):
                line = line.rstrip('\n\r')  # Remove line endings only

                # Skip empty lines but preserve line number continuity
                if not line.strip():
                    continue

                entry = self._parse_line(line, line_num)
                entries = (
                    [entry]
                    if entry.token_count <= self.max_chunk_tokens
                    else self._split_oversized_entry(entry)
                )

                for entry_part in entries:
                    if (
                        current_entries
                        and current_tokens + entry_part.token_count > self.max_chunk_tokens
                    ):
                        chunks.append(self._create_chunk(
                            chunk_id=len(chunks),
                            start_line=current_entries[0].line_number,
                            end_line=current_entries[-1].line_number,
                            entries=current_entries,
                            token_count=current_tokens,
                            has_oversized=any(item.is_fragment for item in current_entries)
                        ))
                        current_entries = []
                        current_tokens = 0

                    current_entries.append(entry_part)
                    current_tokens += entry_part.token_count

        # Add final chunk if not empty
        if current_entries:
            chunks.append(self._create_chunk(
                chunk_id=len(chunks),
                start_line=current_entries[0].line_number,
                end_line=current_entries[-1].line_number,
                entries=current_entries,
                token_count=current_tokens,
                has_oversized=any(item.is_fragment for item in current_entries)
            ))

        # Handle empty file
        if not chunks:
            chunks.append(self._create_empty_chunk())

        return chunks

    def _parse_line(self, line: str, line_num: int) -> LogEntry:
        """
        Parse a single log line.

        Args:
            line: Raw log line text
            line_num: Original line number (1-indexed)

        Returns:
            LogEntry with parsed data or error information
        """
        # Attempt JSON parse
        try:
            data = json.loads(line)
            if not isinstance(data, dict):
                data = {"_value": data}
            entry = LogEntry(
                line_number=line_num,
                raw_text=line,
                token_count=0,
                data=data,
                is_malformed=False
            )
        except json.JSONDecodeError as e:
            # Preserve malformed line with error info
            entry = LogEntry(
                line_number=line_num,
                raw_text=line,
                token_count=0,
                data=None,
                is_malformed=True,
                parse_error=f"JSON parse error at position {e.pos}: {e.msg}"
            )
        entry.token_count = self._entry_token_count(entry)
        return entry

    def _prompt_entry(self, entry: LogEntry) -> Dict[str, Any]:
        if entry.is_fragment:
            return {
                "line": entry.line_number,
                "fragment": entry.raw_text,
                "fragment_index": entry.segment_index,
                "fragment_count": entry.segment_count,
            }
        if entry.is_malformed:
            return {
                "line": entry.line_number,
                "malformed": entry.raw_text,
            }
        return {"line": entry.line_number, **(entry.data or {})}

    def _entry_token_count(self, entry: LogEntry) -> int:
        serialized = json.dumps(
            [self._prompt_entry(entry)],
            ensure_ascii=False,
            separators=(",", ":")
        )
        return token_counter.count_tokens(serialized)

    def _split_oversized_entry(self, entry: LogEntry) -> List[LogEntry]:
        """Split a single oversized physical line while retaining its source line."""
        fragments = []
        cursor = 0
        text = entry.raw_text
        while cursor < len(text):
            low, high = cursor + 1, len(text)
            best = cursor
            while low <= high:
                middle = (low + high) // 2
                candidate = LogEntry(
                    line_number=entry.line_number,
                    raw_text=text[cursor:middle],
                    token_count=0,
                    segment_index=999999,
                    segment_count=999999,
                )
                if self._entry_token_count(candidate) <= self.max_chunk_tokens:
                    best = middle
                    low = middle + 1
                else:
                    high = middle - 1

            if best == cursor:
                raise ValueError(
                    f"Token limit {self.max_chunk_tokens} is too small to hold "
                    f"an entry fragment from line {entry.line_number}"
                )

            fragments.append(text[cursor:best])
            cursor = best

        total = len(fragments)
        result = [
            LogEntry(
                line_number=entry.line_number,
                raw_text=fragment,
                token_count=0,
                segment_index=index,
                segment_count=total,
            )
            for index, fragment in enumerate(fragments, start=1)
        ]
        for fragment in result:
            fragment.token_count = self._entry_token_count(fragment)
        return result

    def _create_chunk(
        self,
        chunk_id: int,
        start_line: int,
        end_line: int,
        entries: List[LogEntry],
        token_count: int,
        has_oversized: bool = False
    ) -> LogChunk:
        """Create a LogChunk object."""
        return LogChunk(
            chunk_id=chunk_id,
            start_line=start_line,
            end_line=end_line,
            entries=entries,
            token_count=token_count,
            has_oversized_entries=has_oversized
        )

    def _create_empty_chunk(self) -> LogChunk:
        """Create an empty chunk (for empty files)."""
        return LogChunk(
            chunk_id=0,
            start_line=0,
            end_line=0,
            entries=[],
            token_count=0
        )
