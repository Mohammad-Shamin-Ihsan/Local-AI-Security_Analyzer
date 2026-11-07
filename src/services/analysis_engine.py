"""Sequential local-model log analysis with persisted findings and correlation."""
import asyncio
import json
import logging
import re
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import httpx

from src.models.database import Database
from src.models.log_models import LogChunk
from src.services.correlation_engine import CorrelationEngine
from src.services.log_chunker import LogChunker
from src.services.ollama_client import OllamaClient
from src.services.prompt_builder import PromptBuilder
from src.services.report_generator import ReportGenerator

logger = logging.getLogger(__name__)


@dataclass
class AnalysisResult:
    """Result of analyzing a single chunk."""

    chunk_id: int
    findings: List[Dict[str, Any]]
    summary: str
    error: Optional[str] = None
    retries: int = 0


class AnalysisEngine:
    """Process one chunk at a time and retain findings across the entire file."""

    MAX_RETRIES = 1
    RETRY_DELAY = 2
    LOGIN_FAILURES_FOR_BRUTE_FORCE = 3
    RATE_WINDOW_SECONDS = 60
    RATE_REQUEST_THRESHOLD = 30

    def __init__(self, db: Database, ollama: OllamaClient):
        self.db = db
        self.ollama = ollama
        self.chunker = LogChunker()
        self.prompt_builder = PromptBuilder()

    async def analyze_log_file(
        self,
        analysis_id: str,
        file_path: str,
        progress_callback: Optional[Callable[[int, int, int], None]] = None
    ) -> Dict[str, Any]:
        chunks = self.chunker.parse_log_file(Path(file_path))
        await self.db.create_analysis(analysis_id, file_path, len(chunks))

        correlation = CorrelationEngine()
        all_findings: List[Dict[str, Any]] = []
        auth_history: Dict[tuple[str, str], Dict[str, Any]] = {}
        scan_history: Dict[str, Dict[str, int]] = defaultdict(dict)
        rate_history: Dict[str, deque[tuple[datetime, int]]] = defaultdict(deque)
        failed_chunks: List[Dict[str, Any]] = []
        context_patterns: Dict[str, Any] = {}

        for chunk in chunks:
            if await self.db.get_chunk_status(analysis_id, chunk.chunk_id) == "completed":
                chunk_findings = await self._load_chunk_findings(
                    analysis_id, chunk.chunk_id
                )
            else:
                rule_findings = self._detect_log_patterns(
                    chunk, auth_history, scan_history, rate_history
                )
                result = await self._analyze_chunk(
                    analysis_id, chunk, context_patterns, retry_count=0
                )
                if result.error:
                    chunk_findings = self._deduplicate_findings(rule_findings)
                    if chunk_findings:
                        await self.db.save_chunk_findings(
                            analysis_id,
                            chunk.chunk_id,
                            chunk_findings,
                            mark_completed=False,
                        )
                    failed_chunks.append({
                        "chunk_id": chunk.chunk_id,
                        "error": result.error,
                    })
                    await self.db.mark_chunk_failed(
                        analysis_id, chunk.chunk_id, result.error
                    )
                    all_findings.extend(chunk_findings)
                    correlation.add_findings(chunk_findings, chunk.chunk_id)
                    self._update_active_patterns(context_patterns, chunk_findings)
                    logger.error(
                        "Analysis %s chunk %s failed: %s",
                        analysis_id, chunk.chunk_id, result.error
                    )
                    if progress_callback:
                        progress_callback(
                            chunk.chunk_id, len(chunks), len(all_findings)
                        )
                    continue

                chunk_findings = self._deduplicate_findings(
                    result.findings + rule_findings
                )
                await self.db.save_chunk_findings(
                    analysis_id, chunk.chunk_id, chunk_findings
                )

            all_findings.extend(chunk_findings)
            correlation.add_findings(chunk_findings, chunk.chunk_id)
            self._update_active_patterns(context_patterns, chunk_findings)
            if progress_callback:
                progress_callback(chunk.chunk_id, len(chunks), len(all_findings))

        patterns = correlation.get_all_patterns()
        report = ReportGenerator().generate_report(all_findings, patterns)
        succeeded = not failed_chunks
        await self.db.complete_analysis(
            analysis_id,
            success=succeeded,
            error_message=(
                f"{len(failed_chunks)} chunk(s) failed" if failed_chunks else None
            )
        )
        return {
            **report,
            "analysis_id": analysis_id,
            "total_chunks": len(chunks),
            "processed_chunks": len(chunks) - len(failed_chunks),
            "failed_chunks": failed_chunks,
            "status": "completed" if succeeded else "partial",
        }

    async def _analyze_chunk(
        self,
        analysis_id: str,
        chunk: LogChunk,
        active_patterns: Dict[str, Any],
        retry_count: int
    ) -> AnalysisResult:
        try:
            log_entries = [self._entry_for_prompt(entry) for entry in chunk.entries]
            system_prompt, user_prompt = self.prompt_builder.build_analysis_prompt(
                log_entries=log_entries,
                chunk_id=chunk.chunk_id,
                start_line=chunk.start_line,
                end_line=chunk.end_line,
                previous_context={"active_patterns": list(active_patterns.values())}
            )
            response = await self.ollama.generate(
                prompt=user_prompt,
                system=system_prompt,
                options=self.prompt_builder.get_model_options()
            )
            parsed = self._parse_model_response(response)
            if parsed.get("error"):
                raise ValueError(parsed["error"])
            findings = [
                normalized
                for finding in parsed["findings"]
                if (normalized := self._normalize_finding(finding, chunk)) is not None
            ]
            return AnalysisResult(
                chunk_id=chunk.chunk_id,
                findings=findings,
                summary=parsed.get("summary", ""),
                retries=retry_count
            )
        except asyncio.CancelledError:
            raise
        except (httpx.TimeoutException, asyncio.TimeoutError) as exc:
            if retry_count < self.MAX_RETRIES:
                await asyncio.sleep(self.RETRY_DELAY * (retry_count + 1))
                return await self._analyze_chunk(
                    analysis_id, chunk, active_patterns, retry_count + 1
                )
            return AnalysisResult(
                chunk_id=chunk.chunk_id,
                findings=[],
                summary="",
                error=f"Local model timed out after {retry_count + 1} attempt(s): {exc}",
                retries=retry_count
            )
        except (httpx.HTTPError, ValueError, json.JSONDecodeError) as exc:
            if retry_count < self.MAX_RETRIES:
                await asyncio.sleep(self.RETRY_DELAY)
                return await self._analyze_chunk(
                    analysis_id, chunk, active_patterns, retry_count + 1
                )
            return AnalysisResult(
                chunk_id=chunk.chunk_id,
                findings=[],
                summary="",
                error=f"Local model call failed after {retry_count + 1} attempt(s): {exc}",
                retries=retry_count
            )
        except Exception as exc:
            logger.exception(
                "Unexpected error analyzing %s chunk %s", analysis_id, chunk.chunk_id
            )
            return AnalysisResult(
                chunk_id=chunk.chunk_id,
                findings=[],
                summary="",
                error=f"Unexpected analysis error: {exc}",
                retries=retry_count
            )

    @staticmethod
    def _entry_for_prompt(entry: Any) -> Dict[str, Any]:
        if entry.is_fragment:
            return {
                "line": entry.line_number,
                "fragment": entry.raw_text,
                "fragment_index": entry.segment_index,
                "fragment_count": entry.segment_count,
            }
        if entry.is_malformed:
            return {"line": entry.line_number, "malformed": entry.raw_text}
        return {"line": entry.line_number, **(entry.data or {})}

    def _normalize_finding(
        self, finding: Dict[str, Any], chunk: LogChunk
    ) -> Optional[Dict[str, Any]]:
        finding_type = finding.get("type") or finding.get("attack_type")
        if not isinstance(finding_type, str) or not finding_type.strip():
            return None

        valid_lines = {entry.line_number for entry in chunk.entries}
        raw_lines = finding.get("lines", [])
        if not isinstance(raw_lines, list):
            return None
        lines = sorted({
            line for line in raw_lines
            if isinstance(line, int) and not isinstance(line, bool) and line in valid_lines
        })
        if not lines:
            return None

        severity_map = {
            "low": "Low",
            "medium": "Medium",
            "high": "High",
            "critical": "Critical",
        }
        severity = severity_map.get(str(finding.get("severity", "")).lower(), "Medium")
        evidence = finding.get("evidence", "")
        if not isinstance(evidence, (str, list, dict)):
            evidence = str(evidence)
        finding_type = finding_type.strip().lower().replace(" ", "_")
        if finding_type.endswith("_attack"):
            finding_type = finding_type[:-7]
        finding_type = {
            "brute_force_login": "brute_force",
            "endpoint_scanning": "endpoint_scan",
            "request_rate_anomaly": "unusual_request_rate",
        }.get(finding_type, finding_type)

        return {
            "type": finding_type[:80],
            "severity": severity,
            "source_ip": self._safe_text(
                finding.get("source_ip") or finding.get("ip")
            ),
            "username": self._safe_text(finding.get("username")),
            "endpoint": self._safe_text(finding.get("endpoint")),
            "lines": lines,
            "auth_result": self._safe_text(finding.get("auth_result")),
            "timestamp_first": self._safe_text(finding.get("timestamp_first")),
            "timestamp_last": self._safe_text(finding.get("timestamp_last")),
            "description": self._safe_text(
                finding.get("description") or finding.get("reason")
            ) or "Suspicious activity supported by the cited log evidence.",
            "reason": self._safe_text(
                finding.get("description") or finding.get("reason")
            ) or "Suspicious activity supported by the cited log evidence.",
            "evidence": evidence,
            "recommendation": self._safe_text(finding.get("recommendation"))
            or "Review the cited events and apply the relevant defensive controls.",
        }

    @staticmethod
    def _safe_text(value: Any) -> Optional[str]:
        if value is None:
            return None
        if isinstance(value, (str, int, float)):
            return str(value)[:1000]
        return None

    def _detect_log_patterns(
        self,
        chunk: LogChunk,
        auth_history: Dict[tuple[str, str], Dict[str, Any]],
        scan_history: Dict[str, Dict[str, int]],
        rate_history: Dict[str, deque[tuple[datetime, int]]]
    ) -> List[Dict[str, Any]]:
        """Add narrowly scoped evidence rules to the model's chunk findings."""
        findings: List[Dict[str, Any]] = []
        auth_events: Dict[tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
        sql_events: Dict[str, List[tuple[int, str, str]]] = defaultdict(list)
        scan_events: Dict[str, List[tuple[int, str]]] = defaultdict(list)
        rate_lines: Dict[str, List[int]] = defaultdict(list)
        sensitive_paths = (
            "/.env", "/.git", "/wp-admin", "/phpmyadmin", "/actuator",
            "/server-status", "/config", "/admin",
        )
        sql_markers = (
            "union select", "or 1=1", "drop table", "sleep(", "benchmark(",
            "waitfor delay", "'--", "%27--", "information_schema",
        )

        for entry in chunk.entries:
            data = entry.data
            if not isinstance(data, dict):
                continue
            ip = self._first_text(
                data, ("source_ip", "client_ip", "remote_addr", "src_ip", "ip")
            )
            username = self._first_text(data, ("username", "user", "account")) or "unknown"
            path = self._first_text(
                data, ("path", "url", "endpoint", "request_uri", "request")
            ) or ""
            lowered_path = path.lower()
            status = str(data.get("status", ""))
            auth_result = str(data.get("auth_result", "")).lower()
            is_login = any(word in lowered_path for word in ("login", "signin", "auth"))
            failed = (
                any(word in auth_result for word in ("fail", "invalid", "denied"))
                or (is_login and status in {"401", "403"})
            )
            succeeded = auth_result in {"success", "successful", "authenticated"} or (
                is_login and status == "200"
            )
            if ip and is_login and (failed or succeeded):
                auth_events[(ip, username)].append({
                    "line": entry.line_number,
                    "result": "failure" if failed else "success",
                    "timestamp": self._first_text(data, ("time", "timestamp", "@timestamp")),
                    "endpoint": path,
                })

            if ip and any(marker in lowered_path for marker in sql_markers):
                sql_events[ip].append((entry.line_number, path, username))

            if ip and status == "404" and any(
                marker in lowered_path for marker in sensitive_paths
            ):
                scan_events[ip].append((entry.line_number, path))

            timestamp = self._parse_timestamp(
                self._first_text(data, ("time", "timestamp", "@timestamp"))
            )
            if ip and timestamp and data.get("path", data.get("url")):
                events = rate_history[ip]
                events.append((timestamp, entry.line_number))
                while events and (timestamp - events[0][0]).total_seconds() > self.RATE_WINDOW_SECONDS:
                    events.popleft()
                if len(events) == self.RATE_REQUEST_THRESHOLD:
                    rate_lines[ip].extend(line for _, line in events)

        for (ip, username), events in auth_events.items():
            key = (ip, username)
            history = auth_history.setdefault(
                key, {"failures": [], "success_lines": set(), "endpoint": None}
            )
            new_failures = [event for event in events if event["result"] == "failure"]
            successes = [event for event in events if event["result"] == "success"]
            history["failures"].extend(
                event for event in new_failures
                if event["line"] not in {old["line"] for old in history["failures"]}
            )
            if events:
                history["endpoint"] = events[-1]["endpoint"]

            if (
                len(history["failures"]) >= self.LOGIN_FAILURES_FOR_BRUTE_FORCE
                and new_failures
            ):
                lines = [event["line"] for event in new_failures]
                findings.append(self._rule_finding(
                    "brute_force",
                    "High" if len(history["failures"]) >= 5 else "Medium",
                    ip,
                    username,
                    history["endpoint"],
                    lines,
                    f"{len(history['failures'])} failed login attempts from {ip} "
                    f"targeting {username}; evidence spans the analyzed log.",
                    "Use rate limits and account lockout controls; review the cited logins.",
                    evidence={"failed_attempts": len(history["failures"])},
                ))

            for event in successes:
                if history["failures"] and event["line"] not in history["success_lines"]:
                    history["success_lines"].add(event["line"])
                    lines = sorted({
                        item["line"] for item in history["failures"][-10:]
                    } | {event["line"]})
                    findings.append(self._rule_finding(
                        "brute_force",
                        "Critical",
                        ip,
                        username,
                        event["endpoint"],
                        lines,
                        f"A successful login for {username} from {ip} followed "
                        f"{len(history['failures'])} failed attempts.",
                        "Verify the login immediately, reset credentials if unauthorized, "
                        "and review the account's subsequent activity.",
                        auth_result="success",
                    ))

        for ip, events in sql_events.items():
            lines = sorted({line for line, _, _ in events})
            endpoints = list(dict.fromkeys(path for _, path, _ in events))[:5]
            findings.append(self._rule_finding(
                "sql_injection",
                "High" if len(lines) >= 3 else "Medium",
                ip,
                None,
                endpoints[0] if endpoints else None,
                lines,
                f"SQL-injection-like syntax was present in {len(lines)} request(s) "
                f"from {ip}; this indicates an attempt, not confirmed exploitation.",
                "Use parameterized queries, review WAF/application logs, and verify "
                "whether any request succeeded.",
                evidence={"endpoints": endpoints},
            ))

        for ip, events in scan_events.items():
            for line, path in events:
                scan_history[ip][path] = line
            if len(scan_history[ip]) >= 3:
                endpoints = list(scan_history[ip])
                findings.append(self._rule_finding(
                    "endpoint_scan",
                    "Medium",
                    ip,
                    None,
                    endpoints[0],
                    sorted(set(line for line, _ in events)),
                    f"{len(endpoints)} distinct sensitive paths returned 404 responses "
                    f"from {ip}, consistent with endpoint reconnaissance.",
                    "Review the requests and apply IP-level controls if the activity "
                    "is not expected.",
                    evidence={"endpoints": endpoints[:10]},
                ))

        for ip, lines in rate_lines.items():
            findings.append(self._rule_finding(
                "unusual_request_rate",
                "Medium",
                ip,
                None,
                None,
                sorted(set(lines)),
                f"{self.RATE_REQUEST_THRESHOLD} or more requests from {ip} occurred "
                f"within {self.RATE_WINDOW_SECONDS} seconds.",
                "Check for legitimate bursts and apply rate limiting if this traffic "
                "is abusive.",
            ))

        return findings

    @staticmethod
    def _first_text(data: Dict[str, Any], keys: tuple[str, ...]) -> Optional[str]:
        for key in keys:
            value = data.get(key)
            if isinstance(value, (str, int, float)) and str(value).strip():
                return str(value)
        return None

    @staticmethod
    def _parse_timestamp(value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None

    @staticmethod
    def _rule_finding(
        finding_type: str,
        severity: str,
        source_ip: Optional[str],
        username: Optional[str],
        endpoint: Optional[str],
        lines: List[int],
        description: str,
        recommendation: str,
        evidence: Any = None,
        auth_result: Optional[str] = None,
    ) -> Dict[str, Any]:
        return {
            "type": finding_type,
            "severity": severity,
            "source_ip": source_ip,
            "username": username,
            "endpoint": endpoint,
            "lines": sorted(set(lines)),
            "description": description,
            "reason": description,
            "evidence": evidence or {},
            "recommendation": recommendation,
            "auth_result": auth_result,
        }

    @staticmethod
    def _deduplicate_findings(
        findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        unique: Dict[tuple[Any, ...], Dict[str, Any]] = {}
        for finding in findings:
            key = (
                finding.get("type"),
                finding.get("source_ip"),
                finding.get("username"),
                tuple(sorted(set(finding.get("lines", [])))),
            )
            if key not in unique:
                unique[key] = finding
                continue
            current = unique[key]
            if finding.get("auth_result") == "success":
                current["auth_result"] = "success"
                current["severity"] = "Critical"
            if not current.get("description") and finding.get("description"):
                current["description"] = finding["description"]
                current["reason"] = finding.get("reason", finding["description"])
            if isinstance(current.get("evidence"), dict) and isinstance(
                finding.get("evidence"), dict
            ):
                current["evidence"].update(finding["evidence"])
        return list(unique.values())

    @staticmethod
    def _parse_model_response(raw_response: str) -> Dict[str, Any]:
        """Parse direct JSON, fenced JSON, or a recoverable JSON object."""
        candidates = [raw_response]
        candidates.extend(
            match.group(1)
            for match in re.finditer(r"```(?:json)?\s*(.*?)```", raw_response, re.S)
        )
        decoder = json.JSONDecoder()
        for candidate in candidates:
            try:
                result = json.loads(candidate.strip())
                if AnalysisEngine._validate_findings(result):
                    return result
            except json.JSONDecodeError:
                pass
            start = candidate.find("{")
            if start >= 0:
                try:
                    result, _ = decoder.raw_decode(candidate[start:])
                    if AnalysisEngine._validate_findings(result):
                        return result
                except json.JSONDecodeError:
                    pass
        return {
            "findings": [],
            "summary": "",
            "error": "Failed to parse model response as complete findings JSON",
        }

    @staticmethod
    def _validate_findings(result: Any) -> bool:
        if not isinstance(result, dict):
            return False
        findings = result.get("findings")
        if not isinstance(findings, list):
            return False
        return all(
            isinstance(finding, dict)
            and isinstance(finding.get("type"), str)
            and isinstance(finding.get("severity"), str)
            for finding in findings
        )

    @staticmethod
    def _update_active_patterns(
        active_patterns: Dict[str, Any],
        new_findings: List[Dict[str, Any]]
    ) -> None:
        """Keep a small summary for the next chunk's prompt."""
        for finding in new_findings:
            pattern_type = finding.get("type", "unknown")
            source_ip = finding.get("source_ip") or "unknown"
            username = finding.get("username")
            key = f"{pattern_type}:{source_ip}:{username}"
            lines = finding.get("lines", [])
            pattern = active_patterns.setdefault(key, {
                "type": pattern_type,
                "ip": source_ip,
                "username": username,
                "failures": 0,
                "first_seen_line": lines[0] if lines else 0,
            })
            if pattern_type == "brute_force":
                pattern["failures"] += len(lines)
            if lines:
                pattern["first_seen_line"] = min(pattern["first_seen_line"], min(lines))
                pattern["last_seen_line"] = max(lines)

    async def _load_chunk_findings(
        self, analysis_id: str, chunk_id: int
    ) -> List[Dict[str, Any]]:
        """Load a completed chunk from SQLite when resuming an analysis."""
        return await self.db.get_chunk_findings(analysis_id, chunk_id)
