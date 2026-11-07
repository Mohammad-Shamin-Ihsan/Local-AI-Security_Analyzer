"""
Correlation engine for cross-chunk attack pattern matching.
Uses deterministic rules alongside AI findings.
"""
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field


@dataclass
class AttackPattern:
    """Represents a correlated attack pattern across chunks."""
    pattern_id: str
    pattern_type: str  # brute_force, sql_injection, path_traversal, etc.
    source_ip: Optional[str]
    username: Optional[str]
    endpoint: Optional[str]
    severity: str  # Low, Medium, High, Critical
    event_count: int
    first_seen_line: int
    last_seen_line: int
    timestamps: List[str] = field(default_factory=list)
    evidence_lines: List[int] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "active"  # active, escalated, resolved
    recommendation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for database storage."""
        return {
            "pattern_id": self.pattern_id,
            "pattern_type": self.pattern_type,
            "source_ip": self.source_ip,
            "username": self.username,
            "endpoint": self.endpoint,
            "severity": self.severity,
            "event_count": self.event_count,
            "first_seen_line": self.first_seen_line,
            "last_seen_line": self.last_seen_line,
            "timestamps": self.timestamps,
            "evidence_lines": self.evidence_lines,
            "status": self.status,
            "recommendation": self.recommendation
        }


class CorrelationEngine:
    """
    Correlates security findings across multiple log chunks.

    Uses deterministic rules based on:
    - Source IP address
    - Username
    - Endpoint path
    - Attack type
    - Timestamp proximity

    This is more reliable than relying on LLM memory for cross-chunk context.
    """

    def __init__(self):
        # Key: (attack_type, ip, username, endpoint)
        self.patterns: Dict[str, AttackPattern] = {}
        self.pattern_counter = 0

    def add_findings(self, findings: List[Dict[str, Any]], chunk_id: int) -> List[AttackPattern]:
        """
        Add findings from a chunk and return updated patterns.

        Args:
            findings: List of findings from chunk analysis
            chunk_id: ID of the chunk these findings came from

        Returns:
            List of attack patterns that were updated or created
        """
        updated_patterns = []

        for finding in findings:
            pattern = self._create_or_update_pattern(finding, chunk_id)
            if pattern:
                updated_patterns.append(pattern)

        return updated_patterns

    def _create_or_update_pattern(
        self,
        finding: Dict[str, Any],
        chunk_id: int
    ) -> Optional[AttackPattern]:
        """
        Create new pattern or update existing one.

        Deterministic correlation key: (attack_type, ip, username, endpoint)
        """
        attack_type = finding.get("type", "unknown")
        source_ip = finding.get("source_ip")
        username = finding.get("username")
        endpoint = finding.get("endpoint")

        # Create correlation key
        key = self._make_key(attack_type, source_ip, username, endpoint)

        if key in self.patterns:
            # Update existing pattern
            pattern = self.patterns[key]
            self._update_pattern(pattern, finding, chunk_id)
            return pattern
        else:
            # Create new pattern
            return self._create_pattern(finding, chunk_id, key)

    def _make_key(
        self,
        attack_type: str,
        source_ip: Optional[str],
        username: Optional[str],
        endpoint: Optional[str]
    ) -> str:
        """Create correlation key from pattern attributes."""
        if attack_type in {"endpoint_scan", "sql_injection"}:
            endpoint = None
        return f"{attack_type}:{source_ip or 'none'}:{username or 'none'}:{endpoint or 'none'}"

    def _create_pattern(
        self,
        finding: Dict[str, Any],
        chunk_id: int,
        key: str
    ) -> AttackPattern:
        """Create a new attack pattern."""
        self.pattern_counter += 1

        lines = sorted(set(finding.get("lines", [])))
        timestamp = finding.get("timestamp_first") or ""

        pattern = AttackPattern(
            pattern_id=f"pattern-{self.pattern_counter:04d}",
            pattern_type=finding.get("type", "unknown"),
            source_ip=finding.get("source_ip"),
            username=finding.get("username"),
            endpoint=finding.get("endpoint"),
            severity=finding.get("severity", "Low"),
            event_count=len(lines),
            first_seen_line=lines[0] if lines else 0,
            last_seen_line=lines[-1] if lines else 0,
            timestamps=[timestamp] if timestamp else [],
            evidence_lines=lines.copy(),
            findings=[finding]
        )

        # Set initial recommendation based on attack type
        pattern.recommendation = self._get_initial_recommendation(pattern)
        if finding.get("auth_result") == "success":
            pattern.status = "escalated"
            pattern.recommendation = (
                "Possible account compromise. Verify the login, reset credentials "
                "if unauthorized, and review subsequent account activity."
            )

        self.patterns[key] = pattern
        return pattern

    def _update_pattern(
        self,
        pattern: AttackPattern,
        finding: Dict[str, Any],
        chunk_id: int
    ) -> None:
        """Update existing pattern with new finding."""
        lines = sorted(set(finding.get("lines", [])))
        timestamp = finding.get("timestamp_first") or ""

        # Update line numbers
        if lines:
            pattern.evidence_lines = sorted(set(pattern.evidence_lines).union(lines))
            pattern.first_seen_line = min(
                pattern.first_seen_line,
                min(lines)
            )
            pattern.last_seen_line = max(
                pattern.last_seen_line,
                max(lines)
            )

        # Update timestamps
        if timestamp:
            pattern.timestamps.append(timestamp)

        # Update event count
        pattern.event_count = len(pattern.evidence_lines)

        # Store new finding
        pattern.findings.append(finding)

        # Escalate severity if needed
        new_severity = finding.get("severity", "Low")
        if self._severity_rank(new_severity) > self._severity_rank(pattern.severity):
            pattern.severity = new_severity

        # Update recommendation if this is a successful breach
        if finding.get("auth_result") == "success":
            pattern.recommendation = (
                "URGENT: Account may be compromised. Verify user activity, "
                "reset credentials, and review access logs."
            )
            pattern.status = "escalated"

    def _severity_rank(self, severity: str) -> int:
        """Return numeric rank for severity comparison."""
        ranks = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
        return ranks.get(severity, 0)

    def _get_initial_recommendation(self, pattern: AttackPattern) -> str:
        """Get recommendation based on attack type."""
        recommendations = {
            "brute_force": "Consider implementing account lockout policy",
            "sql_injection": "Review input validation and use parameterized queries",
            "path_traversal": "Validate file path inputs and restrict access",
            "endpoint_scan": "Review web server access logs for suspicious patterns",
            "rate_limit_trigger": "Ensure rate limiting is configured correctly",
            "prompt_injection": "Verify input sanitization and content filters",
            "unauthorized_access": "Review access control policies",
            "data_exfiltration": "Investigate data access patterns immediately"
        }
        return recommendations.get(pattern.pattern_type, "Investigate this finding")

    def get_all_patterns(self) -> List[AttackPattern]:
        """Get all correlated attack patterns."""
        return list(self.patterns.values())

    def get_patterns_by_type(self, pattern_type: str) -> List[AttackPattern]:
        """Get patterns filtered by type."""
        return [p for p in self.patterns.values() if p.pattern_type == pattern_type]

    def get_patterns_by_severity(self, severity: str) -> List[AttackPattern]:
        """Get patterns filtered by severity."""
        return [p for p in self.patterns.values() if p.severity == severity]

    def clear(self) -> None:
        """Clear all patterns (for testing)."""
        self.patterns.clear()
        self.pattern_counter = 0


def correlate_brute_force_attempts(patterns: List[AttackPattern]) -> List[Dict[str, Any]]:
    """
    Correlate brute force attempts to identify successful compromises.

    Returns consolidated findings with complete attack narrative.
    """
    results = []

    for pattern in patterns:
        if pattern.pattern_type != "brute_force":
            continue

        # Check if this pattern includes a successful login
        has_success = any(
            f.get("auth_result") == "success"
            for f in pattern.findings
        )

        if has_success:
            severity = "Critical"
            recommendation = (
                "URGENT: Account compromise likely! "
                "Immediate actions: "
                "1. Disable or reset account, "
                "2. Review session activity, "
                "3. Check for unauthorized data access, "
                "4. Review firewall logs for lateral movement"
            )
        else:
            severity = "High" if pattern.event_count >= 5 else "Medium"
            recommendation = (
                "Implement account lockout policy (3-5 failed attempts) "
                "and consider IP-based blocking"
            )

        if has_success:
            description = (
                f"Repeated failed logins targeting {pattern.username or 'user'} from "
                f"{pattern.source_ip or 'unknown IP'} were followed by a successful "
                f"login. Evidence spans lines {pattern.first_seen_line}-"
                f"{pattern.last_seen_line}."
            )
        else:
            description = (
                f"Brute force attack detected targeting {pattern.username or 'user'} "
                f"from {pattern.source_ip or 'unknown IP'}. "
                f"{pattern.event_count} authentication attempts across "
                f"lines {pattern.first_seen_line}-{pattern.last_seen_line}."
            )

        results.append({
            "type": "brute_force",
            "severity": severity,
            "source_ip": pattern.source_ip,
            "username": pattern.username,
            "endpoint": pattern.endpoint,
            "event_count": pattern.event_count,
            "first_attempt_line": pattern.first_seen_line,
            "last_attempt_line": pattern.last_seen_line,
            "evidence_lines": pattern.evidence_lines,
            "lines": pattern.evidence_lines,
            "reason": description,
            "description": description,
            "recommendation": recommendation
        })

    return results


def correlate_endpoint_scanning(patterns: List[AttackPattern]) -> List[Dict[str, Any]]:
    """
    Correlate endpoint scanning to identify reconnaissance activity.

    Detects systematic probing of sensitive endpoints.
    """
    results = []

    for pattern in patterns:
        if pattern.pattern_type != "endpoint_scan":
            continue

        # Count unique endpoints scanned
        unique_endpoints = set()
        for finding in pattern.findings:
            if finding.get("endpoint"):
                unique_endpoints.add(finding["endpoint"])
                unique_endpoints.update(finding.get("endpoints", []))

        if len(unique_endpoints) >= 3:
            severity = "Medium"
            description = (
                f"Endpoint scanning detected from {pattern.source_ip}. "
                f"{len(unique_endpoints)} sensitive endpoints probed: "
                f"{', '.join(sorted(unique_endpoints)[:5])}"
            )
        else:
            severity = "Low"
            description = (
                f"Suspicious endpoint access from {pattern.source_ip}. "
                f"Consider reviewing web server logs."
            )

        results.append({
            "type": "endpoint_scan",
            "severity": severity,
            "source_ip": pattern.source_ip,
            "unique_endpoints": list(unique_endpoints),
            "event_count": pattern.event_count,
            "first_seen_line": pattern.first_seen_line,
            "last_seen_line": pattern.last_seen_line,
            "evidence_lines": pattern.evidence_lines,
            "username": pattern.username,
            "endpoint": None,
            "lines": pattern.evidence_lines,
            "reason": description,
            "description": description,
            "recommendation": "Review web server access logs and consider blocking IP"
        })

    return results


def correlate_sql_injection_attempts(patterns: List[AttackPattern]) -> List[Dict[str, Any]]:
    """
    Correlate SQL injection attempts.

    Detects crafted SQL payloads in query parameters.
    """
    results = []

    for pattern in patterns:
        if pattern.pattern_type != "sql_injection":
            continue

        # Count unique payloads
        payloads = set()
        for finding in pattern.findings:
            candidates = [finding.get("endpoint")]
            candidates.extend(finding.get("endpoints", []))
            evidence = finding.get("evidence")
            if isinstance(evidence, dict):
                candidates.extend(evidence.get("endpoints", []))
            for endpoint in candidates:
                if not isinstance(endpoint, str):
                    continue
                # Extract SQL-like patterns from endpoint
                if any(kw in endpoint.lower() for kw in [
                    "union", "select", "or 1=1", "sleep", "drop", "--"
                ]):
                    payloads.add(endpoint[:100])

        severity = "High" if len(payloads) >= 2 else "Medium"

        results.append({
            "type": "sql_injection",
            "severity": severity,
            "source_ip": pattern.source_ip,
            "username": pattern.username,
            "endpoint": pattern.endpoint,
            "event_count": len(pattern.evidence_lines),
            "payload_count": len(payloads),
            "first_seen_line": pattern.first_seen_line,
            "last_seen_line": pattern.last_seen_line,
            "evidence_lines": pattern.evidence_lines,
            "lines": pattern.evidence_lines,
            "reason": (
                f"SQL injection attempts detected from {pattern.source_ip}. "
                f"{len(payloads)} unique payloads observed."
            ),
            "description": (
                f"SQL injection attempts detected from {pattern.source_ip}. "
                f"{len(payloads)} unique payloads observed."
            ),
            "recommendation": "Review application input validation, use parameterized queries, and check WAF logs"
        })

    return results
