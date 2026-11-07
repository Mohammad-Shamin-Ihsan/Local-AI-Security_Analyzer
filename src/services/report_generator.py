"""
Report generator for consolidated security findings.
Produces actionable security reports.
"""
from typing import Dict, List, Any
from datetime import datetime, timezone

from src.services.correlation_engine import (
    correlate_brute_force_attempts,
    correlate_endpoint_scanning,
    correlate_sql_injection_attempts
)


class ReportGenerator:
    """Generates consolidated security reports from correlated findings."""

    def generate_report(
        self,
        chunk_findings: List[Dict[str, Any]],
        patterns: List[Any]
    ) -> Dict[str, Any]:
        """
        Generate comprehensive security report.

        Args:
            chunk_findings: Raw findings from all chunks
            patterns: Correlated attack patterns

        Returns:
            Complete security report
        """
        # Consolidate recurring patterns, retaining uncorrelated model findings.
        attack_findings = self._generate_attack_findings(patterns)
        stats = self._calculate_statistics(attack_findings)

        # Generate executive summary
        summary = self._generate_summary(stats, attack_findings)

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": summary,
            "statistics": stats,
            "attack_findings": attack_findings,
            "raw_chunk_findings": chunk_findings,
            "pattern_count": len(patterns),
            "findings": attack_findings,
            "total_findings": len(attack_findings),
        }

    def _calculate_statistics(
        self,
        findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Calculate security statistics from findings."""
        stats = {
            "total_findings": len(findings),
            "by_severity": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
            "by_type": {},
            "by_ip": {},
            "by_endpoint": {}
        }

        for finding in findings:
            # Count by severity
            severity = finding.get("severity", "Unknown")
            stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1

            # Count by type
            finding_type = finding.get("type", "unknown")
            stats["by_type"][finding_type] = stats["by_type"].get(finding_type, 0) + 1

            # Count by IP
            ip = finding.get("source_ip")
            if ip:
                stats["by_ip"][ip] = stats["by_ip"].get(ip, 0) + 1

            # Count by endpoint
            endpoint = finding.get("endpoint")
            if endpoint:
                stats["by_endpoint"][endpoint] = stats["by_endpoint"].get(endpoint, 0) + 1

        return stats

    def _generate_attack_findings(
        self,
        patterns: List[Any]
    ) -> List[Dict[str, Any]]:
        """Generate consolidated attack findings from patterns."""
        attack_findings = []

        # Apply correlation rules
        brute_force_findings = correlate_brute_force_attempts(patterns)
        attack_findings.extend(brute_force_findings)

        scan_findings = correlate_endpoint_scanning(patterns)
        attack_findings.extend(scan_findings)

        sqli_findings = correlate_sql_injection_attempts(patterns)
        attack_findings.extend(sqli_findings)

        correlated_types = {"brute_force", "endpoint_scan", "sql_injection"}
        for pattern in patterns:
            if pattern.pattern_type in correlated_types:
                continue
            lines = sorted(set(pattern.evidence_lines))
            descriptions = list(dict.fromkeys(
                finding.get("description", "")
                for finding in pattern.findings
                if finding.get("description")
            ))
            evidence = [
                finding.get("evidence")
                for finding in pattern.findings
                if finding.get("evidence")
            ]
            reason = " ".join(descriptions) or (
                f"{pattern.pattern_type.replace('_', ' ').capitalize()} activity "
                f"was reported across {len(lines)} evidence line(s)."
            )
            attack_findings.append({
                "type": pattern.pattern_type,
                "severity": pattern.severity,
                "source_ip": pattern.source_ip,
                "username": pattern.username,
                "endpoint": pattern.endpoint,
                "event_count": pattern.event_count,
                "lines": lines,
                "evidence_lines": lines,
                "reason": reason,
                "description": reason,
                "evidence": evidence,
                "recommendation": pattern.recommendation or "Investigate the cited events.",
            })

        for finding in attack_findings:
            if "lines" not in finding:
                finding["lines"] = finding.get("evidence_lines", [])
            if "evidence_lines" not in finding:
                finding["evidence_lines"] = finding["lines"]
            if "reason" not in finding:
                finding["reason"] = finding.get("description", "")

        return attack_findings

    def _generate_summary(
        self,
        stats: Dict[str, Any],
        attack_findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Generate executive summary."""
        # Calculate risk score
        risk_score = (
            stats["by_severity"].get("Critical", 0) * 10 +
            stats["by_severity"].get("High", 0) * 5 +
            stats["by_severity"].get("Medium", 0) * 2 +
            stats["by_severity"].get("Low", 0)
        )

        # Determine risk level
        if risk_score >= 30:
            risk_level = "CRITICAL"
        elif risk_score >= 15:
            risk_level = "HIGH"
        elif risk_score >= 5:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        # Identify top threats
        top_threats = []
        if stats["by_severity"].get("Critical", 0) > 0:
            top_threats.append("Critical account compromise detected")
        if stats["by_severity"].get("High", 0) > 0:
            top_threats.append("Multiple high-severity attacks")
        if stats.get("by_type", {}).get("endpoint_scan", 0) > 0:
            top_threats.append("Active reconnaissance detected")

        return {
            "risk_level": risk_level,
            "risk_score": risk_score,
            "total_findings": stats.get("total_findings", 0),
            "unique_attack_types": len(stats.get("by_type", {})),
            "unique_sources": len(stats.get("by_ip", {})),
            "top_threats": top_threats,
            "generated_at": datetime.now(timezone.utc).isoformat()
        }
