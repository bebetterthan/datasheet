"""
Reporter Module
===============

Generates comprehensive security assessment reports.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
import json

from agent.utils.logger import get_logger


class Reporter:
    """
    Reporter module for the Red Team Agent.
    
    Generates structured reports from task execution results.
    Supports multiple output formats: JSON, Markdown, HTML.
    
    Report Structure:
        - Executive Summary
        - Technical Findings
        - Remediation Recommendations
        - Evidence/Logs
    """
    
    SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
    SEVERITY_COLORS = {
        "critical": "#FF0000",
        "high": "#FF6600",
        "medium": "#FFCC00",
        "low": "#66CC00",
        "info": "#0066CC"
    }
    
    def __init__(self, llm: Optional[Any] = None):
        """
        Initialize Reporter.
        
        Args:
            llm: LLM provider for generating summaries
        """
        self.llm = llm
        self.logger = get_logger("Reporter")
        
    def generate(
        self,
        task: str,
        findings: List[Dict[str, Any]],
        execution_log: List[Dict[str, Any]],
        memory_export: Dict[str, Any],
        format: str = "json"
    ) -> Dict[str, Any]:
        """
        Generate a complete report.
        
        Args:
            task: Original task description
            findings: List of findings from observer
            execution_log: Log of all executed steps
            memory_export: Exported memory state
            format: Output format ("json", "markdown", "html")
            
        Returns:
            Generated report in specified format
        """
        self.logger.info(f"Generating {format} report...")
        
        # Build base report structure
        report = self._build_report_structure(
            task=task,
            findings=findings,
            execution_log=execution_log
        )
        
        # Generate executive summary
        report["executive_summary"] = self._generate_executive_summary(
            task, findings
        )
        
        # Generate recommendations
        report["recommendations"] = self._generate_recommendations(findings)
        
        # Format output
        if format == "markdown":
            return self._format_markdown(report)
        elif format == "html":
            return self._format_html(report)
        else:
            return report
            
    def _build_report_structure(
        self,
        task: str,
        findings: List[Dict[str, Any]],
        execution_log: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Build the base report structure."""
        # Sort findings by severity
        sorted_findings = self._sort_findings_by_severity(findings)
        
        # Calculate statistics
        stats = self._calculate_statistics(findings)
        
        return {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "task": task,
                "total_findings": len(findings),
                "steps_executed": len(execution_log),
                "agent_version": "0.1.0"
            },
            "statistics": stats,
            "findings": sorted_findings,
            "execution_timeline": self._build_timeline(execution_log),
            "executive_summary": "",
            "recommendations": []
        }
        
    def _sort_findings_by_severity(
        self,
        findings: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Sort findings by severity (critical first)."""
        def severity_key(f):
            sev = f.get("severity", "info").lower()
            try:
                return self.SEVERITY_ORDER.index(sev)
            except ValueError:
                return len(self.SEVERITY_ORDER)
                
        return sorted(findings, key=severity_key)
        
    def _calculate_statistics(
        self,
        findings: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Calculate finding statistics."""
        stats = {
            "by_severity": {},
            "by_type": {},
            "total": len(findings)
        }
        
        for f in findings:
            # By severity
            sev = f.get("severity", "info").lower()
            stats["by_severity"][sev] = stats["by_severity"].get(sev, 0) + 1
            
            # By type
            ftype = f.get("type", "unknown")
            stats["by_type"][ftype] = stats["by_type"].get(ftype, 0) + 1
            
        # Calculate risk score (simple weighted sum)
        severity_weights = {"critical": 10, "high": 5, "medium": 3, "low": 1, "info": 0}
        risk_score = sum(
            count * severity_weights.get(sev, 0)
            for sev, count in stats["by_severity"].items()
        )
        stats["risk_score"] = risk_score
        
        # Risk level
        if risk_score >= 50:
            stats["risk_level"] = "CRITICAL"
        elif risk_score >= 25:
            stats["risk_level"] = "HIGH"
        elif risk_score >= 10:
            stats["risk_level"] = "MEDIUM"
        elif risk_score > 0:
            stats["risk_level"] = "LOW"
        else:
            stats["risk_level"] = "INFO"
            
        return stats
        
    def _build_timeline(
        self,
        execution_log: List[Dict[str, Any]]
    ) -> List[Dict[str, str]]:
        """Build execution timeline."""
        timeline = []
        
        for entry in execution_log:
            step = entry.get("step", {})
            result = entry.get("result", {})
            
            timeline.append({
                "timestamp": entry.get("timestamp", ""),
                "action": f"{step.get('tool', '?')}.{step.get('action', '?')}",
                "status": result.get("status", "unknown"),
                "target": step.get("params", {}).get("target", "N/A")
            })
            
        return timeline
        
    def _generate_executive_summary(
        self,
        task: str,
        findings: List[Dict[str, Any]]
    ) -> str:
        """Generate executive summary."""
        stats = self._calculate_statistics(findings)
        
        critical_count = stats["by_severity"].get("critical", 0)
        high_count = stats["by_severity"].get("high", 0)
        
        summary_parts = [
            f"Security assessment completed for task: {task[:100]}",
            f"",
            f"Total findings: {stats['total']}",
            f"Risk Level: {stats['risk_level']} (Score: {stats['risk_score']})",
            f""
        ]
        
        if critical_count > 0:
            summary_parts.append(
                f"CRITICAL: {critical_count} critical vulnerabilities require immediate attention."
            )
        if high_count > 0:
            summary_parts.append(
                f"HIGH: {high_count} high severity issues should be addressed urgently."
            )
            
        if stats["total"] == 0:
            summary_parts.append(
                "No significant vulnerabilities were identified during this assessment."
            )
            
        return "\n".join(summary_parts)
        
    def _generate_recommendations(
        self,
        findings: List[Dict[str, Any]]
    ) -> List[Dict[str, str]]:
        """Generate remediation recommendations."""
        recommendations = []
        
        # Group by type for consolidated recommendations
        by_type = {}
        for f in findings:
            ftype = f.get("type", "unknown")
            if ftype not in by_type:
                by_type[ftype] = []
            by_type[ftype].append(f)
            
        # Generate recommendation per type
        for ftype, type_findings in by_type.items():
            max_severity = min(
                type_findings,
                key=lambda x: self.SEVERITY_ORDER.index(
                    x.get("severity", "info").lower()
                ) if x.get("severity", "info").lower() in self.SEVERITY_ORDER else 999
            ).get("severity", "info")
            
            recommendations.append({
                "type": ftype,
                "severity": max_severity,
                "count": len(type_findings),
                "recommendation": f"Address {len(type_findings)} {ftype} finding(s). "
                                 f"Priority: {max_severity.upper()}"
            })
            
        # Sort by severity
        def rec_severity_key(r):
            sev = r.get("severity", "info").lower()
            try:
                return self.SEVERITY_ORDER.index(sev)
            except ValueError:
                return len(self.SEVERITY_ORDER)
                
        return sorted(recommendations, key=rec_severity_key)
        
    def _format_markdown(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Format report as Markdown."""
        md_parts = [
            "# Security Assessment Report",
            "",
            f"**Generated:** {report['metadata']['generated_at']}",
            f"**Task:** {report['metadata']['task']}",
            "",
            "## Executive Summary",
            "",
            report["executive_summary"],
            "",
            "## Statistics",
            "",
            f"- **Total Findings:** {report['statistics']['total']}",
            f"- **Risk Level:** {report['statistics']['risk_level']}",
            f"- **Risk Score:** {report['statistics']['risk_score']}",
            "",
            "### By Severity",
            ""
        ]
        
        for sev in self.SEVERITY_ORDER:
            count = report["statistics"]["by_severity"].get(sev, 0)
            if count > 0:
                md_parts.append(f"- **{sev.upper()}:** {count}")
                
        md_parts.extend([
            "",
            "## Findings",
            ""
        ])
        
        for i, finding in enumerate(report["findings"], 1):
            md_parts.extend([
                f"### {i}. [{finding.get('severity', 'INFO').upper()}] {finding.get('type', 'Unknown')}",
                "",
                f"**Description:** {finding.get('description', 'No description')}",
                "",
                f"**Evidence:** {finding.get('evidence', 'N/A')}",
                ""
            ])
            
        md_parts.extend([
            "## Recommendations",
            ""
        ])
        
        for rec in report["recommendations"]:
            md_parts.append(
                f"- **[{rec['severity'].upper()}]** {rec['recommendation']}"
            )
            
        md_parts.extend([
            "",
            "## Execution Timeline",
            "",
            "| Timestamp | Action | Target | Status |",
            "|-----------|--------|--------|--------|"
        ])
        
        for event in report["execution_timeline"][:20]:  # Limit to 20
            md_parts.append(
                f"| {event['timestamp']} | {event['action']} | "
                f"{event['target'][:30]} | {event['status']} |"
            )
            
        report["markdown"] = "\n".join(md_parts)
        return report
        
    def _format_html(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Format report as HTML."""
        # Convert markdown to basic HTML
        md_report = self._format_markdown(report)
        markdown_content = md_report.get("markdown", "")
        
        # Basic HTML template
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Security Assessment Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }}
        h1 {{ color: #333; border-bottom: 2px solid #333; }}
        h2 {{ color: #555; }}
        .critical {{ color: {self.SEVERITY_COLORS['critical']}; }}
        .high {{ color: {self.SEVERITY_COLORS['high']}; }}
        .medium {{ color: {self.SEVERITY_COLORS['medium']}; }}
        .low {{ color: {self.SEVERITY_COLORS['low']}; }}
        .info {{ color: {self.SEVERITY_COLORS['info']}; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #4CAF50; color: white; }}
        .finding {{ border-left: 4px solid; padding: 10px; margin: 10px 0; }}
    </style>
</head>
<body>
    <h1>Security Assessment Report</h1>
    <p><strong>Generated:</strong> {report['metadata']['generated_at']}</p>
    <p><strong>Task:</strong> {report['metadata']['task']}</p>
    
    <h2>Executive Summary</h2>
    <pre>{report['executive_summary']}</pre>
    
    <h2>Statistics</h2>
    <ul>
        <li><strong>Total Findings:</strong> {report['statistics']['total']}</li>
        <li><strong>Risk Level:</strong> <span class="{report['statistics']['risk_level'].lower()}">{report['statistics']['risk_level']}</span></li>
        <li><strong>Risk Score:</strong> {report['statistics']['risk_score']}</li>
    </ul>
    
    <h2>Findings</h2>
"""
        
        for i, finding in enumerate(report["findings"], 1):
            sev = finding.get("severity", "info").lower()
            html += f"""
    <div class="finding" style="border-color: {self.SEVERITY_COLORS.get(sev, '#999')}">
        <h3 class="{sev}">{i}. [{sev.upper()}] {finding.get('type', 'Unknown')}</h3>
        <p><strong>Description:</strong> {finding.get('description', 'No description')}</p>
        <p><strong>Evidence:</strong> {finding.get('evidence', 'N/A')}</p>
    </div>
"""
        
        html += """
    <h2>Recommendations</h2>
    <ul>
"""
        
        for rec in report["recommendations"]:
            sev = rec["severity"].lower()
            html += f'        <li class="{sev}"><strong>[{rec["severity"].upper()}]</strong> {rec["recommendation"]}</li>\n'
            
        html += """
    </ul>
</body>
</html>
"""
        
        report["html"] = html
        return report
        
    def save(
        self,
        report: Dict[str, Any],
        filepath: str,
        format: str = "json"
    ) -> str:
        """
        Save report to file.
        
        Args:
            report: Generated report
            filepath: Path to save file
            format: Output format
            
        Returns:
            Path to saved file
        """
        if format == "json":
            with open(filepath, "w") as f:
                json.dump(report, f, indent=2, default=str)
        elif format == "markdown":
            with open(filepath, "w") as f:
                f.write(report.get("markdown", str(report)))
        elif format == "html":
            with open(filepath, "w") as f:
                f.write(report.get("html", str(report)))
                
        self.logger.info(f"Report saved to {filepath}")
        return filepath
