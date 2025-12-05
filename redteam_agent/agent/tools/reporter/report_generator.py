"""
Report Generator
================

Multi-format security assessment report generator.
"""

import json
from typing import Dict, Any, Optional, List
from datetime import datetime
from pathlib import Path

from agent.tools.base import BaseTool, ToolResult, ToolStatus


class ReportGenerator(BaseTool):
    """
    Security assessment report generator.
    
    Generates reports in multiple formats:
    - JSON (machine-readable)
    - Markdown (human-readable)
    - HTML (presentable)
    """
    
    name = "report_generator"
    description = "Generate security assessment reports"
    category = "reporter"
    
    actions = [
        "generate",
        "add_finding",
        "add_section",
        "export"
    ]
    
    timeout = 60
    
    def __init__(self):
        super().__init__()
        self.report_data = {
            "metadata": {},
            "executive_summary": "",
            "findings": [],
            "sections": {},
            "recommendations": [],
            "appendix": []
        }
        
    def execute(
        self,
        action: str,
        target: str = "",
        params: Optional[Dict[str, Any]] = None
    ) -> ToolResult:
        """Execute report generation action."""
        params = params or {}
        start_time = datetime.now()
        
        if action == "generate":
            result = self._generate_report(target, params)
        elif action == "add_finding":
            result = self._add_finding(params)
        elif action == "add_section":
            result = self._add_section(params)
        elif action == "export":
            result = self._export_report(params)
        else:
            result = {"error": f"Unknown action: {action}"}
            
        duration = (datetime.now() - start_time).total_seconds()
        
        return ToolResult(
            status=ToolStatus.SUCCESS if "error" not in result else ToolStatus.FAILURE,
            output=json.dumps(result, indent=2),
            parsed=result,
            duration=duration,
            metadata={"action": action}
        )
        
    def _generate_report(
        self,
        target: str,
        params: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate a complete report from assessment data."""
        findings = params.get("findings", [])
        scan_results = params.get("scan_results", {})
        format_type = params.get("format", "markdown")
        
        # Build report data
        self.report_data = {
            "metadata": {
                "title": params.get("title", f"Security Assessment Report - {target}"),
                "target": target,
                "date": datetime.now().isoformat(),
                "assessor": params.get("assessor", "Red Team AI Agent"),
                "engagement_id": params.get("engagement_id", "N/A"),
                "scope": params.get("scope", [target]),
                "version": "1.0"
            },
            "executive_summary": self._generate_executive_summary(findings),
            "findings": self._process_findings(findings),
            "severity_summary": self._calculate_severity_summary(findings),
            "sections": {
                "reconnaissance": scan_results.get("recon", {}),
                "vulnerabilities": scan_results.get("vulns", {}),
                "configuration": scan_results.get("config", {}),
                "compliance": scan_results.get("compliance", {})
            },
            "recommendations": self._generate_recommendations(findings),
            "appendix": []
        }
        
        # Generate output in requested format
        if format_type == "json":
            return self.report_data
        elif format_type == "markdown":
            return {"markdown": self._to_markdown()}
        elif format_type == "html":
            return {"html": self._to_html()}
        else:
            return self.report_data
            
    def _generate_executive_summary(self, findings: List[Dict]) -> str:
        """Generate executive summary from findings."""
        critical = len([f for f in findings if f.get("severity") == "critical"])
        high = len([f for f in findings if f.get("severity") == "high"])
        medium = len([f for f in findings if f.get("severity") == "medium"])
        low = len([f for f in findings if f.get("severity") == "low"])
        
        total = len(findings)
        
        if critical > 0:
            risk_level = "CRITICAL"
            risk_description = "Immediate action required. Critical vulnerabilities found that could lead to complete system compromise."
        elif high > 0:
            risk_level = "HIGH"
            risk_description = "Significant vulnerabilities found that require prompt attention."
        elif medium > 0:
            risk_level = "MEDIUM"
            risk_description = "Moderate vulnerabilities found that should be addressed in the near term."
        elif low > 0:
            risk_level = "LOW"
            risk_description = "Minor issues found that should be addressed as part of regular maintenance."
        else:
            risk_level = "MINIMAL"
            risk_description = "No significant vulnerabilities identified during the assessment."
            
        return f"""
## Executive Summary

**Overall Risk Level: {risk_level}**

{risk_description}

### Finding Summary

| Severity | Count |
|----------|-------|
| Critical | {critical} |
| High | {high} |
| Medium | {medium} |
| Low | {low} |
| **Total** | **{total}** |

### Key Concerns

{self._generate_key_concerns(findings)}
"""
        
    def _generate_key_concerns(self, findings: List[Dict]) -> str:
        """Generate key concerns from critical/high findings."""
        concerns = []
        for f in findings:
            if f.get("severity") in ["critical", "high"]:
                concerns.append(f"- **{f.get('title', 'Unknown')}**: {f.get('description', '')[:100]}")
                
        if not concerns:
            return "No critical or high severity findings identified."
            
        return "\n".join(concerns[:5])  # Top 5 concerns
        
    def _process_findings(self, findings: List[Dict]) -> List[Dict]:
        """Process and enrich findings."""
        processed = []
        
        for i, finding in enumerate(findings, 1):
            processed.append({
                "id": f"FINDING-{i:03d}",
                "title": finding.get("title", "Untitled Finding"),
                "severity": finding.get("severity", "info"),
                "cvss_score": finding.get("cvss_score"),
                "category": finding.get("category", "general"),
                "description": finding.get("description", ""),
                "evidence": finding.get("evidence", ""),
                "impact": finding.get("impact", ""),
                "remediation": finding.get("remediation", ""),
                "references": finding.get("references", []),
                "cwe": finding.get("cwe"),
                "affected_components": finding.get("affected_components", [])
            })
            
        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        processed.sort(key=lambda x: severity_order.get(x["severity"], 5))
        
        return processed
        
    def _calculate_severity_summary(self, findings: List[Dict]) -> Dict[str, int]:
        """Calculate severity distribution."""
        summary = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0
        }
        
        for finding in findings:
            severity = finding.get("severity", "info")
            if severity in summary:
                summary[severity] += 1
                
        return summary
        
    def _generate_recommendations(self, findings: List[Dict]) -> List[Dict]:
        """Generate prioritized recommendations."""
        recommendations = []
        seen = set()
        
        # Sort findings by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            findings,
            key=lambda x: severity_order.get(x.get("severity"), 5)
        )
        
        for finding in sorted_findings:
            remediation = finding.get("remediation", "")
            if remediation and remediation not in seen:
                seen.add(remediation)
                recommendations.append({
                    "priority": finding.get("severity", "info"),
                    "finding": finding.get("title", ""),
                    "recommendation": remediation,
                    "effort": self._estimate_effort(finding)
                })
                
        return recommendations
        
    def _estimate_effort(self, finding: Dict) -> str:
        """Estimate remediation effort."""
        severity = finding.get("severity", "info")
        category = finding.get("category", "")
        
        if "configuration" in category.lower():
            return "Low"
        elif severity == "critical":
            return "High"
        elif severity == "high":
            return "Medium-High"
        else:
            return "Low-Medium"
            
    def _add_finding(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Add a finding to the report."""
        finding = {
            "title": params.get("title", ""),
            "severity": params.get("severity", "info"),
            "description": params.get("description", ""),
            "evidence": params.get("evidence", ""),
            "impact": params.get("impact", ""),
            "remediation": params.get("remediation", ""),
            "category": params.get("category", "general")
        }
        
        self.report_data["findings"].append(finding)
        return {"status": "added", "finding_count": len(self.report_data["findings"])}
        
    def _add_section(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Add a section to the report."""
        section_name = params.get("name", "")
        content = params.get("content", {})
        
        self.report_data["sections"][section_name] = content
        return {"status": "added", "section": section_name}
        
    def _export_report(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Export report to file."""
        format_type = params.get("format", "markdown")
        output_path = params.get("output_path", "")
        
        if format_type == "json":
            content = json.dumps(self.report_data, indent=2)
            ext = ".json"
        elif format_type == "markdown":
            content = self._to_markdown()
            ext = ".md"
        elif format_type == "html":
            content = self._to_html()
            ext = ".html"
        else:
            return {"error": f"Unknown format: {format_type}"}
            
        if output_path:
            path = Path(output_path)
            if not path.suffix:
                path = path.with_suffix(ext)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
            return {"status": "exported", "path": str(path)}
        else:
            return {"content": content}
            
    def _to_markdown(self) -> str:
        """Convert report to Markdown format."""
        md = []
        meta = self.report_data.get("metadata", {})
        
        # Title
        md.append(f"# {meta.get('title', 'Security Assessment Report')}")
        md.append("")
        
        # Metadata table
        md.append("## Report Information")
        md.append("")
        md.append("| Field | Value |")
        md.append("|-------|-------|")
        md.append(f"| Target | {meta.get('target', 'N/A')} |")
        md.append(f"| Date | {meta.get('date', 'N/A')} |")
        md.append(f"| Assessor | {meta.get('assessor', 'N/A')} |")
        md.append(f"| Engagement ID | {meta.get('engagement_id', 'N/A')} |")
        md.append("")
        
        # Executive Summary
        md.append(self.report_data.get("executive_summary", ""))
        md.append("")
        
        # Detailed Findings
        md.append("## Detailed Findings")
        md.append("")
        
        for finding in self.report_data.get("findings", []):
            severity_badge = {
                "critical": "🔴",
                "high": "🟠",
                "medium": "🟡",
                "low": "🟢",
                "info": "🔵"
            }.get(finding.get("severity"), "⚪")
            
            md.append(f"### {severity_badge} {finding.get('id', '')} - {finding.get('title', '')}")
            md.append("")
            md.append(f"**Severity:** {finding.get('severity', 'N/A').upper()}")
            if finding.get("cvss_score"):
                md.append(f"**CVSS Score:** {finding.get('cvss_score')}")
            md.append(f"**Category:** {finding.get('category', 'N/A')}")
            md.append("")
            
            md.append("#### Description")
            md.append(finding.get("description", "No description provided."))
            md.append("")
            
            if finding.get("evidence"):
                md.append("#### Evidence")
                md.append(f"```\n{finding.get('evidence')}\n```")
                md.append("")
                
            if finding.get("impact"):
                md.append("#### Impact")
                md.append(finding.get("impact"))
                md.append("")
                
            if finding.get("remediation"):
                md.append("#### Remediation")
                md.append(finding.get("remediation"))
                md.append("")
                
            if finding.get("references"):
                md.append("#### References")
                for ref in finding.get("references", []):
                    md.append(f"- {ref}")
                md.append("")
                
            md.append("---")
            md.append("")
            
        # Recommendations
        md.append("## Recommendations")
        md.append("")
        md.append("| Priority | Finding | Recommendation | Effort |")
        md.append("|----------|---------|----------------|--------|")
        
        for rec in self.report_data.get("recommendations", []):
            md.append(f"| {rec.get('priority', '').upper()} | {rec.get('finding', '')} | {rec.get('recommendation', '')[:50]}... | {rec.get('effort', '')} |")
            
        md.append("")
        
        # Footer
        md.append("---")
        md.append("")
        md.append(f"*Report generated by {meta.get('assessor', 'Red Team AI Agent')} on {meta.get('date', '')}*")
        
        return "\n".join(md)
        
    def _to_html(self) -> str:
        """Convert report to HTML format."""
        meta = self.report_data.get("metadata", {})
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{meta.get('title', 'Security Assessment Report')}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; max-width: 1200px; margin: 0 auto; padding: 20px; }}
        h1 {{ color: #1a1a2e; border-bottom: 3px solid #e94560; padding-bottom: 10px; }}
        h2 {{ color: #16213e; margin-top: 40px; }}
        h3 {{ color: #0f3460; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background-color: #16213e; color: white; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        .severity-critical {{ background-color: #ff4757; color: white; padding: 3px 8px; border-radius: 4px; }}
        .severity-high {{ background-color: #ff6b35; color: white; padding: 3px 8px; border-radius: 4px; }}
        .severity-medium {{ background-color: #ffa502; color: black; padding: 3px 8px; border-radius: 4px; }}
        .severity-low {{ background-color: #2ed573; color: white; padding: 3px 8px; border-radius: 4px; }}
        .severity-info {{ background-color: #1e90ff; color: white; padding: 3px 8px; border-radius: 4px; }}
        .finding {{ border: 1px solid #ddd; padding: 20px; margin: 20px 0; border-radius: 8px; }}
        .finding-critical {{ border-left: 5px solid #ff4757; }}
        .finding-high {{ border-left: 5px solid #ff6b35; }}
        .finding-medium {{ border-left: 5px solid #ffa502; }}
        .finding-low {{ border-left: 5px solid #2ed573; }}
        .finding-info {{ border-left: 5px solid #1e90ff; }}
        pre {{ background-color: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto; }}
        .summary-box {{ background-color: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; }}
    </style>
</head>
<body>
    <h1>{meta.get('title', 'Security Assessment Report')}</h1>
    
    <div class="summary-box">
        <h2>Report Information</h2>
        <table>
            <tr><th>Field</th><th>Value</th></tr>
            <tr><td>Target</td><td>{meta.get('target', 'N/A')}</td></tr>
            <tr><td>Date</td><td>{meta.get('date', 'N/A')}</td></tr>
            <tr><td>Assessor</td><td>{meta.get('assessor', 'N/A')}</td></tr>
            <tr><td>Engagement ID</td><td>{meta.get('engagement_id', 'N/A')}</td></tr>
        </table>
    </div>
    
    <h2>Executive Summary</h2>
    <div class="summary-box">
        {self._markdown_to_html(self.report_data.get('executive_summary', ''))}
    </div>
    
    <h2>Severity Summary</h2>
    <table>
        <tr>
            <th>Severity</th>
            <th>Count</th>
        </tr>
"""
        
        severity_summary = self.report_data.get("severity_summary", {})
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_summary.get(sev, 0)
            html += f'        <tr><td><span class="severity-{sev}">{sev.upper()}</span></td><td>{count}</td></tr>\n'
            
        html += """    </table>
    
    <h2>Detailed Findings</h2>
"""
        
        for finding in self.report_data.get("findings", []):
            severity = finding.get("severity", "info")
            html += f"""
    <div class="finding finding-{severity}">
        <h3>{finding.get('id', '')} - {finding.get('title', '')}</h3>
        <p><span class="severity-{severity}">{severity.upper()}</span> | Category: {finding.get('category', 'N/A')}</p>
        
        <h4>Description</h4>
        <p>{finding.get('description', 'No description provided.')}</p>
"""
            
            if finding.get("evidence"):
                html += f"""
        <h4>Evidence</h4>
        <pre>{finding.get('evidence')}</pre>
"""
                
            if finding.get("impact"):
                html += f"""
        <h4>Impact</h4>
        <p>{finding.get('impact')}</p>
"""
                
            if finding.get("remediation"):
                html += f"""
        <h4>Remediation</h4>
        <p>{finding.get('remediation')}</p>
"""
                
            html += "    </div>\n"
            
        html += f"""
    <h2>Recommendations</h2>
    <table>
        <tr>
            <th>Priority</th>
            <th>Finding</th>
            <th>Recommendation</th>
            <th>Effort</th>
        </tr>
"""
        
        for rec in self.report_data.get("recommendations", []):
            priority = rec.get('priority', 'info')
            html += f"""        <tr>
            <td><span class="severity-{priority}">{priority.upper()}</span></td>
            <td>{rec.get('finding', '')}</td>
            <td>{rec.get('recommendation', '')}</td>
            <td>{rec.get('effort', '')}</td>
        </tr>
"""
            
        html += f"""    </table>
    
    <hr>
    <p><em>Report generated by {meta.get('assessor', 'Red Team AI Agent')} on {meta.get('date', '')}</em></p>
</body>
</html>
"""
        
        return html
        
    def _markdown_to_html(self, md: str) -> str:
        """Simple markdown to HTML conversion."""
        import re
        
        html = md
        
        # Headers
        html = re.sub(r'^### (.+)$', r'<h4>\1</h4>', html, flags=re.MULTILINE)
        html = re.sub(r'^## (.+)$', r'<h3>\1</h3>', html, flags=re.MULTILINE)
        html = re.sub(r'^# (.+)$', r'<h2>\1</h2>', html, flags=re.MULTILINE)
        
        # Bold
        html = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', html)
        
        # Lists
        html = re.sub(r'^- (.+)$', r'<li>\1</li>', html, flags=re.MULTILINE)
        
        # Paragraphs
        html = re.sub(r'\n\n', '</p><p>', html)
        
        return f"<p>{html}</p>"
        
    def parse_output(self, output: str) -> Dict[str, Any]:
        try:
            return json.loads(output)
        except:
            return {"raw": output}
