"""
Observer Module
===============

Analyzes tool output using LLM to extract findings and insights.
"""

from typing import Dict, Any, List, Optional

from agent.utils.logger import get_logger


class Observer:
    """
    Result observation module for the Red Team Agent.
    
    Responsible for:
    - Parsing raw tool output
    - Using LLM to interpret results
    - Extracting key findings
    - Determining severity levels
    - Suggesting next actions
    - Updating memory with observations
    
    Attributes:
        llm: LLM provider for analysis
        memory: Agent memory
    """
    
    def __init__(self, llm, memory):
        """
        Initialize the Observer.
        
        Args:
            llm: LLM provider instance
            memory: Memory instance
        """
        self.llm = llm
        self.memory = memory
        self.logger = get_logger("Observer")
        
    def analyze(
        self,
        step: Dict[str, Any],
        result: Any,
        context: str
    ) -> Dict[str, Any]:
        """
        Analyze tool execution result.
        
        Args:
            step: The step that was executed
            result: StepResult object
            context: Current context from memory
            
        Returns:
            Observation dictionary with:
            - findings: List of extracted findings
            - recommendations: List of recommended actions
            - next_suggested_tools: Tools to consider next
            - task_complete: Whether task should be marked complete
        """
        self.logger.info(f"Analyzing result from {step.get('tool', 'unknown')}")
        
        # Handle failed steps
        if hasattr(result, 'status') and result.status != "success":
            return self._handle_failure(step, result)
            
        # Get output to analyze
        output = result.output if hasattr(result, 'output') else result.get('output')
        existing_findings = result.findings if hasattr(result, 'findings') else result.get('findings', [])
        
        # If tool already extracted findings, enhance them
        if existing_findings:
            enhanced_findings = self._enhance_findings(existing_findings, step)
            return {
                "findings": enhanced_findings,
                "recommendations": self._generate_recommendations(enhanced_findings),
                "next_suggested_tools": self._suggest_next_tools(enhanced_findings),
                "task_complete": False
            }
        
        # Use LLM to analyze output
        if output:
            return self._llm_analyze(step, output, context)
            
        return {
            "findings": [],
            "recommendations": [],
            "next_suggested_tools": [],
            "task_complete": False
        }
        
    def _llm_analyze(
        self,
        step: Dict[str, Any],
        output: Any,
        context: str
    ) -> Dict[str, Any]:
        """Use LLM to analyze tool output."""
        prompt = f"""Analyze this security tool output and extract findings.

TOOL: {step.get('tool', 'unknown')}
ACTION: {step.get('action', 'unknown')}

OUTPUT:
{self._format_output(output)}

CONTEXT:
{context[:2000] if context else 'No additional context'}

Extract security findings. For each finding, provide:
- type: Type of issue (e.g., missing_csp, xss_vulnerable, etc.)
- severity: critical/high/medium/low/info
- description: Clear description
- evidence: Specific evidence from the output
- impact: Potential security impact

Output format:
<analysis>
<finding severity="LEVEL" type="TYPE">
<description>Description here</description>
<evidence>Evidence here</evidence>
<impact>Impact here</impact>
</finding>
</analysis>

If no security issues found, output:
<analysis>
<no_findings>No security issues detected</no_findings>
</analysis>

Also indicate if you think the overall task is complete:
<task_complete>true/false</task_complete>

Your analysis:"""

        response = self.llm.generate(prompt)
        return self._parse_analysis(response)
        
    def _parse_analysis(self, response: str) -> Dict[str, Any]:
        """Parse LLM analysis response."""
        import re
        
        findings = []
        task_complete = False
        
        # Check for no findings
        if "<no_findings>" in response:
            pass  # No findings to extract
        else:
            # Extract findings
            finding_pattern = r'<finding\s+severity="([^"]+)"\s+type="([^"]+)"[^>]*>.*?<description>(.*?)</description>.*?<evidence>(.*?)</evidence>.*?(?:<impact>(.*?)</impact>)?.*?</finding>'
            matches = re.findall(finding_pattern, response, re.DOTALL)
            
            for match in matches:
                severity, finding_type, description, evidence, impact = match
                findings.append({
                    "type": finding_type.strip(),
                    "severity": severity.strip().lower(),
                    "description": description.strip(),
                    "evidence": evidence.strip(),
                    "impact": impact.strip() if impact else ""
                })
        
        # Check task complete
        complete_match = re.search(r'<task_complete>(true|false)</task_complete>', response.lower())
        if complete_match:
            task_complete = complete_match.group(1) == "true"
            
        return {
            "findings": findings,
            "recommendations": self._generate_recommendations(findings),
            "next_suggested_tools": self._suggest_next_tools(findings),
            "task_complete": task_complete
        }
        
    def _handle_failure(self, step: Dict[str, Any], result: Any) -> Dict[str, Any]:
        """Handle failed step execution."""
        error = result.error if hasattr(result, 'error') else result.get('error', 'Unknown error')
        
        self.logger.warning(f"Step failed: {step.get('tool')} - {error}")
        
        return {
            "findings": [],
            "recommendations": [f"Retry {step.get('tool')} or try alternative approach"],
            "next_suggested_tools": [],
            "task_complete": False,
            "error": error
        }
        
    def _enhance_findings(
        self,
        findings: List[Dict[str, Any]],
        step: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Enhance existing findings with additional context."""
        enhanced = []
        for f in findings:
            enhanced_finding = f.copy()
            # Add source tool info
            enhanced_finding["source_tool"] = step.get("tool")
            enhanced_finding["source_action"] = step.get("action")
            # Ensure severity is lowercase
            if "severity" in enhanced_finding:
                enhanced_finding["severity"] = enhanced_finding["severity"].lower()
            enhanced.append(enhanced_finding)
        return enhanced
        
    def _generate_recommendations(
        self,
        findings: List[Dict[str, Any]]
    ) -> List[str]:
        """Generate recommendations based on findings."""
        recommendations = []
        
        for f in findings:
            finding_type = f.get("type", "").lower()
            severity = f.get("severity", "").lower()
            
            if "csp" in finding_type or "content-security-policy" in finding_type:
                recommendations.append("Implement Content-Security-Policy header")
            elif "xss" in finding_type:
                recommendations.append("Implement proper input validation and output encoding")
            elif "sql" in finding_type:
                recommendations.append("Use parameterized queries")
            elif "header" in finding_type:
                recommendations.append("Review and implement security headers")
            elif "ssl" in finding_type or "tls" in finding_type:
                recommendations.append("Update TLS configuration")
            elif "skimmer" in finding_type or "magecart" in finding_type:
                recommendations.append("Immediately investigate and remove suspicious scripts")
                recommendations.append("Implement SRI for all external scripts")
                
        return list(set(recommendations))  # Remove duplicates
        
    def _suggest_next_tools(
        self,
        findings: List[Dict[str, Any]]
    ) -> List[str]:
        """Suggest next tools based on findings."""
        suggestions = []
        
        for f in findings:
            finding_type = f.get("type", "").lower()
            severity = f.get("severity", "").lower()
            
            # High severity findings warrant deeper investigation
            if severity in ["critical", "high"]:
                if "csp" in finding_type:
                    suggestions.append("js_analyzer")
                    suggestions.append("xss_scanner")
                elif "script" in finding_type or "javascript" in finding_type:
                    suggestions.append("skimmer_detect")
                    suggestions.append("js_analyzer")
                    
        return list(set(suggestions))
        
    def _format_output(self, output: Any) -> str:
        """Format output for LLM prompt."""
        if isinstance(output, dict):
            import json
            return json.dumps(output, indent=2, default=str)[:3000]
        elif isinstance(output, list):
            import json
            return json.dumps(output, indent=2, default=str)[:3000]
        else:
            return str(output)[:3000]
