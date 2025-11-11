"""
AI-powered validator that will be used via Claude Desktop MCP integration

Note: This validator is designed to work with Claude Desktop through the MCP server.
Claude will use the MCP tools to analyze issues and make validation decisions.
"""

from typing import Any, Dict

from burp_cli.api.models import Issue
from .base import BaseValidator, ValidationResult


class AIValidator(BaseValidator):
    """
    AI-powered validator for security issues

    This validator is primarily a placeholder for MCP-based validation.
    The actual AI analysis happens through Claude Desktop using MCP tools.
    """

    @property
    def supported_issue_types(self) -> list[str]:
        """Supports all issue types through AI analysis"""
        return ["*"]  # Wildcard - supports all types

    async def validate(self, issue: Issue) -> ValidationResult:
        """
        Validate issue using AI analysis

        In practice, this method would be called by Claude Desktop via MCP tools.
        Claude will analyze the issue details and make intelligent decisions.

        Args:
            issue: Issue to validate

        Returns:
            Validation result
        """
        # Extract key information for analysis
        evidence = {
            "issue_type": issue.issue_type,
            "severity": issue.severity.value,
            "confidence": issue.confidence.value,
            "path": issue.path,
            "description": issue.description[:500],  # Truncate for readability
            "evidence_count": len(issue.evidence) if issue.evidence else 0
        }

        # Return initial assessment
        # Claude Desktop will use MCP tools for deeper validation
        return ValidationResult(
            is_valid=True,  # Assume valid pending AI review
            confidence=0.5,  # Medium confidence pending validation
            evidence=evidence,
            notes="Issue requires AI validation via Claude Desktop MCP tools"
        )

    async def analyze_with_context(
        self,
        issue: Issue,
        additional_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Analyze issue with additional context

        This method provides structured data for Claude to analyze via MCP.

        Args:
            issue: Issue to analyze
            additional_context: Additional context (e.g., app type, framework)

        Returns:
            Analysis data for AI processing
        """
        return {
            "issue": {
                "type": issue.issue_type,
                "name": issue.name,
                "severity": issue.severity.value,
                "confidence": issue.confidence.value,
                "path": issue.path,
                "description": issue.description,
                "remediation": issue.remediation,
            },
            "evidence": [
                {
                    "request": ev.request[:1000] if ev.request else None,
                    "response": ev.response[:1000] if ev.response else None,
                }
                for ev in (issue.evidence or [])[:3]  # Limit to first 3 pieces
            ],
            "context": additional_context,
            "recommendation": (
                "Use burp_validate_sqli for SQL injection issues, "
                "burp_validate_xss for XSS issues, or "
                "burp_send_to_repeater for manual testing"
            )
        }
