"""
Minimal MCP Server for Burp Suite REST API v0.1

IMPORTANT: Burp REST API v0.1 only has 3 endpoints:
1. POST /{api_key}/v0.1/scan - Start a scan
2. GET /{api_key}/v0.1/scan/{task_id} - Get scan status and issues
3. GET /{api_key}/v0.1/knowledge_base/issue_definitions - Get issue definitions

This server ONLY exposes tools that actually work with these limited endpoints.
For Repeater, Intruder, Collaborator, Proxy, etc. use PortSwigger's MCP extension.
"""

import asyncio
import json
import os
import sys
from typing import Any, Dict, List, Optional

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from api.client import BurpClient
from api.models import ScanStatus
from utils.config import get_settings


class BurpMCPServer:
    """Minimal MCP Server for Burp Suite REST API v0.1"""

    def __init__(self):
        self.settings = get_settings()
        self.server = Server("burp-suite")
        self.burp_client: Optional[BurpClient] = None

        # Register handlers
        self._register_handlers()

    def _register_handlers(self) -> None:
        """Register MCP server handlers - ONLY tools supported by REST API v0.1"""

        @self.server.list_tools()
        async def list_tools() -> List[Tool]:
            """List available Burp Suite tools (REST API v0.1 limited)"""
            return [
                # Tool 1: Start Scan (POST /scan)
                Tool(
                    name="burp_start_scan",
                    description=(
                        "Start a security scan on target URLs using Burp Suite. "
                        "Initiates an active scan that will crawl and test the target. "
                        "Returns a scan ID for status checking. "
                        "Note: This uses Burp REST API v0.1 which only supports basic scanning. "
                        "For Repeater, Intruder, Collaborator use PortSwigger's MCP extension."
                    ),
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "urls": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "List of target URLs to scan"
                            }
                        },
                        "required": ["urls"]
                    }
                ),

                # Tool 2: Get Scan Status (GET /scan/{id})
                Tool(
                    name="burp_get_scan_status",
                    description=(
                        "Get the current status of a running or completed scan. "
                        "Returns status (queued/crawling/auditing/running/succeeded/failed), "
                        "progress metrics, and summary of findings."
                    ),
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "scan_id": {
                                "type": "string",
                                "description": "Scan identifier from burp_start_scan"
                            }
                        },
                        "required": ["scan_id"]
                    }
                ),

                # Tool 3: Get Scan Issues (GET /scan/{id} -> issue_events)
                Tool(
                    name="burp_get_scan_issues",
                    description=(
                        "Retrieve security vulnerabilities found during a scan. "
                        "Returns detailed vulnerability information including: "
                        "name, severity (high/medium/low/info), confidence (certain/firm/tentative), "
                        "affected URL, description, remediation advice, and evidence. "
                        "Can optionally filter by severity level."
                    ),
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "scan_id": {
                                "type": "string",
                                "description": "Scan identifier"
                            },
                            "severity": {
                                "type": "string",
                                "enum": ["high", "medium", "low", "info"],
                                "description": "Optional: Filter by severity"
                            }
                        },
                        "required": ["scan_id"]
                    }
                ),

                # Tool 4: Wait for Scan Completion (polling GET /scan/{id})
                Tool(
                    name="burp_wait_for_scan",
                    description=(
                        "Wait for a scan to complete and return final results. "
                        "Polls the scan status until it reaches a terminal state "
                        "(succeeded, failed, or cancelled). Use this after starting a scan "
                        "to get the final vulnerability report."
                    ),
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "scan_id": {
                                "type": "string",
                                "description": "Scan identifier"
                            },
                            "poll_interval": {
                                "type": "integer",
                                "description": "Seconds between status checks (default: 5)",
                                "default": 5
                            },
                            "max_wait_time": {
                                "type": "integer",
                                "description": "Maximum seconds to wait (default: 3600)",
                                "default": 3600
                            }
                        },
                        "required": ["scan_id"]
                    }
                ),

                # Tool 5: Health Check (GET /v0.1/)
                Tool(
                    name="burp_health_check",
                    description=(
                        "Check if Burp Suite REST API is accessible and get version info. "
                        "Returns connection status and Burp Suite version."
                    ),
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                ),
            ]

        @self.server.call_tool()
        async def call_tool(name: str, arguments: Any) -> List[TextContent]:
            """Execute Burp Suite tools"""
            try:
                async with BurpClient(
                    api_url=self.settings.burp_api_url,
                    api_key=self.settings.burp_api_key,
                    timeout=self.settings.request_timeout
                ) as client:
                    result = await self._execute_tool(client, name, arguments or {})
                    return [TextContent(
                        type="text",
                        text=json.dumps(result, indent=2)
                    )]
            except Exception as e:
                return [TextContent(
                    type="text",
                    text=json.dumps({
                        "success": False,
                        "error": str(e),
                        "tool": name
                    }, indent=2)
                )]

    async def _execute_tool(self, client: BurpClient, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a specific tool"""

        if name == "burp_start_scan":
            return await self._start_scan(client, args)
        elif name == "burp_get_scan_status":
            return await self._get_scan_status(client, args)
        elif name == "burp_get_scan_issues":
            return await self._get_scan_issues(client, args)
        elif name == "burp_wait_for_scan":
            return await self._wait_for_scan(client, args)
        elif name == "burp_health_check":
            return await self._health_check(client, args)
        else:
            return {
                "success": False,
                "error": f"Unknown tool: {name}"
            }

    # ========== Tool Implementations ==========

    async def _start_scan(self, client: BurpClient, args: Dict[str, Any]) -> Dict[str, Any]:
        """Start a new scan"""
        urls = args["urls"]
        scan = await client.start_scan(urls)

        return {
            "success": True,
            "scan_id": scan.scan_id,
            "status": scan.status.value,
            "message": f"Scan started successfully for {len(urls)} URL(s)"
        }

    async def _get_scan_status(self, client: BurpClient, args: Dict[str, Any]) -> Dict[str, Any]:
        """Get scan status and metrics"""
        scan_id = args["scan_id"]
        details = await client.get_scan_status(scan_id)

        # Handle scan_metrics - it's a dictionary, not an object
        metrics = {}
        if details.scan_metrics:
            metrics = {
                "audit_items_completed": details.scan_metrics.get("audit_queue_items_completed", 0),
                "audit_items_waiting": details.scan_metrics.get("audit_queue_items_waiting", 0),
                "audit_requests_made": details.scan_metrics.get("audit_requests_made", 0),
                "crawl_requests_made": details.scan_metrics.get("crawl_requests_made", 0),
                "issue_events": details.scan_metrics.get("issue_events", 0),
                "progress": details.scan_metrics.get("crawl_and_audit_progress", 0)
            }

        return {
            "success": True,
            "scan_id": scan_id,
            "status": details.status.value,
            "metrics": metrics,
            "issue_counts": details.issue_counts or {}
        }

    async def _get_scan_issues(self, client: BurpClient, args: Dict[str, Any]) -> Dict[str, Any]:
        """Get vulnerabilities from scan"""
        scan_id = args["scan_id"]
        severity = args.get("severity")

        issues_response = await client.get_scan_issues(scan_id, severity)

        # Format issues for readability
        formatted_issues = []
        for idx, issue in enumerate(issues_response.issues):
            formatted_issues.append({
                "index": idx,
                "name": issue.name,
                "severity": issue.severity.value,
                "confidence": issue.confidence.value,
                "path": issue.path,
                "description": issue.description[:200] + "..." if len(issue.description) > 200 else issue.description,
                "remediation": issue.remediation[:150] + "..." if issue.remediation and len(issue.remediation) > 150 else issue.remediation
            })

        return {
            "success": True,
            "scan_id": scan_id,
            "total_issues": issues_response.total_count,
            "severity_filter": severity or "all",
            "issues": formatted_issues
        }

    async def _wait_for_scan(self, client: BurpClient, args: Dict[str, Any]) -> Dict[str, Any]:
        """Wait for scan to complete"""
        scan_id = args["scan_id"]
        poll_interval = args.get("poll_interval", 5)
        max_wait_time = args.get("max_wait_time", 3600)

        details = await client.wait_for_scan(
            scan_id=scan_id,
            poll_interval=poll_interval,
            max_wait_time=max_wait_time
        )

        # Get final issues
        issues_response = await client.get_scan_issues(scan_id)

        # Count by severity
        severity_counts = {"high": 0, "medium": 0, "low": 0, "info": 0}
        for issue in issues_response.issues:
            severity_counts[issue.severity.value] += 1

        return {
            "success": True,
            "scan_id": scan_id,
            "final_status": details.status.value,
            "total_issues": issues_response.total_count,
            "issues_by_severity": severity_counts,
            "message": f"Scan completed with status: {details.status.value}"
        }

    async def _health_check(self, client: BurpClient, args: Dict[str, Any]) -> Dict[str, Any]:
        """Check Burp API connection and version"""
        version = await client.get_version()

        return {
            "success": True,
            "connected": True,
            "burp_version": version.version,
            "product": version.product,
            "api_url": self.settings.burp_api_url,
            "api_version": "v0.1"
        }

    async def run(self):
        """Run the MCP server"""
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                self.server.create_initialization_options()
            )


async def main():
    """Main entry point"""
    server = BurpMCPServer()
    await server.run()


if __name__ == "__main__":
    asyncio.run(main())
