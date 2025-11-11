"""
Pydantic models for Burp Suite API
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, HttpUrl


class ScanStatus(str, Enum):
    """Scan status enumeration

    Based on Burp Suite Professional REST API v0.1:
    - queued: Scan is queued and waiting to start
    - crawling: Scan is in the crawling/discovery phase
    - auditing: Scan is actively auditing for vulnerabilities
    - running: Scan is running (generic running state)
    - succeeded: Scan completed successfully
    - failed: Scan failed
    - paused: Scan is paused
    - cancelled: Scan was cancelled
    """
    QUEUED = "queued"
    CRAWLING = "crawling"
    AUDITING = "auditing"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    PAUSED = "paused"
    CANCELLED = "cancelled"


class IssueSeverity(str, Enum):
    """Issue severity levels"""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class IssueConfidence(str, Enum):
    """Issue confidence levels"""
    CERTAIN = "certain"
    FIRM = "firm"
    TENTATIVE = "tentative"


class ScopeType(str, Enum):
    """Scope type enumeration"""
    SIMPLE = "SimpleScope"
    ADVANCED = "AdvancedScope"


class ScopeRule(BaseModel):
    """Simple scope rule - just a string pattern"""
    rule: str = Field(..., description="URL pattern or regex")


class SimpleScope(BaseModel):
    """Simple scope configuration for Burp scan"""
    type: ScopeType = Field(default=ScopeType.SIMPLE, description="Scope type")
    include: Optional[List[ScopeRule]] = Field(default=None, description="Include rules")
    exclude: Optional[List[ScopeRule]] = Field(default=None, description="Exclude rules")


class NamedConfiguration(BaseModel):
    """Reference to a built-in Burp configuration by name"""
    type: str = Field(default="NamedConfiguration", description="Configuration type")
    name: str = Field(..., description="Built-in configuration name (e.g., 'Crawl and Audit - Fast')")


class CustomConfiguration(BaseModel):
    """Custom JSON configuration"""
    type: str = Field(default="CustomConfiguration", description="Configuration type")
    config: str = Field(..., description="JSON configuration string")


class UsernamePasswordLogin(BaseModel):
    """Username and password authentication"""
    type: str = Field(default="UsernameAndPasswordLogin", description="Login type")
    username: str = Field(..., description="Username")
    password: str = Field(..., description="Password")


class RecordedLogin(BaseModel):
    """Recorded login script"""
    type: str = Field(default="RecordedLogin", description="Login type")
    label: str = Field(..., description="Login label")
    script: str = Field(..., description="Recorded login script JSON")


class ScanCallback(BaseModel):
    """Webhook callback for scan completion"""
    url: str = Field(..., description="Callback URL")


class ScanConfiguration(BaseModel):
    """Legacy scan configuration settings - kept for backwards compatibility"""
    scan_type: str = Field(default="active", description="Type of scan (active/passive)")
    scope_include: Optional[List[str]] = Field(default=None, description="URLs to include in scope")
    scope_exclude: Optional[List[str]] = Field(default=None, description="URLs to exclude from scope")
    max_crawl_depth: Optional[int] = Field(default=None, description="Maximum crawl depth")
    max_duration: Optional[int] = Field(default=None, description="Maximum scan duration in minutes")


class ScanRequest(BaseModel):
    """Request to start a new scan - Full REST API v0.1 support

    Based on Burp Suite Professional REST API v0.1 POST /scan endpoint.
    Reference: https://portswigger.net/burp/documentation/desktop/tools/proxy/using

    Full configuration example:
    {
        "urls": ["https://example.com"],
        "scope": {
            "type": "SimpleScope",
            "include": [{"rule": "^https://example\\.com/.*"}],
            "exclude": [{"rule": "^https://example\\.com/logout.*"}]
        },
        "scan_configurations": [
            {"type": "NamedConfiguration", "name": "Crawl and Audit - Fast"}
        ],
        "application_logins": [
            {"type": "UsernameAndPasswordLogin", "username": "admin", "password": "pass123"}
        ],
        "protocol_option": "httpAndHttps",
        "resource_pool": "default",
        "scan_callback": {"url": "https://callback.example.com/webhook"}
    }
    """
    urls: List[str] = Field(..., description="Target URLs to scan")
    scope: Optional[SimpleScope] = Field(default=None, description="Scope configuration")
    scan_configurations: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="List of NamedConfiguration or CustomConfiguration objects"
    )
    application_logins: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="List of UsernameAndPasswordLogin or RecordedLogin objects"
    )
    protocol_option: Optional[str] = Field(
        default=None,
        description="Protocol option: 'httpAndHttps' or 'specified'"
    )
    resource_pool: Optional[str] = Field(default=None, description="Resource pool identifier")
    scan_callback: Optional[ScanCallback] = Field(default=None, description="Webhook callback")

    # Legacy field for backwards compatibility
    scan_configuration: Optional[ScanConfiguration] = Field(
        default=None,
        description="Legacy scan configuration (deprecated, use scope/scan_configurations instead)"
    )
    name: Optional[str] = Field(default=None, description="Scan name (not officially supported)")


class ScanResponse(BaseModel):
    """Response from scan operations"""
    scan_id: str = Field(..., description="Unique scan identifier")
    status: ScanStatus = Field(..., description="Current scan status")
    created_at: Optional[datetime] = Field(default=None, description="Scan creation time")


class IssueEvidence(BaseModel):
    """Evidence for a security issue"""
    request: Optional[str] = Field(default=None, description="HTTP request")
    response: Optional[str] = Field(default=None, description="HTTP response")
    request_response_count: Optional[int] = Field(
        default=None,
        description="Number of request/response pairs"
    )


class Issue(BaseModel):
    """Security issue found during scan"""
    issue_type: str = Field(..., description="Type of issue")
    name: str = Field(..., description="Issue name")
    description: str = Field(..., description="Issue description")
    severity: IssueSeverity = Field(..., description="Severity level")
    confidence: IssueConfidence = Field(..., description="Confidence level")
    path: str = Field(..., description="Affected URL path")
    origin: Optional[str] = Field(default=None, description="Issue origin")
    evidence: Optional[List[IssueEvidence]] = Field(default=None, description="Supporting evidence")
    remediation: Optional[str] = Field(default=None, description="Remediation advice")
    vulnerability_classifications: Optional[List[str]] = Field(
        default=None,
        description="Vulnerability classifications (OWASP, CWE, etc.)"
    )
    serial_number: Optional[int] = Field(default=None, description="Serial number")


class ScanIssues(BaseModel):
    """Collection of issues from a scan"""
    scan_id: str = Field(..., description="Scan identifier")
    issues: List[Issue] = Field(default_factory=list, description="List of issues")
    total_count: int = Field(..., description="Total number of issues")


class ScanDetails(BaseModel):
    """Detailed scan information"""
    scan_id: str = Field(..., description="Unique scan identifier")
    status: ScanStatus = Field(..., description="Current scan status")
    name: Optional[str] = Field(default=None, description="Scan name")
    target_urls: List[str] = Field(default_factory=list, description="Target URLs")
    created_at: Optional[datetime] = Field(default=None, description="Creation timestamp")
    started_at: Optional[datetime] = Field(default=None, description="Start timestamp")
    completed_at: Optional[datetime] = Field(default=None, description="Completion timestamp")
    issue_counts: Optional[Dict[str, int]] = Field(
        default=None,
        description="Count of issues by severity"
    )
    scan_metrics: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Scan metrics (requests, coverage, etc.)"
    )


class ProxyHistory(BaseModel):
    """Proxy history item"""
    id: int = Field(..., description="History item ID")
    url: str = Field(..., description="Request URL")
    method: str = Field(..., description="HTTP method")
    status_code: Optional[int] = Field(default=None, description="Response status code")
    length: Optional[int] = Field(default=None, description="Response length")
    mime_type: Optional[str] = Field(default=None, description="Response MIME type")
    request: Optional[str] = Field(default=None, description="Full HTTP request")
    response: Optional[str] = Field(default=None, description="Full HTTP response")


class RepeaterRequest(BaseModel):
    """Request to send via Repeater"""
    request: str = Field(..., description="HTTP request to send")
    url: str = Field(..., description="Target URL")


class RepeaterResponse(BaseModel):
    """Response from Repeater"""
    request: str = Field(..., description="Sent request")
    response: str = Field(..., description="Received response")
    status_code: int = Field(..., description="HTTP status code")
    time_ms: int = Field(..., description="Response time in milliseconds")


class BurpVersion(BaseModel):
    """Burp Suite version information"""
    product: str = Field(..., description="Product name")
    version: str = Field(..., description="Version number")
    major: int = Field(..., description="Major version")
    minor: int = Field(..., description="Minor version")
