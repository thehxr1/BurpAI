"""
Burp Suite REST API Client
"""

import asyncio
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

import httpx
from httpx import AsyncClient, Response

from .exceptions import (
    BurpAPIError,
    BurpAuthError,
    BurpConnectionError,
    BurpInvalidRequestError,
    BurpResourceNotFoundError,
    BurpScanError,
)
from .models import (
    BurpVersion,
    Issue,
    ProxyHistory,
    RepeaterRequest,
    RepeaterResponse,
    ScanDetails,
    ScanIssues,
    ScanRequest,
    ScanResponse,
    ScanStatus,
    ScopeRule,
)


class BurpClient:
    """
    Async HTTP client for Burp Suite REST API

    Example:
        async with BurpClient(api_url="http://127.0.0.1:1337", api_key="your-key") as client:
            scan = await client.start_scan(["https://example.com"])
            print(f"Scan started: {scan.scan_id}")
    """

    def __init__(
        self,
        api_url: str,
        api_key: str,
        timeout: int = 30,
        verify_ssl: bool = True
    ):
        """
        Initialize Burp API client

        Args:
            api_url: Burp Suite REST API base URL
            api_key: API key for authentication
            timeout: Request timeout in seconds
            verify_ssl: Verify SSL certificates
        """
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self._client: Optional[AsyncClient] = None

    async def __aenter__(self) -> "BurpClient":
        """Async context manager entry"""
        self._client = AsyncClient(
            base_url=self.api_url,
            headers=self._get_headers(),
            timeout=self.timeout,
            verify=self.verify_ssl
        )
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit"""
        if self._client:
            await self._client.aclose()

    def _get_headers(self) -> Dict[str, str]:
        """Get request headers with API key"""
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

    async def _request(
        self,
        method: str,
        endpoint: str,
        **kwargs: Any
    ) -> Response:
        """
        Make HTTP request to Burp API

        Args:
            method: HTTP method
            endpoint: API endpoint
            **kwargs: Additional arguments for httpx

        Returns:
            HTTP response

        Raises:
            BurpConnectionError: If connection fails
            BurpAuthError: If authentication fails
            BurpAPIError: For other API errors
        """
        if not self._client:
            raise BurpAPIError("Client not initialized. Use async context manager.")

        url = f"/{self.api_key}/{endpoint.lstrip('/')}"

        try:
            response = await self._client.request(method, url, **kwargs)
            self._handle_response_errors(response)
            return response

        except httpx.ConnectError as e:
            raise BurpConnectionError(
                f"Failed to connect to Burp API at {self.api_url}"
            ) from e
        except httpx.TimeoutException as e:
            raise BurpConnectionError(
                f"Request timeout after {self.timeout}s"
            ) from e

    def _handle_response_errors(self, response: Response) -> None:
        """Handle HTTP error responses"""
        if response.status_code == 401:
            raise BurpAuthError("Invalid API key")
        elif response.status_code == 404:
            raise BurpResourceNotFoundError("Resource not found")
        elif response.status_code == 400:
            raise BurpInvalidRequestError(
                f"Bad request: {response.text}"
            )
        elif response.status_code >= 500:
            raise BurpAPIError(
                f"Server error: {response.status_code} - {response.text}",
                status_code=response.status_code
            )
        elif not response.is_success:
            raise BurpAPIError(
                f"Request failed: {response.status_code} - {response.text}",
                status_code=response.status_code
            )

    # ========== Version & Health ==========

    async def get_version(self) -> BurpVersion:
        """Get Burp Suite version information from response headers"""
        # Burp API v0.1 doesn't have a version endpoint, but includes version in headers
        response = await self._request("GET", "v0.1/")
        version_header = response.headers.get("X-Burp-Version", "Unknown")

        # Parse version from header (e.g., "2025.10.4-43098")
        if version_header and version_header != "Unknown":
            parts = version_header.split("-")[0].split(".")
            major = int(parts[0]) if len(parts) > 0 else 0
            minor = int(parts[1]) if len(parts) > 1 else 0
        else:
            major, minor = 0, 0

        return BurpVersion(
            product="Burp Suite Professional",
            version=version_header,
            major=major,
            minor=minor
        )

    async def health_check(self) -> bool:
        """Check if Burp API is accessible"""
        try:
            await self.get_version()
            return True
        except Exception:
            return False

    # ========== Scan Management ==========

    async def start_scan(
        self,
        urls: List[str],
        scope: Optional[Dict[str, Any]] = None,
        scan_configurations: Optional[List[Dict[str, Any]]] = None,
        application_logins: Optional[List[Dict[str, Any]]] = None,
        protocol_option: Optional[str] = None,
        resource_pool: Optional[str] = None,
        scan_callback: Optional[Dict[str, str]] = None,
        # Legacy parameters for backwards compatibility
        scan_config: Optional[Dict[str, Any]] = None,
        name: Optional[str] = None
    ) -> ScanResponse:
        """
        Start a new scan with full REST API v0.1 configuration support

        Args:
            urls: List of target URLs to scan
            scope: Scope configuration with include/exclude rules
                Example: {
                    "type": "SimpleScope",
                    "include": [{"rule": "^https://example\\.com/.*"}],
                    "exclude": [{"rule": "^https://example\\.com/logout.*"}]
                }
            scan_configurations: List of scan configurations (NamedConfiguration or CustomConfiguration)
                Example: [{"type": "NamedConfiguration", "name": "Crawl and Audit - Fast"}]
            application_logins: List of authentication methods
                Example: [{"type": "UsernameAndPasswordLogin", "username": "admin", "password": "pass"}]
            protocol_option: Protocol option ("httpAndHttps" or "specified")
            resource_pool: Resource pool identifier
            scan_callback: Webhook callback configuration
                Example: {"url": "https://callback.example.com/webhook"}
            scan_config: [DEPRECATED] Legacy scan configuration parameter
            name: [DEPRECATED] Scan name (Enterprise only, not supported in Pro)

        Returns:
            Scan response with scan ID and initial status

        Reference:
            Based on Burp Suite Professional REST API v0.1 POST /scan endpoint
            https://portswigger.net/burp/documentation/desktop/tools/proxy/using
        """
        # Build the scan request payload
        payload: Dict[str, Any] = {
            "urls": urls
        }

        # Add full REST API v0.1 parameters
        if scope:
            payload["scope"] = scope

        if scan_configurations:
            payload["scan_configurations"] = scan_configurations

        if application_logins:
            payload["application_logins"] = application_logins

        if protocol_option:
            if protocol_option not in ("httpAndHttps", "specified"):
                raise BurpInvalidRequestError(
                    f"Invalid protocol_option: {protocol_option}. Must be 'httpAndHttps' or 'specified'"
                )
            payload["protocol_option"] = protocol_option

        if resource_pool:
            payload["resource_pool"] = resource_pool

        if scan_callback:
            payload["scan_callback"] = scan_callback

        # Legacy support: convert old scan_config parameter if provided
        if scan_config and not scan_configurations:
            # This is for backwards compatibility - convert to new format if needed
            payload["scan_configuration"] = scan_config

        # Note: name parameter is Enterprise-only, not supported in Professional
        # Omitted intentionally

        response = await self._request("POST", "v0.1/scan", json=payload)

        # Burp API returns 201 with Location header containing the task_id
        # Response body is empty, so we parse the Location header
        location = response.headers.get("Location", "")
        task_id = location.strip("/").split("/")[-1]  # Extract task ID from Location

        return ScanResponse(
            scan_id=task_id,
            status=ScanStatus.QUEUED
        )

    async def get_scan_status(self, scan_id: str) -> ScanDetails:
        """
        Get scan status and details

        Args:
            scan_id: Scan identifier

        Returns:
            Scan details including status
        """
        response = await self._request("GET", f"v0.1/scan/{scan_id}")
        data = response.json()

        return ScanDetails(
            scan_id=scan_id,
            status=ScanStatus(data.get("scan_status", "running").lower()),
            issue_counts=data.get("issue_counts"),
            scan_metrics=data.get("scan_metrics")
        )

    async def stop_scan(self, scan_id: str) -> bool:
        """Stop a running scan"""
        try:
            await self._request("DELETE", f"v0.1/scan/{scan_id}")
            return True
        except Exception:
            return False

    async def list_scans(self) -> List[ScanDetails]:
        """
        List all scans

        Note: Burp API v0.1 does not support listing all scans.
        This method is kept for API compatibility but returns an empty list.
        Consider tracking scan IDs locally if you need to list scans.
        """
        # Burp API v0.1 doesn't have a list scans endpoint
        # Return empty list for now
        return []

    async def wait_for_scan(
        self,
        scan_id: str,
        poll_interval: int = 5,
        max_wait_time: int = 3600,
        callback: Optional[callable] = None
    ) -> ScanDetails:
        """
        Wait for scan to complete

        Args:
            scan_id: Scan identifier
            poll_interval: Polling interval in seconds
            max_wait_time: Maximum time to wait in seconds (default: 3600)
            callback: Optional callback function for status updates

        Returns:
            Final scan details (returns current status if timeout)
        """
        elapsed = 0
        while elapsed < max_wait_time:
            details = await self.get_scan_status(scan_id)

            if callback:
                callback(details)

            if details.status in [
                ScanStatus.SUCCEEDED,
                ScanStatus.FAILED,
                ScanStatus.CANCELLED
            ]:
                return details

            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

        # Timeout - return current status
        return await self.get_scan_status(scan_id)

    # ========== Issues ==========

    async def get_scan_issues(
        self,
        scan_id: str,
        severity: Optional[str] = None
    ) -> ScanIssues:
        """
        Get issues from a scan

        Note: Burp API v0.1 returns issues as part of the scan status response,
        not as a separate endpoint.

        Args:
            scan_id: Scan identifier
            severity: Optional severity filter (high, medium, low, info)

        Returns:
            Scan issues
        """
        # Get scan details which includes issue_events
        response = await self._request("GET", f"v0.1/scan/{scan_id}")
        data = response.json()

        # Extract issue events from the scan response
        issues_data = data.get("issue_events", [])

        # Filter by severity if specified
        if severity:
            issues_data = [
                issue for issue in issues_data
                if issue.get("severity", "").lower() == severity.lower()
            ]

        # Convert to Issue objects
        issues = []
        for issue_data in issues_data:
            try:
                issues.append(Issue(**issue_data))
            except Exception:
                # Skip issues that don't match our schema
                continue

        return ScanIssues(
            scan_id=scan_id,
            issues=issues,
            total_count=len(issues)
        )

    async def get_issue_definitions(self) -> List[Dict[str, Any]]:
        """
        Get Burp's knowledge base of issue definitions

        Returns all issue types with their descriptions, remediation advice,
        and vulnerability classifications.

        Returns:
            List of issue definitions

        Reference:
            GET /{api_key}/v0.1/knowledge_base/issue_definitions
        """
        response = await self._request("GET", "v0.1/knowledge_base/issue_definitions")
        data = response.json()

        # API returns array of issue definitions
        return data if isinstance(data, list) else []

    # ========== Proxy History ==========

    async def get_proxy_history(
        self,
        limit: int = 100,
        filter_url: Optional[str] = None
    ) -> List[ProxyHistory]:
        """
        Get proxy history

        Args:
            limit: Maximum number of items
            filter_url: Optional URL filter

        Returns:
            List of proxy history items
        """
        params = {"limit": limit}
        if filter_url:
            params["url"] = filter_url

        response = await self._request("GET", "v0.1/proxy/history", params=params)
        data = response.json()

        items = data.get("history", [])
        return [ProxyHistory(**item) for item in items]

    # ========== Repeater ==========

    async def send_to_repeater(
        self,
        request: str,
        url: str
    ) -> RepeaterResponse:
        """
        Send request via Repeater

        Args:
            request: HTTP request to send
            url: Target URL

        Returns:
            Repeater response
        """
        payload = {
            "request": request,
            "url": url
        }

        response = await self._request("POST", "v0.1/repeater", json=payload)
        data = response.json()

        return RepeaterResponse(**data)

    # ========== Scope ==========

    async def set_scope(self, rules: List[ScopeRule]) -> bool:
        """
        Set target scope

        Args:
            rules: List of scope rules

        Returns:
            Success status
        """
        payload = {
            "include": [r.url for r in rules if r.include],
            "exclude": [r.url for r in rules if not r.include]
        }

        try:
            await self._request("PUT", "v0.1/scope", json=payload)
            return True
        except Exception:
            return False

    async def get_scope(self) -> List[ScopeRule]:
        """Get current scope configuration"""
        response = await self._request("GET", "v0.1/scope")
        data = response.json()

        rules = []
        for url in data.get("include", []):
            rules.append(ScopeRule(url=url, include=True))
        for url in data.get("exclude", []):
            rules.append(ScopeRule(url=url, include=False))

        return rules
