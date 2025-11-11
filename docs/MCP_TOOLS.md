# MCP Tools Reference

This document describes all available MCP tools that Claude Desktop can use to interact with Burp Suite.

## Connection & Health

### `burp_health_check`

Check if Burp Suite REST API is accessible and working correctly.

**Returns:**
- Connection status
- Burp Suite version information

**Example:**
```
Claude, check if Burp Suite is connected
```

## Scan Management

### `burp_start_scan`

Start a security scan on target URLs.

**Parameters:**
- `urls` (required): Array of target URLs
- `scan_name` (optional): Name for the scan

**Returns:**
- Scan ID
- Initial status

**Example:**
```
Scan https://example.com for vulnerabilities
```

### `burp_get_scan_status`

Get current status and progress of a scan.

**Parameters:**
- `scan_id` (required): Scan identifier

**Returns:**
- Current status (queued/running/succeeded/failed)
- Issue counts by severity
- Scan metrics

**Example:**
```
What's the status of scan abc123?
```

### `burp_wait_for_scan`

Wait for a scan to complete.

**Parameters:**
- `scan_id` (required): Scan identifier
- `poll_interval` (optional): Polling interval in seconds (default: 5)

**Returns:**
- Final scan status
- Issue counts

**Example:**
```
Wait for scan abc123 to finish
```

### `burp_list_scans`

List all scans with their current status.

**Returns:**
- Array of scans with IDs and statuses

**Example:**
```
Show me all running scans
```

### `burp_stop_scan`

Stop a running scan.

**Parameters:**
- `scan_id` (required): Scan identifier

**Returns:**
- Success status

**Example:**
```
Stop scan abc123
```

## Issue Analysis

### `burp_get_scan_issues`

Retrieve security issues found during a scan.

**Parameters:**
- `scan_id` (required): Scan identifier
- `severity` (optional): Filter by severity (high/medium/low/info)

**Returns:**
- Total issue count
- Array of issues with:
  - Name and description
  - Severity and confidence
  - Affected URL path
  - Evidence
  - Remediation advice

**Example:**
```
Show me all high severity issues from scan abc123
```

## Validation Tools

### `burp_validate_sqli`

Validate a potential SQL injection vulnerability.

**Parameters:**
- `url` (required): Target URL
- `parameter` (required): Vulnerable parameter name
- `original_request` (required): Original HTTP request

**Returns:**
- Test results for multiple SQLi payloads
- Response analysis
- Validation recommendation

**Example:**
```
Validate the SQL injection at https://example.com/login?user=admin
```

### `burp_validate_xss`

Validate a potential XSS vulnerability.

**Parameters:**
- `url` (required): Target URL
- `parameter` (required): Vulnerable parameter name
- `original_request` (required): Original HTTP request

**Returns:**
- Test results for XSS payloads
- Reflection analysis
- Validation recommendation

**Example:**
```
Validate the XSS finding in the search parameter
```

## Manual Testing

### `burp_send_to_repeater`

Send a custom HTTP request for manual testing.

**Parameters:**
- `request` (required): Full HTTP request
- `url` (required): Target URL

**Returns:**
- Status code
- Response body (truncated)
- Response time

**Example:**
```
Send a request to https://example.com with header X-Test: 123
```

### `burp_get_proxy_history`

Retrieve HTTP traffic captured by Burp Proxy.

**Parameters:**
- `limit` (optional): Maximum items to return (default: 100)
- `filter_url` (optional): URL pattern filter

**Returns:**
- Array of proxy history items with:
  - Request method and URL
  - Response status code
  - Request/response data

**Example:**
```
Show me the last 50 requests to api.example.com
```

## Scope Management

### `burp_set_scope`

Configure target scope for Burp Suite.

**Parameters:**
- `include` (optional): Array of URL patterns to include
- `exclude` (optional): Array of URL patterns to exclude

**Returns:**
- Success status
- Number of rules configured

**Example:**
```
Set scope to include https://example.com/* and exclude */logout
```

## Workflow Examples

### Complete Scan with AI Validation

```
You: Scan example.com and validate all SQL injection findings

Claude will:
1. Use burp_start_scan to initiate scan
2. Use burp_wait_for_scan to monitor progress
3. Use burp_get_scan_issues to retrieve findings
4. Use burp_validate_sqli for each SQLi issue
5. Analyze results and report only confirmed vulnerabilities
```

### Interactive Testing

```
You: I want to test the login form at example.com/login

Claude will:
1. Use burp_get_proxy_history to see existing requests
2. Use burp_send_to_repeater to test different payloads
3. Analyze responses for vulnerabilities
4. Provide exploitation recommendations
```

### Continuous Monitoring

```
You: Monitor example.com and alert me to new high severity issues

Claude will:
1. Use burp_start_scan to begin scanning
2. Periodically use burp_get_scan_status to check progress
3. Use burp_get_scan_issues with severity=high
4. Validate findings using appropriate validation tools
5. Report confirmed critical vulnerabilities
```

## Best Practices

### When Asking Claude to Scan

✅ **Good:**
- "Scan example.com and show me confirmed SQL injections"
- "Test api.example.com for authentication bypasses"
- "Find and validate XSS in example.com/search"

❌ **Avoid:**
- Scanning without permission
- Aggressive scanning of production systems
- Ignoring rate limits

### When Validating Findings

✅ **Good:**
- "Validate this SQLi finding before adding to report"
- "Confirm if this XSS is actually exploitable"
- "Test if this vulnerability works in production"

❌ **Avoid:**
- Blindly trusting Burp's findings
- Skipping validation for high-severity issues
- Not documenting validation steps

### When Using Repeater

✅ **Good:**
- "Test this endpoint with different authentication tokens"
- "Try these SQL injection payloads on the user parameter"
- "Check if the API validates input properly"

❌ **Avoid:**
- Sending too many requests (DoS)
- Testing destructive operations
- Ignoring application state

## Error Handling

### Common Errors

1. **Connection Failed**
   - Ensure Burp Suite is running
   - Check API key is correct
   - Verify REST API is enabled

2. **Scan Not Found**
   - Scan ID may be invalid
   - Scan may have been deleted

3. **Invalid Request**
   - Check required parameters
   - Validate URL format
   - Ensure proper request syntax

## Rate Limiting

The MCP server does not implement rate limiting, but you should:
- Avoid rapid consecutive scans
- Use appropriate poll intervals
- Consider target application limits
- Monitor Burp Suite resource usage

## Security Considerations

⚠️ **Important:**
- Only scan targets you have permission to test
- Store API keys securely
- Don't share scan results publicly
- Follow responsible disclosure practices
- Comply with testing agreements

---

For more information, see the main [README.md](../README.md) and [SETUP.md](SETUP.md).
