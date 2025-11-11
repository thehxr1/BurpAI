# Burp Suite MCP Workflows for Claude Desktop

> Complete guide for using Burp Suite through Claude Desktop conversations

## Philosophy

**No CLI. No API calls. Just talk to Claude.**

This tool is designed to be used entirely through Claude Desktop. You describe what you want in natural language, and Claude uses the MCP tools to interact with Burp Suite for you.

---

## Setup (One-Time)

### 1. Enable Burp Suite REST API
```
Open Burp Suite Professional
→ Settings → Suite → REST API
→ Enable "Service is running"
→ Generate API key
→ Note the key (you'll need it once)
```

### 2. Configure Claude Desktop

**Windows:** Edit `%APPDATA%\Claude\claude_desktop_config.json`
**macOS:** Edit `~/Library/Application Support/Claude/claude_desktop_config.json`
**Linux:** Edit `~/.config/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "burp-suite": {
      "command": "python",
      "args": [
        "/absolute/path/to/burp-cli/burp_cli/mcp_server/server.py"
      ],
      "env": {
        "BURP_API_URL": "http://127.0.0.1:1337",
        "BURP_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

### 3. Restart Claude Desktop

**That's it!** You never need to touch config files or code again.

---

## How to Use

### Basic Principle

Talk to Claude naturally. Claude will:
1. Choose the right tools
2. Chain them together
3. Interpret results
4. Give you insights

You don't need to know tool names or parameters.

---

## Complete Workflows

### Workflow 1: Simple Scan

**You say:**
```
Scan http://testphp.vulnweb.com/ and tell me what vulnerabilities you find
```

**Claude does:**
1. Uses `burp_start_scan` to start scanning
2. Uses `burp_wait_for_scan` to monitor progress
3. Uses `burp_get_scan_issues` to retrieve findings
4. Analyzes and presents results to you

**You get:**
- List of vulnerabilities by severity
- Affected URLs
- Confidence levels
- Recommendations

---

### Workflow 2: Validate Findings

**You say:**
```
I found a SQL injection at http://example.com/product?id=1
Can you verify if it's real?
```

**Claude does:**
1. Uses `burp_validate_sqli` with various payloads
2. Analyzes response times and error messages
3. Uses `burp_send_to_repeater` for manual verification
4. Gives you a verdict

**You get:**
- True positive or false positive verdict
- Evidence from payload testing
- Exploitability assessment

---

### Workflow 3: Deep Scan with Scope

**You say:**
```
Scan example.com but only test the /api/* endpoints
Ignore /admin and /health paths
```

**Claude does:**
1. Uses `burp_set_scope` to configure includes/excludes
2. Uses `burp_start_scan` with proper URLs
3. Uses `burp_wait_for_scan` to monitor
4. Uses `burp_get_scan_issues` to get results

**You get:**
- Scoped scan results
- Only relevant endpoints tested
- Clean, focused findings

---

### Workflow 4: Investigate Traffic

**You say:**
```
Show me the last 30 requests to example.com
Look for anything suspicious
```

**Claude does:**
1. Uses `burp_get_proxy_history` with filters
2. Analyzes requests for anomalies
3. Identifies interesting patterns
4. Highlights security concerns

**You get:**
- Filtered traffic analysis
- Suspicious requests highlighted
- Security insights

---

### Workflow 5: XSS Verification

**You say:**
```
There's a reflected XSS in the search parameter at /search?q=test
Verify it and show me proof
```

**Claude does:**
1. Uses `burp_validate_xss` with various payloads
2. Uses `burp_send_to_repeater` for custom tests
3. Checks reflection and encoding
4. Provides proof-of-concept

**You get:**
- Confirmed XSS vulnerability
- Working payload
- Exploitation details

---

### Workflow 6: Continuous Monitoring

**You say:**
```
Scan example.com every hour and alert me to new issues
```

**Claude does:**
1. Starts initial scan with `burp_start_scan`
2. Waits for completion with `burp_wait_for_scan`
3. Stores baseline issues
4. Schedules recurring scans
5. Compares new vs baseline

**You get:**
- Alert when new vulnerabilities appear
- Diff showing what changed
- Trending security posture

**Note:** This requires Claude to maintain state between conversations

---

### Workflow 7: Multi-Target Campaign

**You say:**
```
Scan these targets and compare their security:
- https://staging.example.com
- https://prod.example.com
- https://dev.example.com
```

**Claude does:**
1. Launches 3 parallel scans
2. Monitors all with `burp_wait_for_scan`
3. Retrieves issues from each
4. Compares findings across targets

**You get:**
- Comparative security analysis
- Vulnerabilities by environment
- Risk assessment per target

---

### Workflow 8: Remediation Verification

**You say:**
```
We fixed the SQL injection in scan ID 7
Rescan and verify it's gone
```

**Claude does:**
1. Gets original issues from scan 7
2. Starts new scan on same target
3. Compares old vs new issues
4. Confirms fix or reports persistence

**You get:**
- Verification of fix
- Before/after comparison
- Confirmation or follow-up needed

---

## Advanced Conversational Commands

### Start and Monitor
```
You: Scan https://api.example.com and monitor it
Claude: *Starts scan, polls every 10 seconds, reports progress*
```

### Filter Results
```
You: Show me only high severity SQL injection findings from scan 5
Claude: *Filters by severity and issue type*
```

### Chain Actions
```
You: Scan the target, then for each HIGH severity finding, verify it with repeater
Claude: *Automates validation workflow*
```

### Contextual Understanding
```
You: Check if that finding we discussed earlier is fixed
Claude: *Remembers context, rescans the specific URL*
```

---

## What Claude Can Do Automatically

### Intelligent Tool Selection
Claude chooses the right tools based on your request:
- **"Scan"** → `burp_start_scan`
- **"Check status"** → `burp_get_scan_status`
- **"Verify SQL injection"** → `burp_validate_sqli`
- **"Show requests"** → `burp_get_proxy_history`

### Tool Chaining
Claude combines tools for complex workflows:
```
Start scan → Wait → Get issues → Validate each → Report results
```

### Error Recovery
If a tool fails, Claude:
- Retries with different parameters
- Tries alternative approaches
- Explains what went wrong

### Context Awareness
Claude remembers:
- Previous scan IDs
- Discussed vulnerabilities
- Your target applications
- Your security concerns

---

## Example Conversations

### Beginner
```
You: Is Burp connected?
Claude: *Uses burp_health_check*
      Yes! Connected to Burp Suite Professional v2025.10.4

You: Scan testphp.vulnweb.com
Claude: *Starts scan, waits, retrieves issues*
      Found 12 vulnerabilities:
      - 3 HIGH (SQL injection, XSS, XXE)
      - 5 MEDIUM (...)
      - 4 LOW (...)
```

### Intermediate
```
You: Scan api.example.com but exclude /health and /metrics endpoints
Claude: *Sets scope, starts scan*
      Scope configured. Starting scan...
      Status: crawling (found 15 endpoints)
      Status: auditing (testing 12 attack vectors)
      Complete! Found 8 issues.

You: Show me the SQL injection ones
Claude: *Filters results*
      2 SQL injection findings:
      1. POST /api/users - id parameter - HIGH confidence
      2. GET /api/products - search parameter - MEDIUM confidence
```

### Advanced
```
You: For each SQL injection finding in scan 7, test with time-based payloads
     and show me which ones delay responses by 5+ seconds

Claude: *Gets issues, validates each, filters by response time*
      Testing 4 SQL injection findings...

      ✓ POST /api/users - id parameter
        Payload: ' OR SLEEP(5)--
        Response time: 5.2s → CONFIRMED blind SQLi

      ✗ GET /api/products - search parameter
        Response time: 0.3s → False positive

      Result: 1 confirmed time-based SQL injection
```

---

## MCP Tools Reference

You don't need to call these directly, but it helps to know what's available:

| Tool | What It Does | When Claude Uses It |
|------|-------------|-------------------|
| `burp_health_check` | Check connection | "Is Burp running?" |
| `burp_start_scan` | Start security scan | "Scan example.com" |
| `burp_get_scan_status` | Check progress | "How's the scan going?" |
| `burp_get_scan_issues` | Get vulnerabilities | "What did you find?" |
| `burp_wait_for_scan` | Wait for completion | "Scan and tell me when done" |
| `burp_stop_scan` | Cancel scan | "Stop that scan" |
| `burp_send_to_repeater` | Manual HTTP test | "Try this payload" |
| `burp_get_proxy_history` | Get captured traffic | "Show me requests" |
| `burp_set_scope` | Configure scope | "Only scan /api/*" |
| `burp_validate_sqli` | Test SQL injection | "Verify this SQLi" |
| `burp_validate_xss` | Test XSS | "Confirm this XSS" |

---

## Tips for Best Results

### Be Specific
**Good:** "Scan the login page at example.com/login and check for XSS"
**Bad:** "Test the site"

### Provide Context
**Good:** "This is a PHP application with MySQL backend"
**Bad:** "Scan it"

### Ask for Analysis
**Good:** "Which of these findings are actually exploitable?"
**Bad:** "Show results"

### Reference Previous Work
**Good:** "Rescan that endpoint we found SQLi in yesterday"
**Bad:** "Scan again"

### Request Specific Actions
**Good:** "For each XSS finding, test with <script>alert(1)</script>"
**Bad:** "Check XSS"

---

## Limitations

### What Claude CAN'T Do (API v0.1 limitations)
- ❌ List all scans (API doesn't support it)
- ❌ Name scans (Enterprise-only)
- ❌ Modify scanner settings
- ❌ Access Intruder
- ❌ Manage extensions

### What Claude CAN Do
- ✅ Start/stop/monitor scans
- ✅ Retrieve all vulnerabilities
- ✅ Validate findings with payloads
- ✅ Analyze HTTP traffic
- ✅ Configure scan scope
- ✅ Chain multiple operations
- ✅ Provide security insights

---

## Troubleshooting

### "Can't connect to Burp"
```
You: Check if Burp is connected
Claude: *Uses burp_health_check*

If failing:
1. Open Burp Suite
2. Enable REST API in Settings
3. Verify port 1337 is listening
4. Check API key in config
5. Restart Claude Desktop
```

### "Scan taking too long"
```
You: What's the status of scan 5?
Claude: *Shows progress: crawling, auditing, etc.*

You: Stop it and start a faster scan
Claude: *Stops scan, suggests lighter config*
```

### "Too many false positives"
```
You: Validate all HIGH severity findings and show me only true positives
Claude: *Tests each finding, filters out FPs*
```

---

## Next Steps

1. **Set up MCP** (one-time configuration above)
2. **Start simple:** "Scan testphp.vulnweb.com"
3. **Explore:** Try different commands and questions
4. **Go advanced:** Chain operations, validate findings
5. **Automate:** Create recurring workflows

**Remember:** You're having a conversation with Claude. Be natural, provide context, and iterate based on results. Claude handles all the technical complexity.
