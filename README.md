# Burp Suite AI-Powered Security Testing with Claude Desktop

> **AI-Powered Automated Security Testing: Scan → Review → Validate → Report**
> Talk to Burp Suite through Claude Desktop. No commands. No code. Just conversation.

## 🎯 What Is This?

This project provides **two complementary MCP (Model Context Protocol) servers** that enable **AI-powered automated security testing** through Claude Desktop:

1. **burp-scan-automation** (Python) - Scan automation via Burp REST API v0.1
2. **burp-suite-tools** (PortSwigger Official) - Repeater, Intruder, Proxy access

Together, they enable:
- **Automated Scanning**: Start scans with custom configurations, scope, and authentication
- **AI Review**: Claude analyzes findings and identifies real vulnerabilities
- **Smart Validation**: Test vulnerabilities using Repeater/Intruder with Claude-generated payloads
- **Intelligent Reporting**: Get conversational security reports with context

**You say:** "Scan testphp.vulnweb.com, review findings, and validate any SQLi in Repeater"
**Claude does:** Start scan → Wait for completion → Review issues → Validate with custom payloads → Report results

---

## 🏗️ Architecture: Dual MCP System

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Claude Desktop (AI)                          │
│                                                                     │
│  "Scan testphp.vulnweb.com and validate any SQL injection"        │
└────────────────┬────────────────────┬───────────────────────────────┘
                 │                    │
    ┌────────────▼────────┐  ┌────────▼──────────┐
    │ burp-scan-automation│  │ burp-suite-tools  │
    │   (Python MCP)      │  │ (PortSwigger MCP) │
    │                     │  │                   │
    │ 5 Tools:            │  │ 22 Tools:         │
    │ • Start scan        │  │ • Repeater tabs   │
    │ • Get status        │  │ • Intruder attacks│
    │ • Get issues        │  │ • Proxy history   │
    │ • Wait for scan     │  │ • HTTP/2 requests │
    │ • Health check      │  │ • WebSockets      │
    └──────────┬──────────┘  └────────┬──────────┘
               │                      │
               │ REST API v0.1        │ Burp Extension API
               │                      │
    ┌──────────▼──────────────────────▼──────────┐
    │     Burp Suite Professional                │
    │                                             │
    │  • Scanner  • Repeater  • Intruder         │
    │  • Proxy    • Extensions • Collaborator    │
    └─────────────────────────────────────────────┘
```

### Why Two MCPs?

**Burp REST API v0.1 Limitations:**
- ✅ Can start/monitor scans
- ✅ Can retrieve findings
- ❌ **Cannot** access Repeater
- ❌ **Cannot** access Intruder
- ❌ **Cannot** access Proxy
- ❌ **Cannot** use Collaborator

**Solution:** Use **both MCPs together**
- **burp-scan-automation** → Automated scanning via REST API
- **burp-suite-tools** → Manual testing tools (Repeater/Intruder/Proxy)

---

## 🚀 Quick Start (5 Minutes)

### Prerequisites

- ✅ Python 3.10+
- ✅ Burp Suite Professional (with valid license)
- ✅ Claude Desktop app
- ✅ Java 17+ (for PortSwigger MCP only)

### Step 1: Install PortSwigger MCP Extension

The PortSwigger MCP provides 22 tools for Repeater, Intruder, Proxy, and more.

**Quick Installation (Recommended):**

1. **Download the pre-built extension:**
   - Visit: https://github.com/PortSwigger/mcp-server/releases
   - Download `burp-mcp-all.jar` (latest release)

2. **Load extension in Burp Suite:**
   - Open Burp Suite Professional
   - Go to **Extensions → Installed**
   - Click **Add**
   - Select **Extension type: Java**
   - Click **Select file...** → Choose `burp-mcp-all.jar`
   - Click **Next** → Extension loads

3. **Extract the MCP proxy JAR:**
   - A new **MCP** tab appears in Burp
   - Click **"Extract MCP Proxy JAR"** button
   - Save `mcp-proxy-all.jar` to a directory (e.g., `C:\tools\` on Windows or `~/tools/` on macOS/Linux)
   - Remember this path - you'll need it for Claude Desktop configuration

4. **Enable the MCP server:**
   - In the MCP tab, check **"Enabled"** checkbox
   - Optionally check **"Enable tools that can edit your config"** (for configuration management tools)
   - Verify status shows **"Server running on http://127.0.0.1:9876"**

**That's it!** No Gradle compilation needed.

> **For advanced installation options** (building from source, custom configurations), see the official guide:
> https://github.com/PortSwigger/mcp-server#installation

### Step 2: Install burp-scan-automation MCP

```bash
# Clone this repository
git clone https://github.com/thehxr1/burpAI.git
cd burpAI

# Install package
pip install -e .
```

**Notes:**
- This installs the Python package and its dependencies
- No virtual environment needed for MCP use (runs via Claude Desktop)
- Make note of the installation path - you'll need it for Step 4

### Step 3: Enable Burp REST API

1. Open **Burp Suite Professional**
2. Go to **Settings → Suite → REST API**
3. Check **"Enable service"**
4. Click **"Generate API key"** → Copy the key (you'll need it)
5. Verify port is **1337** (default)

### Step 4: Configure Claude Desktop

Edit Claude Desktop's configuration file:

**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Linux:** `~/.config/Claude/claude_desktop_config.json`

Add both MCP servers:

```json
{
  "mcpServers": {
    "burp-scan-automation": {
      "command": "python",
      "args": [
        "/absolute/path/to/burpAI/burp_cli/mcp_server/server.py"
      ],
      "env": {
        "BURP_API_URL": "http://127.0.0.1:1337",
        "BURP_API_KEY": "your-api-key-from-step-3"
      }
    },
    "burp-suite-tools": {
      "command": "/path/to/java",
      "args": [
        "-jar",
        "/path/to/mcp-proxy-all.jar",
        "--sse-url",
        "http://127.0.0.1:9876"
      ]
    }
  }
}
```

**Path Examples:**

**Windows:**
```json
{
  "mcpServers": {
    "burp-scan-automation": {
      "command": "python",
      "args": ["C:\\Projects\\burpAI\\burp_cli\\mcp_server\\server.py"],
      "env": {
        "BURP_API_URL": "http://127.0.0.1:1337",
        "BURP_API_KEY": "PASTE_YOUR_ACTUAL_API_KEY_HERE"
      }
    },
    "burp-suite-tools": {
      "command": "C:\\Program Files\\Java\\jdk-21\\bin\\java.exe",
      "args": ["-jar", "C:\\tools\\mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
    }
  }
}
```

**macOS/Linux:**
```json
{
  "mcpServers": {
    "burp-scan-automation": {
      "command": "python3",
      "args": ["/home/user/projects/burpAI/burp_cli/mcp_server/server.py"],
      "env": {
        "BURP_API_URL": "http://127.0.0.1:1337",
        "BURP_API_KEY": "PASTE_YOUR_ACTUAL_API_KEY_HERE"
      }
    },
    "burp-suite-tools": {
      "command": "/usr/bin/java",
      "args": ["-jar", "/Users/user/tools/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
    }
  }
}
```

**Important:**
- Replace `/absolute/path/to/` with your actual installation directory
- On Windows, use double backslashes: `C:\\Projects\\...`
- On macOS/Linux, use forward slashes: `/home/user/...`
- Paste your actual Burp API key from Step 3
- Find your Java path: `where java` (Windows) or `which java` (macOS/Linux)

### Step 5: Restart Claude Desktop & Test

1. **Close and reopen Claude Desktop**

2. **Test connectivity:**
```
Check if Burp Suite is connected
```

Expected response: Burp version information

3. **Test scan automation:**
```
Scan https://testphp.vulnweb.com
```

Expected response: Scan started, monitoring progress, findings reported

4. **Test Repeater (if PortSwigger MCP working):**
```
Send a GET request to https://testphp.vulnweb.com to Repeater
```

Expected response: Repeater tab created

**You're ready!** See [AI Workflows](#-ai-powered-workflows) below.

---

## 🤖 AI-Powered Workflows

### Workflow 1: Automated Scan → Review → Report

**You:** "Scan testphp.vulnweb.com and report HIGH severity findings"

**Claude does:**
1. `burp_start_scan` → Start scan on target
2. `burp_wait_for_scan` → Monitor until completion
3. `burp_get_scan_issues(severity='high')` → Retrieve high-severity issues
4. **AI Analysis** → Review each finding, explain impact
5. **Report** → Conversational summary with remediation advice

### Workflow 2: Scan → Validate with Repeater

**You:** "Scan example.com/api and validate any SQLi findings in Repeater"

**Claude does:**
1. `burp_start_scan` → Start scan
2. `burp_wait_for_scan` → Wait for completion
3. `burp_get_scan_issues` → Get all issues
4. **AI Review** → Identify potential SQL injection issues
5. `CreateRepeaterTab` (PortSwigger MCP) → Send request to Repeater
6. **AI Validation** → Suggest payloads: `' OR SLEEP(5)--`, `' UNION SELECT NULL--`
7. **Report** → Confirmed or false positive

### Workflow 3: Scoped Authenticated Scan

**You:** "Scan api.example.com with username 'admin' and password 'test123', but exclude /health and /metrics endpoints"

**Claude does:**
1. `burp_start_scan` → Start scan with:
   - URLs: `["https://api.example.com"]`
   - Authentication: `{"type": "UsernameAndPasswordLogin", "username": "admin", "password": "test123"}`
   - Scope: `{"include": ["^https://api\\.example\\.com/.*"], "exclude": ["^https://api\\.example\\.com/health.*", "^https://api\\.example\\.com/metrics.*"]}`
2. `burp_wait_for_scan` → Monitor progress
3. `burp_get_scan_issues` → Retrieve findings
4. **AI Report** → Context-aware report for authenticated API scan

### Workflow 4: Proxy History Analysis → Intruder Attack

**You:** "Show me POST requests to /login in proxy history, then fuzz the password parameter"

**Claude does:**
1. `GetProxyHttpHistoryRegex` (PortSwigger MCP) → Filter for `/login` POST requests
2. **AI Analysis** → Identify login request format
3. `SendToIntruder` (PortSwigger MCP) → Create Intruder attack with password position marked
4. **AI Suggestion** → Recommend wordlist: "Use common passwords list for brute force testing"

### Workflow 5: Comprehensive Security Assessment

**You:** "Perform a full security assessment on app.example.com including authentication testing"

**Claude does:**
1. `burp_health_check` → Verify Burp connectivity
2. `burp_start_scan` → Start comprehensive scan
3. `burp_wait_for_scan` → Monitor progress (may take 30+ minutes)
4. `burp_get_scan_issues` → Get all findings
5. **AI Categorization** → Group by:
   - Authentication issues (session management, password policy)
   - Injection flaws (SQLi, XSS, Command Injection)
   - Access control vulnerabilities
   - Cryptographic weaknesses
   - Configuration issues
6. For critical findings:
   - `CreateRepeaterTab` → Manual validation
   - **AI Payload Generation** → Suggest exploitation payloads
7. **Executive Report** → Business-impact focused summary
8. **Technical Report** → Detailed findings with remediation

---

## 📋 Available Tools

### burp-scan-automation (Python MCP)

| Tool | Description | Use Case |
|------|-------------|----------|
| `burp_start_scan` | Start security scan | Basic scanning with URLs |
| `burp_get_scan_status` | Get scan progress | Monitor running scans |
| `burp_get_scan_issues` | Retrieve vulnerabilities | Get findings (can filter by severity) |
| `burp_wait_for_scan` | Wait for completion | Automated workflows |
| `burp_health_check` | Check connectivity | Verify setup |

**Supported Scan Parameters** (via `burp_start_scan`):
- **URLs**: Target URLs to scan
- **Scope**: Include/exclude patterns (regex supported)
- **Authentication**: Username/password or recorded login
- **Scan Configuration**: Built-in configs (e.g., "Crawl and Audit - Fast")
- **Protocol**: HTTP/HTTPS selection
- **Resource Pool**: For scan prioritization

### burp-suite-tools (PortSwigger MCP)

**Complete tool list (22 tools):**

#### HTTP Request Tools
| Tool | Description |
|------|-------------|
| `SendHttp1Request` | Issues an HTTP/1.1 request and returns the response |
| `SendHttp2Request` | Issues an HTTP/2 request and returns the response |
| `CreateRepeaterTab` | Creates a new Repeater tab with the specified HTTP request |
| `SendToIntruder` | Sends an HTTP request to Intruder with position markers |

#### Proxy & History Access
| Tool | Description |
|------|-------------|
| `GetProxyHttpHistory` | Displays items within the proxy HTTP history |
| `GetProxyHttpHistoryRegex` | Displays items matching a specified regex within the proxy HTTP history |
| `GetProxyWebsocketHistory` | Displays items within the proxy WebSocket history |
| `GetProxyWebsocketHistoryRegex` | Displays items matching a specified regex within the proxy WebSocket history |
| `SetProxyInterceptState` | Enables or disables Burp Proxy Intercept |

#### Scanner Tools (Professional only)
| Tool | Description |
|------|-------------|
| `GetScannerIssues` | Displays information about issues identified by the scanner |

#### Encoding/Decoding Tools
| Tool | Description |
|------|-------------|
| `UrlEncode` | URL encodes the input string |
| `UrlDecode` | URL decodes the input string |
| `Base64Encode` | Base64 encodes the input string |
| `Base64Decode` | Base64 decodes the input string |
| `GenerateRandomString` | Generates a random string of specified length and character set |

#### Configuration Management
| Tool | Description |
|------|-------------|
| `output_project_options` | Outputs current project-level configuration in JSON format |
| `output_user_options` | Outputs current user-level configuration in JSON format |
| `SetProjectOptions` | Sets project-level configuration in JSON format |
| `SetUserOptions` | Sets user-level configuration in JSON format |

#### Editor & Task Management
| Tool | Description |
|------|-------------|
| `get_active_editor_contents` | Outputs the contents of the user's active message editor |
| `SetActiveEditorContents` | Sets the content of the user's active message editor |
| `SetTaskExecutionEngineState` | Sets the state of Burp's task execution engine (paused or unpaused) |

> **Note:** For detailed documentation on all PortSwigger MCP tools, see: https://github.com/PortSwigger/mcp-server

---

## 💬 Example Conversations

### Example 1: Quick Scan

```
You: Scan testphp.vulnweb.com

Claude: I'll start a security scan on testphp.vulnweb.com.

Starting scan... ✓
Scan ID: 10
Status: queued → crawling → auditing...

Scan completed in 3 minutes 42 seconds.

Found 12 vulnerabilities:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
HIGH (2):
  • SQL injection at /listproducts.php?cat=
  • Cross-site scripting at /search.php?test=

MEDIUM (5):
  • Session ID in URL
  • Password field with autocomplete enabled
  • Missing security headers (3 instances)

LOW (5):
  • Information disclosure
  • ...

Would you like me to validate any of these findings?
```

### Example 2: Validation Workflow

```
You: Validate that SQL injection issue

Claude: I'll validate the SQL injection at /listproducts.php?cat=1

Creating Repeater tab... ✓

Testing with payloads:
1. ' OR '1'='1
   → Response: 200 OK (all products shown - possible bypass)

2. ' OR SLEEP(5)--
   → Response: Delayed by 5.3 seconds ✓ CONFIRMED

3. ' UNION SELECT NULL,NULL,NULL--
   → Response: 200 OK (union query worked)

4. ' UNION SELECT @@version,NULL,NULL--
   → Response: MySQL 5.7.31 ✓ VERSION DISCLOSED

CONFIRMED: Time-based blind SQL injection
Severity: CRITICAL
Impact: Full database access, potential data exfiltration

Recommendation: Use parameterized queries (prepared statements)
```

### Example 3: Authenticated Scan

```
You: Scan admin.example.com with credentials admin:password123, exclude /logout

Claude: Starting authenticated scan with scope configuration...

Configuration:
  URLs: ["https://admin.example.com"]
  Authentication: Username/Password (admin)
  Scope Exclusions: ["/logout"]

Scan started... ✓
Logged in successfully ✓
Crawling authenticated pages...

Found 8 admin-only endpoints:
  /admin/users
  /admin/settings
  /admin/reports
  ...

Testing for vulnerabilities in authenticated context...

Scan complete. Found 3 issues requiring attention:
...
```

---

## 🔧 Configuration

### burp-scan-automation Configuration

The Python MCP uses environment variables from Claude Desktop config:

```json
{
  "env": {
    "BURP_API_URL": "http://127.0.0.1:1337",
    "BURP_API_KEY": "your-api-key"
  }
}
```

### burp-suite-tools Configuration

The PortSwigger MCP connects to Burp's extension API via SSE:

```json
{
  "args": [
    "-jar",
    "/path/to/mcp-proxy-all.jar",
    "--sse-url",
    "http://127.0.0.1:9876"
  ]
}
```

The SSE server runs inside Burp as an extension.

---

## 📁 Project Structure

```
burpAI/
├── burp_cli/
│   ├── api/                    # Burp REST API client
│   │   ├── client.py           # Full REST API v0.1 implementation
│   │   ├── models.py           # Pydantic models (all parameters)
│   │   └── exceptions.py       # Custom exceptions
│   ├── mcp_server/             # MCP server for Claude
│   │   └── server.py           # 5 scan automation tools
│   └── utils/
│       ├── config.py           # Configuration management
│       └── logger.py           # Logging
├── docs/
│   ├── SETUP.md                # Detailed setup guide (if available)
│   └── API_REFERENCE.md        # REST API documentation (if available)
├── README.md                   # This file
└── pyproject.toml              # Package configuration
```

---

## 🎯 Implementation Status

### ✅ Completed

**burp-scan-automation MCP (Python):**
- ✅ Full REST API v0.1 client implementation
- ✅ All scan configuration parameters (scope, auth, configs)
- ✅ 5 MCP tools for scan automation
- ✅ Issue retrieval with severity filtering
- ✅ Scan status monitoring with all states
- ✅ Health check and connectivity verification

**burp-suite-tools MCP (PortSwigger):**
- ✅ 22 tools for Burp Suite integration
- ✅ Repeater tab creation
- ✅ Intruder attack setup
- ✅ Proxy history access
- ✅ HTTP/1.1 and HTTP/2 support
- ✅ WebSocket testing
- ✅ Encoding/decoding utilities

### ⚠️ Known Limitations

**Burp REST API v0.1:**
- ❌ Cannot list all scans (only GET by scan ID)
- ❌ Cannot delete scans
- ❌ No separate issues endpoint (issues in scan status response)
- ❌ Limited to basic scan configurations

**Workaround:** Track scan IDs locally or use PortSwigger MCP's `GetScannerIssues` tool

---

## 🛡️ Security Note

**This tool is for authorized security testing only.**

- Always obtain written permission before scanning targets
- Never use against systems you don't own or have authorization for
- Store API keys securely (never commit to git)
- Use `.env` or environment variables for sensitive data

---

## 📚 Additional Resources

- [Burp REST API Documentation](https://portswigger.net/burp/documentation/desktop/tools/proxy/using)
- [MCP Protocol Specification](https://modelcontextprotocol.io/)
- [PortSwigger MCP Repository](https://github.com/PortSwigger/mcp-server)
- [Claude Desktop Documentation](https://claude.ai/desktop)

---

## 🤝 Contributing

Contributions, issues, and feature requests are welcome! Feel free to check the [issues page](https://github.com/thehxr1/BurpAI/issues).

**Like this project?** Follow my security research blog: [https://hxr1.ghost.io](https://hxr1.ghost.io)

---

## 📄 License

MIT License - See LICENSE file for details.

---

## 🙏 Credits

- **Anthropic** - Claude Desktop and MCP Protocol
- **PortSwigger** - Burp Suite Professional and official MCP extension
- **cihanmehmet** - burp-cli reference implementation

---

**Made with ❤️ for AI-powered security testing**
