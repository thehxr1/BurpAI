# Claude Desktop Setup - Complete ✓

## ✅ Setup Status

Your Claude Desktop is now configured with the Burp Suite MCP server!

## 📝 Configuration Applied

**File Location:**
```
C:\Users\c559028\AppData\Roaming\Claude\claude_desktop_config.json
```

**Configuration:**
```json
{
  "mcpServers": {
    "attackforge": {
      "command": "node",
      "args": [
        "C:\\Users\\c559028\\attackforce\\attackforge-mcp\\dist\\index.js"
      ]
    },
    "burp-suite": {
      "command": "C:\\Users\\c559028\\MyWork\\burp-cli\\venv\\Scripts\\python.exe",
      "args": [
        "C:\\Users\\c559028\\MyWork\\burp-cli\\burp_cli\\mcp_server\\server.py"
      ],
      "env": {
        "BURP_API_URL": "http://127.0.0.1:1337",
        "BURP_API_KEY": "23jfiw-djsk3-fc93k"
      }
    }
  }
}
```

**Backup Created:**
```
C:\Users\c559028\AppData\Roaming\Claude\claude_desktop_config.json.backup
```

## 🚀 Next Steps

### 1. Restart Claude Desktop

**IMPORTANT:** You must restart Claude Desktop for the changes to take effect.

1. Close Claude Desktop completely (check system tray)
2. Reopen Claude Desktop
3. The MCP server will load automatically

### 2. Enable Burp Suite REST API

Before testing, ensure Burp Suite is configured:

1. Open **Burp Suite Professional**
2. Go to: **Settings → Suite → REST API**
3. Check **"Service running"**
4. Verify URL: `http://127.0.0.1:1337`
5. Your API key is already configured: `23jfiw-djsk3-fc93k`

### 3. Test the Integration

Once Claude Desktop is restarted and Burp Suite is running, try these commands:

**Test Connection:**
```
You: "Check if Burp Suite is connected"
Claude: *Should use burp_health_check tool*
```

**Start a Scan:**
```
You: "Scan https://example.com"
Claude: *Should use burp_start_scan tool*
```

**Get Scan Results:**
```
You: "Show me issues from the scan"
Claude: *Should use burp_get_scan_issues tool*
```

## 🔧 Available MCP Tools

Once loaded, Claude Desktop will have access to 12 Burp Suite tools:

1. **burp_health_check** - Verify Burp connection
2. **burp_start_scan** - Initiate security scans
3. **burp_get_scan_status** - Check scan progress
4. **burp_get_scan_issues** - Retrieve vulnerabilities
5. **burp_wait_for_scan** - Monitor scan completion
6. **burp_send_to_repeater** - Manual request testing
7. **burp_get_proxy_history** - View captured traffic
8. **burp_list_scans** - List all scans
9. **burp_stop_scan** - Cancel running scans
10. **burp_set_scope** - Configure target scope
11. **burp_validate_sqli** - SQL injection validation
12. **burp_validate_xss** - XSS validation

## 🐛 Troubleshooting

### Claude Desktop Doesn't Show Burp Tools

**Check MCP Server Logs:**
```
C:\Users\c559028\AppData\Roaming\Claude\logs\mcp*.log
```

**Verify Python Path:**
```bash
C:\Users\c559028\MyWork\burp-cli\venv\Scripts\python.exe --version
```

Should show: Python 3.13.5

### Connection Errors

1. **Ensure Burp Suite is running** - The REST API must be enabled
2. **Check API key** - Verify it matches in both Burp and the config
3. **Check port** - Default is 1337, confirm it's not in use

### MCP Server Won't Load

**Test manually:**
```bash
cd C:\Users\c559028\MyWork\burp-cli
venv\Scripts\python.exe burp_cli\mcp_server\server.py
```

If this fails, check:
- Virtual environment is intact
- All dependencies are installed
- No syntax errors in server.py

### Restore Previous Config

If you need to rollback:
```bash
copy "C:\Users\c559028\AppData\Roaming\Claude\claude_desktop_config.json.backup" "C:\Users\c559028\AppData\Roaming\Claude\claude_desktop_config.json"
```

Then restart Claude Desktop.

## 📊 Testing Without Burp Suite

You can test if the MCP server is loading even without Burp Suite running:

```
You: "List available Burp Suite tools"
Claude: *Should be able to describe the 12 available tools*
```

The health check and actual scans will fail without Burp Suite, but Claude should still have access to the tool definitions.

## 🔐 Security Notes

- Your Burp API key is stored in the Claude Desktop config
- The config file is in your user directory (not shared)
- Only Claude Desktop can access the MCP server
- The MCP server only accepts stdio communication (localhost only)

## 📚 Further Documentation

- **MCP Tools Reference:** `docs/MCP_TOOLS.md`
- **Setup Guide:** `docs/SETUP.md`
- **Main README:** `README.md`

## ✅ Verification Checklist

- [x] Claude Desktop config file updated
- [x] Backup created
- [x] Virtual environment Python configured
- [x] Burp API key set
- [x] MCP server imports verified
- [ ] Claude Desktop restarted (you need to do this)
- [ ] Burp Suite REST API enabled (you need to do this)
- [ ] Test connection with Claude (after restart)

---

**Your setup is complete!** Restart Claude Desktop and Burp Suite to start using AI-assisted security testing.
