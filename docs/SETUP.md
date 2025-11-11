# Burp CLI Setup Guide

## Prerequisites

### 1. Burp Suite Professional

- Install Burp Suite Professional (v2.0+)
- Enable REST API:
  - Go to Settings → Suite → REST API
  - Check "Service running"
  - Set service URL (default: `http://127.0.0.1:1337`)
  - Generate API key
  - Note: The API key will be displayed only once, save it securely

### 2. Python Environment

- Python 3.10 or higher
- pip (Python package manager)

## Installation Steps

### Step 1: Navigate to Project Directory

```bash
cd ~/MyWork/burp-cli
```

### Step 2: Create Virtual Environment

**Windows:**
```cmd
python -m venv venv
venv\Scripts\activate
```

**macOS/Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies

```bash
pip install --upgrade pip
pip install -e ".[dev]"
```

### Step 4: Configure Environment

1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` and add your Burp API key:
   ```bash
   BURP_API_URL=http://127.0.0.1:1337
   BURP_API_KEY=your_actual_api_key_here
   ```

### Step 5: Verify Installation

Test the CLI:
```bash
burp-cli health
```

Expected output:
```
✓ Connected to Burp Suite Professional v2025.x
```

## Claude Desktop Integration (MCP)

### Step 1: Locate Claude Desktop Config

**Windows:**
```
%APPDATA%\Claude\claude_desktop_config.json
```

**macOS:**
```
~/Library/Application Support/Claude/claude_desktop_config.json
```

### Step 2: Add MCP Server Configuration

Edit the config file and add:

```json
{
  "mcpServers": {
    "burp-suite": {
      "command": "python",
      "args": [
        "C:\\Users\\c559028\\MyWork\\burp-cli\\burp_cli\\mcp_server\\server.py"
      ],
      "env": {
        "BURP_API_URL": "http://127.0.0.1:1337",
        "BURP_API_KEY": "your_burp_api_key_here"
      }
    }
  }
}
```

**Note:** Adjust the path based on your actual installation location.

### Step 3: Restart Claude Desktop

Close and reopen Claude Desktop to load the MCP server.

### Step 4: Test MCP Integration

In Claude Desktop, ask:
```
Can you check if Burp Suite is connected?
```

Claude should use the `burp_health_check` tool and report the connection status.

## Usage Examples

### CLI Usage

```bash
# Start a scan
burp-cli scan https://example.com --wait --issues

# Check scan status
burp-cli status <scan-id>

# Get issues from completed scan
burp-cli issues <scan-id> --severity high

# List all scans
burp-cli list

# View proxy history
burp-cli proxy --limit 50

# Stop a scan
burp-cli stop <scan-id>
```

### Claude Desktop Usage

```
You: "Scan example.com for vulnerabilities"
Claude: *Uses burp_start_scan tool*

You: "Show me the high severity issues"
Claude: *Uses burp_get_scan_issues with severity filter*

You: "Validate the SQL injection finding at /login"
Claude: *Uses burp_validate_sqli tool*
```

## Troubleshooting

### Cannot Connect to Burp API

1. Verify Burp Suite Professional is running
2. Check REST API is enabled in Burp settings
3. Verify API URL and port (default: 127.0.0.1:1337)
4. Ensure API key is correct in `.env` file

### MCP Server Not Loading

1. Check Python path in `claude_desktop_config.json`
2. Verify virtual environment has all dependencies
3. Check Claude Desktop logs:
   - Windows: `%APPDATA%\Claude\logs`
   - macOS: `~/Library/Logs/Claude`

### Import Errors

```bash
# Reinstall dependencies
pip install -e ".[dev]" --force-reinstall
```

### Permission Issues (Windows)

Run terminal as Administrator when installing packages.

## Development Setup

### Install Development Tools

```bash
pip install -e ".[dev]"
```

### Run Tests

```bash
pytest
```

### Format Code

```bash
black burp_cli/
```

### Lint Code

```bash
ruff check burp_cli/
```

## Next Steps

1. Configure your first scan target
2. Set up scope rules in Burp Suite
3. Try AI-assisted validation via Claude Desktop
4. Explore automated workflows

For more information, see the [README.md](../README.md).
