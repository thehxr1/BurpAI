@echo off
REM Burp Suite MCP Server Launcher
REM This script ensures the virtual environment is used

cd /d "%~dp0"
"%~dp0venv\Scripts\python.exe" "%~dp0burp_cli\mcp_server\server.py"
