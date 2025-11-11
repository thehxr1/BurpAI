"""
Configuration management using Pydantic Settings
"""

from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables"""

    # Burp Suite Configuration
    burp_api_url: str = Field(
        default="http://127.0.0.1:1337",
        description="Burp Suite REST API URL"
    )
    burp_api_key: str = Field(
        default="",
        description="Burp Suite API Key"
    )

    # Claude AI Configuration
    anthropic_api_key: Optional[str] = Field(
        default=None,
        description="Anthropic API Key for AI validation"
    )

    # Database
    database_url: str = Field(
        default="sqlite:///burp_cli.db",
        description="Database connection URL"
    )

    # Logging
    log_level: str = Field(
        default="INFO",
        description="Logging level"
    )
    log_file: str = Field(
        default="burp_cli.log",
        description="Log file path"
    )

    # Validation Settings
    enable_ai_validation: bool = Field(
        default=True,
        description="Enable AI-powered validation"
    )
    enable_sqlmap_validation: bool = Field(
        default=False,
        description="Enable SQLMap validation for SQLi findings"
    )
    sqlmap_path: str = Field(
        default="sqlmap",
        description="Path to SQLMap executable"
    )

    # Reporting
    default_report_format: str = Field(
        default="html",
        description="Default report format"
    )
    report_output_dir: Path = Field(
        default=Path("./reports"),
        description="Directory for report output"
    )

    # MCP Server
    mcp_server_host: str = Field(
        default="localhost",
        description="MCP server host"
    )
    mcp_server_port: int = Field(
        default=8080,
        description="MCP server port"
    )

    # Timeouts
    request_timeout: int = Field(
        default=30,
        description="HTTP request timeout in seconds"
    )
    scan_poll_interval: int = Field(
        default=5,
        description="Scan status polling interval in seconds"
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate log level"""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        v = v.upper()
        if v not in valid_levels:
            raise ValueError(f"Invalid log level. Must be one of {valid_levels}")
        return v

    @field_validator("default_report_format")
    @classmethod
    def validate_report_format(cls, v: str) -> str:
        """Validate report format"""
        valid_formats = ["html", "json", "xml", "markdown"]
        v = v.lower()
        if v not in valid_formats:
            raise ValueError(f"Invalid report format. Must be one of {valid_formats}")
        return v

    def model_post_init(self, __context: object) -> None:
        """Post-initialization hook to create directories"""
        self.report_output_dir.mkdir(parents=True, exist_ok=True)


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    return Settings()
