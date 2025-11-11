"""
Base validator class for issue validation
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from burp_cli.api.models import Issue


class ValidationResult:
    """Result of vulnerability validation"""

    def __init__(
        self,
        is_valid: bool,
        confidence: float,
        evidence: Dict[str, Any],
        notes: Optional[str] = None
    ):
        self.is_valid = is_valid
        self.confidence = confidence  # 0.0 to 1.0
        self.evidence = evidence
        self.notes = notes

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "is_valid": self.is_valid,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "notes": self.notes
        }


class BaseValidator(ABC):
    """Base class for issue validators"""

    def __init__(self, burp_client: Any):
        """
        Initialize validator

        Args:
            burp_client: BurpClient instance for API calls
        """
        self.burp_client = burp_client

    @abstractmethod
    async def validate(self, issue: Issue) -> ValidationResult:
        """
        Validate if an issue is a true positive

        Args:
            issue: Issue to validate

        Returns:
            Validation result
        """
        pass

    @property
    @abstractmethod
    def supported_issue_types(self) -> list[str]:
        """List of issue types this validator supports"""
        pass

    def can_validate(self, issue: Issue) -> bool:
        """Check if this validator can handle the given issue"""
        return issue.issue_type in self.supported_issue_types
