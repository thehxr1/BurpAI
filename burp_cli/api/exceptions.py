"""
Custom exceptions for Burp API client
"""


class BurpAPIError(Exception):
    """Base exception for Burp API errors"""

    def __init__(self, message: str, status_code: int = None, response: dict = None):
        self.message = message
        self.status_code = status_code
        self.response = response
        super().__init__(self.message)


class BurpConnectionError(BurpAPIError):
    """Raised when connection to Burp API fails"""

    def __init__(self, message: str = "Failed to connect to Burp Suite API"):
        super().__init__(message)


class BurpAuthError(BurpAPIError):
    """Raised when authentication with Burp API fails"""

    def __init__(self, message: str = "Authentication failed. Check your API key"):
        super().__init__(message, status_code=401)


class BurpScanError(BurpAPIError):
    """Raised when scan operation fails"""
    pass


class BurpResourceNotFoundError(BurpAPIError):
    """Raised when requested resource is not found"""

    def __init__(self, resource: str, resource_id: str = None):
        message = f"Resource '{resource}' not found"
        if resource_id:
            message += f" (ID: {resource_id})"
        super().__init__(message, status_code=404)


class BurpInvalidRequestError(BurpAPIError):
    """Raised when request is invalid"""

    def __init__(self, message: str = "Invalid request"):
        super().__init__(message, status_code=400)
