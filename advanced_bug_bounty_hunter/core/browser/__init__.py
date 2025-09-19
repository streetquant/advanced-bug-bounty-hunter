"""Browser automation module for Advanced Bug Bounty Hunter.

This module provides browser automation capabilities using Playwright,
including request/response interception, HAR file generation, and
sophisticated browser interaction patterns.
"""

from .playwright_manager import PlaywrightManager
from .request_interceptor import RequestInterceptor
from .browser_context import BrowserContextManager

__all__ = [
    "PlaywrightManager",
    "RequestInterceptor", 
    "BrowserContextManager",
]
