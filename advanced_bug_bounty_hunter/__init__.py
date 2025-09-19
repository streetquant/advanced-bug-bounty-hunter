"""Advanced Bug Bounty Hunter - AI-Powered Security Testing Tool

A sophisticated, AI-powered bug bounty hunting tool that emulates human security
researcher behavior using multi-agent frameworks, LLM intelligence, and advanced
vulnerability detection capabilities.
"""

__version__ = "0.1.0"
__author__ = "Shayan Banerjee"
__email__ = "your.email@example.com"
__description__ = "AI-powered bug bounty hunting tool that emulates human security researcher behavior"

from .core.config import ConfigManager
from .agents.orchestrator import SecurityTestingOrchestrator

__all__ = [
    "ConfigManager",
    "SecurityTestingOrchestrator",
]
