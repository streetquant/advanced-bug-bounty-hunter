"""Multi-agent security testing framework.

This module contains the agent-based architecture for automated security testing,
including specialized agents for different types of vulnerabilities and testing scenarios.
"""

from .base import AgentBase, AgentResult, AgentStatus
from .orchestrator import SecurityTestingOrchestrator

__all__ = [
    "AgentBase",
    "AgentResult", 
    "AgentStatus",
    "SecurityTestingOrchestrator",
]
