"""Base classes for security testing agents.

This module defines the foundational architecture for all security testing agents,
including common interfaces, result structures, and execution patterns.
"""

import asyncio
import time
from abc import ABC, abstractmethod
from enum import Enum
from typing import Dict, List, Optional, Any, AsyncGenerator, Union
from dataclasses import dataclass, field
from pathlib import Path

from ..core.config.settings import SecurityTestingConfig
from ..core.browser.playwright_manager import PlaywrightManager
from ..core.state.state_manager import StateManager
from ..utils.logging import get_logger

logger = get_logger(__name__)


class AgentStatus(Enum):
    """Agent execution status enumeration."""
    IDLE = "idle"
    INITIALIZING = "initializing"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class VulnerabilitySeverity(Enum):
    """Vulnerability severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Vulnerability:
    """Represents a discovered vulnerability."""
    
    id: str
    title: str
    description: str
    severity: VulnerabilitySeverity
    category: str
    url: str
    method: str = "GET"
    parameters: Dict[str, Any] = field(default_factory=dict)
    payload: Optional[str] = None
    evidence: List[str] = field(default_factory=list)
    reproduction_steps: List[str] = field(default_factory=list)
    remediation: Optional[str] = None
    references: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)
    confidence: float = 1.0  # 0.0 to 1.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert vulnerability to dictionary format."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category,
            "url": self.url,
            "method": self.method,
            "parameters": self.parameters,
            "payload": self.payload,
            "evidence": self.evidence,
            "reproduction_steps": self.reproduction_steps,
            "remediation": self.remediation,
            "references": self.references,
            "timestamp": self.timestamp,
            "confidence": self.confidence,
        }


@dataclass
class AgentResult:
    """Result of an agent's execution."""
    
    agent_name: str
    status: AgentStatus
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    evidence_files: List[Path] = field(default_factory=list)
    execution_time: float = 0.0
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_vulnerability(self, vulnerability: Vulnerability) -> None:
        """Add a vulnerability to the results."""
        self.vulnerabilities.append(vulnerability)
        logger.info(f"Vulnerability added: {vulnerability.title} ({vulnerability.severity.value})")
    
    def add_evidence_file(self, file_path: Path) -> None:
        """Add an evidence file to the results."""
        self.evidence_files.append(file_path)
        logger.debug(f"Evidence file added: {file_path}")
    
    def get_vulnerability_count_by_severity(self) -> Dict[str, int]:
        """Get count of vulnerabilities by severity."""
        counts = {severity.value: 0 for severity in VulnerabilitySeverity}
        for vuln in self.vulnerabilities:
            counts[vuln.severity.value] += 1
        return counts


class AgentBase(ABC):
    """Abstract base class for all security testing agents."""
    
    def __init__(self, 
                 name: str,
                 config: SecurityTestingConfig,
                 browser_manager: PlaywrightManager,
                 state_manager: StateManager):
        """Initialize the agent.
        
        Args:
            name: Agent name/identifier
            config: Security testing configuration
            browser_manager: Browser automation manager
            state_manager: Shared state manager
        """
        self.name = name
        self.config = config
        self.browser_manager = browser_manager
        self.state_manager = state_manager
        self.logger = get_logger(f"agent.{name}")
        
        # Agent state
        self._status = AgentStatus.IDLE
        self._result = AgentResult(agent_name=name, status=AgentStatus.IDLE)
        self._start_time: Optional[float] = None
        self._cancelled = False
        
        # Agent-specific configuration
        self._timeout = config.performance.timeout_settings.agent_task
        self._max_retries = 3
    
    @property
    def status(self) -> AgentStatus:
        """Get current agent status."""
        return self._status
    
    @property
    def result(self) -> AgentResult:
        """Get current agent result."""
        return self._result
    
    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the agent before execution."""
        pass
    
    @abstractmethod
    async def execute(self) -> AgentResult:
        """Execute the agent's main functionality."""
        pass
    
    @abstractmethod
    async def cleanup(self) -> None:
        """Clean up agent resources after execution."""
        pass
    
    async def run(self) -> AgentResult:
        """Run the complete agent lifecycle with error handling.
        
        Returns:
            Agent execution result
        """
        self.logger.info(f"Starting agent: {self.name}")
        self._start_time = time.time()
        self._status = AgentStatus.INITIALIZING
        
        try:
            # Initialize agent
            await self.initialize()
            
            # Check if cancelled during initialization
            if self._cancelled:
                self._status = AgentStatus.CANCELLED
                self._result.status = AgentStatus.CANCELLED
                return self._result
            
            # Execute with timeout
            self._status = AgentStatus.RUNNING
            result = await asyncio.wait_for(
                self.execute(),
                timeout=self._timeout
            )
            
            # Update result
            self._result = result
            self._result.execution_time = time.time() - self._start_time
            self._status = AgentStatus.COMPLETED
            self._result.status = AgentStatus.COMPLETED
            
            self.logger.info(
                f"Agent {self.name} completed successfully. "
                f"Found {len(result.vulnerabilities)} vulnerabilities in "
                f"{result.execution_time:.2f} seconds"
            )
            
        except asyncio.TimeoutError:
            self.logger.error(f"Agent {self.name} timed out after {self._timeout} seconds")
            self._status = AgentStatus.FAILED
            self._result.status = AgentStatus.FAILED
            self._result.error_message = "Agent execution timed out"
            
        except asyncio.CancelledError:
            self.logger.warning(f"Agent {self.name} was cancelled")
            self._status = AgentStatus.CANCELLED
            self._result.status = AgentStatus.CANCELLED
            
        except Exception as e:
            self.logger.error(f"Agent {self.name} failed with error: {e}", exc_info=True)
            self._status = AgentStatus.FAILED
            self._result.status = AgentStatus.FAILED
            self._result.error_message = str(e)
            
        finally:
            # Always try to clean up
            try:
                await self.cleanup()
            except Exception as e:
                self.logger.warning(f"Error during agent cleanup: {e}")
            
            # Update final execution time if not set
            if self._result.execution_time == 0.0 and self._start_time:
                self._result.execution_time = time.time() - self._start_time
        
        return self._result
    
    async def cancel(self) -> None:
        """Cancel agent execution."""
        self.logger.info(f"Cancelling agent: {self.name}")
        self._cancelled = True
        
        if self._status == AgentStatus.RUNNING:
            self._status = AgentStatus.CANCELLED
    
    def is_cancelled(self) -> bool:
        """Check if agent execution was cancelled."""
        return self._cancelled
    
    async def create_vulnerability(self,
                                 title: str,
                                 description: str,
                                 severity: VulnerabilitySeverity,
                                 category: str,
                                 url: str,
                                 **kwargs) -> Vulnerability:
        """Helper method to create a vulnerability finding.
        
        Args:
            title: Vulnerability title
            description: Detailed description
            severity: Severity level
            category: Vulnerability category
            url: URL where vulnerability was found
            **kwargs: Additional vulnerability fields
            
        Returns:
            Created Vulnerability instance
        """
        vuln_id = f"{self.name}_{int(time.time())}_{len(self._result.vulnerabilities)}"
        
        vulnerability = Vulnerability(
            id=vuln_id,
            title=title,
            description=description,
            severity=severity,
            category=category,
            url=url,
            **kwargs
        )
        
        self._result.add_vulnerability(vulnerability)
        
        # Store in state manager for cross-agent access
        await self.state_manager.add_vulnerability(vulnerability)
        
        return vulnerability
    
    async def capture_evidence(self, 
                             evidence_type: str,
                             content: Union[str, bytes],
                             filename: Optional[str] = None) -> Path:
        """Capture evidence for vulnerabilities.
        
        Args:
            evidence_type: Type of evidence (screenshot, request, response, etc.)
            content: Evidence content
            filename: Optional custom filename
            
        Returns:
            Path to saved evidence file
        """
        if not filename:
            timestamp = int(time.time())
            filename = f"{self.name}_{evidence_type}_{timestamp}"
        
        evidence_dir = Path(self.config.output.directory) / "evidence" / self.name
        evidence_dir.mkdir(parents=True, exist_ok=True)
        
        evidence_path = evidence_dir / filename
        
        if isinstance(content, str):
            with open(evidence_path, 'w', encoding='utf-8') as f:
                f.write(content)
        else:
            with open(evidence_path, 'wb') as f:
                f.write(content)
        
        self._result.add_evidence_file(evidence_path)
        
        self.logger.debug(f"Evidence captured: {evidence_path}")
        return evidence_path
    
    async def get_shared_state(self, key: str) -> Optional[Any]:
        """Get data from shared state.
        
        Args:
            key: State key
            
        Returns:
            Stored value or None
        """
        return await self.state_manager.get(key)
    
    async def set_shared_state(self, key: str, value: Any) -> None:
        """Set data in shared state.
        
        Args:
            key: State key
            value: Value to store
        """
        await self.state_manager.set(key, value)
    
    def __str__(self) -> str:
        """String representation of the agent."""
        return f"Agent({self.name}, status={self.status.value})"
    
    def __repr__(self) -> str:
        """Detailed string representation of the agent."""
        return (
            f"Agent(name='{self.name}', status={self.status.value}, "
            f"vulnerabilities={len(self._result.vulnerabilities)})"
        )
