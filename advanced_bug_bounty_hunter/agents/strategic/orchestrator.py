"""Strategic orchestrator for coordinating multi-agent security testing.

This module provides the main orchestration logic that coordinates all security
testing agents, manages task distribution, monitors agent health, and adapts
testing strategies based on discovered intelligence.
"""

import asyncio
import time
from typing import Dict, List, Optional, Any, Type, Set
from enum import Enum
from dataclasses import dataclass, field
from collections import defaultdict

from ..base import AgentBase, AgentResult, AgentStatus, Vulnerability, VulnerabilitySeverity
from ..base.communication import (
    MessageBus, AgentMessage, MessageType, MessageHandler,
    AgentCommunicationMixin, HealthCheckMessage, VulnerabilityFoundMessage
)
from ...core.config.settings import SecurityTestingConfig
from ...core.browser.playwright_manager import PlaywrightManager
from ...core.state.state_manager import StateManager
from ...utils.logging import get_logger

logger = get_logger(__name__)


class TaskStatus(Enum):
    """Status of assigned tasks."""
    PENDING = "pending"
    ASSIGNED = "assigned"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AgentType(Enum):
    """Types of agents for task assignment."""
    RECONNAISSANCE = "reconnaissance"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    INJECTION = "injection"
    XSS = "xss"
    BUSINESS_LOGIC = "business_logic"
    CLIENT_SIDE = "client_side"
    INFRASTRUCTURE = "infrastructure"
    API_SECURITY = "api_security"


@dataclass
class Task:
    """Represents a task to be executed by an agent."""
    
    id: str
    type: AgentType
    description: str
    priority: int = 1  # 1 = low, 5 = critical
    assigned_agent: Optional[str] = None
    status: TaskStatus = TaskStatus.PENDING
    created_at: float = field(default_factory=time.time)
    assigned_at: Optional[float] = None
    completed_at: Optional[float] = None
    payload: Dict[str, Any] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)  # Task IDs that must complete first
    max_retries: int = 3
    retry_count: int = 0
    error_message: Optional[str] = None
    
    def can_execute(self, completed_tasks: Set[str]) -> bool:
        """Check if task dependencies are satisfied.
        
        Args:
            completed_tasks: Set of completed task IDs
            
        Returns:
            True if all dependencies are satisfied
        """
        return all(dep_id in completed_tasks for dep_id in self.dependencies)
    
    def should_retry(self) -> bool:
        """Check if task should be retried after failure.
        
        Returns:
            True if task can be retried
        """
        return self.retry_count < self.max_retries and self.status == TaskStatus.FAILED


@dataclass 
class AgentInfo:
    """Information about a registered agent."""
    
    id: str
    type: AgentType
    status: AgentStatus
    current_task: Optional[str] = None
    last_health_check: Optional[float] = None
    capabilities: List[str] = field(default_factory=list)
    performance_score: float = 1.0  # 0.0 to 1.0
    total_tasks: int = 0
    successful_tasks: int = 0
    failed_tasks: int = 0
    average_task_time: float = 0.0
    
    @property
    def success_rate(self) -> float:
        """Calculate agent success rate."""
        if self.total_tasks == 0:
            return 1.0
        return self.successful_tasks / self.total_tasks
    
    @property
    def is_healthy(self) -> bool:
        """Check if agent is healthy based on last health check."""
        if self.last_health_check is None:
            return False
        return time.time() - self.last_health_check < 60.0  # 60 second timeout
    
    @property
    def is_available(self) -> bool:
        """Check if agent is available for new tasks."""
        return (self.status == AgentStatus.IDLE and 
                self.current_task is None and 
                self.is_healthy)


class OrchestrationMessageHandler(MessageHandler):
    """Handles messages for the orchestration system."""
    
    def __init__(self, orchestrator: 'StrategicOrchestrator'):
        self.orchestrator = orchestrator
    
    async def handle_message(self, message: AgentMessage) -> None:
        """Handle incoming messages.
        
        Args:
            message: Message to handle
        """
        if message.type == MessageType.HEALTH_CHECK:
            await self._handle_health_check(message)
        elif message.type == MessageType.TEST_COMPLETED:
            await self._handle_test_completed(message)
        elif message.type == MessageType.TEST_FAILED:
            await self._handle_test_failed(message)
        elif message.type == MessageType.VULNERABILITY_FOUND:
            await self._handle_vulnerability_found(message)
        elif message.type == MessageType.ERROR_OCCURRED:
            await self._handle_error(message)
    
    def can_handle(self, message_type: MessageType) -> bool:
        """Check if this handler can process the message type."""
        return message_type in {
            MessageType.HEALTH_CHECK,
            MessageType.TEST_COMPLETED,
            MessageType.TEST_FAILED,
            MessageType.VULNERABILITY_FOUND,
            MessageType.ERROR_OCCURRED
        }
    
    async def _handle_health_check(self, message: AgentMessage) -> None:
        """Handle health check messages from agents."""
        agent_id = message.sender_id
        if agent_id in self.orchestrator._registered_agents:
            self.orchestrator._registered_agents[agent_id].last_health_check = time.time()
            logger.debug(f"Health check received from {agent_id}")
    
    async def _handle_test_completed(self, message: AgentMessage) -> None:
        """Handle test completion messages."""
        agent_id = message.sender_id
        task_id = message.payload.get('task_id')
        
        if task_id in self.orchestrator._tasks:
            task = self.orchestrator._tasks[task_id]
            task.status = TaskStatus.COMPLETED
            task.completed_at = time.time()
            
            # Update agent info
            if agent_id in self.orchestrator._registered_agents:
                agent = self.orchestrator._registered_agents[agent_id]
                agent.current_task = None
                agent.status = AgentStatus.IDLE
                agent.successful_tasks += 1
                
                # Update performance metrics
                if task.assigned_at:
                    task_time = task.completed_at - task.assigned_at
                    total_time = agent.average_task_time * (agent.total_tasks - 1) + task_time
                    agent.average_task_time = total_time / agent.total_tasks
            
            logger.info(f"Task {task_id} completed by {agent_id}")
    
    async def _handle_test_failed(self, message: AgentMessage) -> None:
        """Handle test failure messages."""
        agent_id = message.sender_id
        task_id = message.payload.get('task_id')
        error_message = message.payload.get('error', 'Unknown error')
        
        if task_id in self.orchestrator._tasks:
            task = self.orchestrator._tasks[task_id]
            task.status = TaskStatus.FAILED
            task.error_message = error_message
            task.retry_count += 1
            
            # Update agent info
            if agent_id in self.orchestrator._registered_agents:
                agent = self.orchestrator._registered_agents[agent_id]
                agent.current_task = None
                agent.status = AgentStatus.IDLE
                agent.failed_tasks += 1
            
            logger.warning(f"Task {task_id} failed on {agent_id}: {error_message}")
            
            # Schedule retry if possible
            if task.should_retry():
                task.status = TaskStatus.PENDING
                task.assigned_agent = None
                logger.info(f"Scheduling retry {task.retry_count}/{task.max_retries} for task {task_id}")
    
    async def _handle_vulnerability_found(self, message: VulnerabilityFoundMessage) -> None:
        """Handle vulnerability discovery messages."""
        vuln_data = message.payload
        logger.info(f"Vulnerability reported by {message.sender_id}: {vuln_data.get('title', 'Unknown')}")
        
        # Update orchestration strategy based on vulnerability severity
        severity = vuln_data.get('severity', 'low')
        if severity in ['critical', 'high']:
            await self.orchestrator._prioritize_related_tasks(vuln_data)
    
    async def _handle_error(self, message: AgentMessage) -> None:
        """Handle error messages from agents."""
        agent_id = message.sender_id
        error_message = message.payload.get('error', 'Unknown error')
        
        logger.error(f"Error reported by {agent_id}: {error_message}")
        
        # Update agent status if severe error
        if agent_id in self.orchestrator._registered_agents:
            agent = self.orchestrator._registered_agents[agent_id]
            if message.payload.get('severity') == 'critical':
                agent.status = AgentStatus.FAILED


class StrategicOrchestrator(AgentBase, AgentCommunicationMixin):
    """Strategic orchestrator for coordinating multi-agent security testing."""
    
    def __init__(self,
                 config: SecurityTestingConfig,
                 browser_manager: PlaywrightManager,
                 state_manager: StateManager,
                 message_bus: MessageBus):
        """Initialize the strategic orchestrator.
        
        Args:
            config: Security testing configuration
            browser_manager: Browser manager instance
            state_manager: State manager instance
            message_bus: Message bus for communication
        """
        super().__init__(
            name="strategic_orchestrator",
            config=config,
            browser_manager=browser_manager,
            state_manager=state_manager
        )
        
        # Set up communication
        self.set_message_bus(message_bus)
        
        # Task management
        self._tasks: Dict[str, Task] = {}
        self._task_queue: List[str] = []  # Priority queue of pending task IDs
        self._completed_tasks: Set[str] = set()
        
        # Agent management
        self._registered_agents: Dict[str, AgentInfo] = {}
        self._agent_instances: Dict[str, AgentBase] = {}
        
        # Orchestration state
        self._orchestration_strategy = config.testing_strategy.methodology
        self._max_concurrent_tasks = config.performance.concurrent_agents
        self._active_tasks = 0
        
        # Message handler
        self._message_handler = OrchestrationMessageHandler(self)
        
        # Statistics
        self._stats = {
            "tasks_created": 0,
            "tasks_completed": 0,
            "tasks_failed": 0,
            "vulnerabilities_found": 0,
            "agents_registered": 0
        }
    
    async def initialize(self) -> None:
        """Initialize the orchestrator."""
        logger.info("Initializing Strategic Orchestrator")
        
        # Add message handler to bus
        if self._message_bus:
            self._message_bus.add_handler(self._message_handler)
        
        # Subscribe to relevant messages
        self.subscribe_to_messages(MessageType.HEALTH_CHECK, self._handle_health_check)
        self.subscribe_to_messages(MessageType.VULNERABILITY_FOUND, self._handle_vulnerability_found)
        
        # Create initial task plan
        await self._create_initial_task_plan()
        
        logger.info("Strategic Orchestrator initialized")
    
    async def execute(self) -> AgentResult:
        """Execute the orchestration logic.
        
        Returns:
            Orchestration result
        """
        logger.info("Starting orchestrated security testing")
        
        # Start the main orchestration loop
        await self._orchestration_loop()
        
        # Generate final result
        result = AgentResult(
            agent_name=self.name,
            status=AgentStatus.COMPLETED
        )
        
        # Collect all vulnerabilities from state
        vulnerabilities = await self.state_manager.get_vulnerabilities()
        result.vulnerabilities.extend(vulnerabilities)
        
        # Add statistics to metadata
        result.metadata.update(self._stats)
        result.metadata["total_tasks"] = len(self._tasks)
        result.metadata["active_agents"] = len([a for a in self._registered_agents.values() if a.is_healthy])
        
        logger.info(f"Orchestration completed. Found {len(vulnerabilities)} vulnerabilities.")
        return result
    
    async def cleanup(self) -> None:
        """Clean up orchestrator resources."""
        logger.info("Cleaning up Strategic Orchestrator")
        
        # Cancel any pending tasks
        for task in self._tasks.values():
            if task.status in [TaskStatus.PENDING, TaskStatus.ASSIGNED, TaskStatus.IN_PROGRESS]:
                task.status = TaskStatus.CANCELLED
        
        # Clean up agent instances
        for agent in self._agent_instances.values():
            try:
                await agent.cleanup()
            except Exception as e:
                logger.warning(f"Error cleaning up agent {agent.name}: {e}")
        
        # Remove message handler
        if self._message_bus and self._message_handler:
            self._message_bus.remove_handler(self._message_handler)
        
        logger.info("Strategic Orchestrator cleanup completed")
    
    def register_agent(self, agent: AgentBase, agent_type: AgentType, 
                      capabilities: Optional[List[str]] = None) -> None:
        """Register an agent with the orchestrator.
        
        Args:
            agent: Agent instance to register
            agent_type: Type of the agent
            capabilities: List of agent capabilities
        """
        agent_info = AgentInfo(
            id=agent.name,
            type=agent_type,
            status=AgentStatus.IDLE,
            capabilities=capabilities or []
        )
        
        self._registered_agents[agent.name] = agent_info
        self._agent_instances[agent.name] = agent
        self._stats["agents_registered"] += 1
        
        # Set up communication for the agent
        if hasattr(agent, 'set_message_bus') and self._message_bus:
            agent.set_message_bus(self._message_bus)
        
        logger.info(f"Registered agent: {agent.name} ({agent_type.value})")
    
    def create_task(self, task_type: AgentType, description: str, 
                   priority: int = 1, payload: Optional[Dict[str, Any]] = None,
                   dependencies: Optional[List[str]] = None) -> str:
        """Create a new task.
        
        Args:
            task_type: Type of agent needed for this task
            description: Task description
            priority: Task priority (1-5)
            payload: Task payload data
            dependencies: List of task IDs that must complete first
            
        Returns:
            Task ID
        """
        task_id = f"{task_type.value}_{int(time.time())}_{len(self._tasks)}"
        
        task = Task(
            id=task_id,
            type=task_type,
            description=description,
            priority=priority,
            payload=payload or {},
            dependencies=dependencies or []
        )
        
        self._tasks[task_id] = task
        self._task_queue.append(task_id)
        self._stats["tasks_created"] += 1
        
        # Sort task queue by priority
        self._task_queue.sort(key=lambda tid: -self._tasks[tid].priority)
        
        logger.info(f"Created task: {task_id} ({description})")
        return task_id
    
    async def _create_initial_task_plan(self) -> None:
        """Create the initial task plan based on configuration."""
        logger.info("Creating initial task plan")
        
        enabled_agents = self.config.testing_strategy.agents
        target_url = str(self.config.target.primary_url)
        
        # Create reconnaissance tasks first (highest priority)
        if enabled_agents.reconnaissance:
            self.create_task(
                AgentType.RECONNAISSANCE,
                f"Passive reconnaissance of {target_url}",
                priority=5,
                payload={"target_url": target_url, "mode": "passive"}
            )
            
            recon_task_id = self.create_task(
                AgentType.RECONNAISSANCE,
                f"Active reconnaissance of {target_url}",
                priority=4,
                payload={"target_url": target_url, "mode": "active"}
            )
        
        # Create dependent tasks
        dependencies = [recon_task_id] if enabled_agents.reconnaissance else []
        
        if enabled_agents.authentication:
            self.create_task(
                AgentType.AUTHENTICATION,
                f"Authentication testing for {target_url}",
                priority=3,
                payload={"target_url": target_url},
                dependencies=dependencies
            )
        
        if enabled_agents.injection:
            self.create_task(
                AgentType.INJECTION,
                f"Injection vulnerability testing",
                priority=3,
                payload={"target_url": target_url},
                dependencies=dependencies
            )
        
        logger.info(f"Created {len(self._tasks)} initial tasks")
    
    async def _orchestration_loop(self) -> None:
        """Main orchestration loop."""
        logger.info("Starting orchestration loop")
        
        while self._task_queue or self._active_tasks > 0:
            # Assign pending tasks to available agents
            await self._assign_pending_tasks()
            
            # Check agent health
            await self._check_agent_health()
            
            # Clean up completed tasks
            self._cleanup_completed_tasks()
            
            # Wait before next iteration
            await asyncio.sleep(1.0)
        
        logger.info("Orchestration loop completed")
    
    async def _assign_pending_tasks(self) -> None:
        """Assign pending tasks to available agents."""
        if not self._task_queue or self._active_tasks >= self._max_concurrent_tasks:
            return
        
        # Find tasks that can be executed (dependencies satisfied)
        executable_tasks = []
        for task_id in self._task_queue:
            task = self._tasks[task_id]
            if task.can_execute(self._completed_tasks):
                executable_tasks.append(task_id)
        
        # Assign tasks to available agents
        for task_id in executable_tasks:
            if self._active_tasks >= self._max_concurrent_tasks:
                break
            
            task = self._tasks[task_id]
            agent = self._find_available_agent(task.type)
            
            if agent:
                await self._assign_task_to_agent(task, agent)
                self._task_queue.remove(task_id)
                self._active_tasks += 1
    
    def _find_available_agent(self, agent_type: AgentType) -> Optional[AgentInfo]:
        """Find an available agent of the specified type.
        
        Args:
            agent_type: Type of agent needed
            
        Returns:
            Available agent info or None
        """
        candidates = [
            agent for agent in self._registered_agents.values()
            if agent.type == agent_type and agent.is_available
        ]
        
        if not candidates:
            return None
        
        # Select agent with best performance score
        return max(candidates, key=lambda a: a.performance_score)
    
    async def _assign_task_to_agent(self, task: Task, agent: AgentInfo) -> None:
        """Assign a task to an agent.
        
        Args:
            task: Task to assign
            agent: Agent to assign task to
        """
        task.assigned_agent = agent.id
        task.status = TaskStatus.ASSIGNED
        task.assigned_at = time.time()
        
        agent.current_task = task.id
        agent.status = AgentStatus.RUNNING
        agent.total_tasks += 1
        
        # Send task assignment message
        message = AgentMessage(
            type=MessageType.TEST_ASSIGNMENT,
            recipient_id=agent.id,
            payload={
                "task_id": task.id,
                "description": task.description,
                "payload": task.payload
            }
        )
        
        await self.send_message(message)
        logger.info(f"Assigned task {task.id} to agent {agent.id}")
    
    async def _check_agent_health(self) -> None:
        """Check health of all registered agents."""
        unhealthy_agents = [
            agent for agent in self._registered_agents.values()
            if not agent.is_healthy and agent.status != AgentStatus.FAILED
        ]
        
        for agent in unhealthy_agents:
            logger.warning(f"Agent {agent.id} appears unhealthy")
            
            # Mark current task as failed if agent was working on one
            if agent.current_task:
                task = self._tasks[agent.current_task]
                task.status = TaskStatus.FAILED
                task.error_message = "Agent became unhealthy"
                agent.current_task = None
                self._active_tasks -= 1
            
            agent.status = AgentStatus.FAILED
    
    def _cleanup_completed_tasks(self) -> None:
        """Clean up completed tasks and update statistics."""
        for task in self._tasks.values():
            if task.status == TaskStatus.COMPLETED and task.id not in self._completed_tasks:
                self._completed_tasks.add(task.id)
                self._stats["tasks_completed"] += 1
                self._active_tasks -= 1
            
            elif task.status == TaskStatus.FAILED and task.id not in self._completed_tasks:
                if not task.should_retry():
                    self._stats["tasks_failed"] += 1
                    self._active_tasks -= 1
    
    async def _prioritize_related_tasks(self, vuln_data: Dict[str, Any]) -> None:
        """Prioritize tasks related to a discovered vulnerability.
        
        Args:
            vuln_data: Vulnerability data
        """
        vuln_category = vuln_data.get('category', '')
        
        # Increase priority for related pending tasks
        for task in self._tasks.values():
            if (task.status == TaskStatus.PENDING and 
                self._is_related_task(task, vuln_category)):
                task.priority = min(task.priority + 1, 5)
        
        # Re-sort task queue
        self._task_queue.sort(key=lambda tid: -self._tasks[tid].priority)
    
    def _is_related_task(self, task: Task, vuln_category: str) -> bool:
        """Check if a task is related to a vulnerability category.
        
        Args:
            task: Task to check
            vuln_category: Vulnerability category
            
        Returns:
            True if task is related to the vulnerability
        """
        # Simple relationship mapping
        relationships = {
            "injection": [AgentType.INJECTION],
            "xss": [AgentType.XSS, AgentType.CLIENT_SIDE],
            "authentication": [AgentType.AUTHENTICATION, AgentType.AUTHORIZATION],
            "business_logic": [AgentType.BUSINESS_LOGIC],
        }
        
        return task.type in relationships.get(vuln_category, [])
    
    async def _handle_health_check(self, message: AgentMessage) -> None:
        """Handle health check messages."""
        # This is handled by the message handler
        pass
    
    async def _handle_vulnerability_found(self, message: VulnerabilityFoundMessage) -> None:
        """Handle vulnerability found messages."""
        self._stats["vulnerabilities_found"] += 1
        await self._prioritize_related_tasks(message.payload)
    
    def get_orchestration_status(self) -> Dict[str, Any]:
        """Get current orchestration status.
        
        Returns:
            Status information dictionary
        """
        return {
            "total_tasks": len(self._tasks),
            "pending_tasks": len([t for t in self._tasks.values() if t.status == TaskStatus.PENDING]),
            "active_tasks": self._active_tasks,
            "completed_tasks": len(self._completed_tasks),
            "failed_tasks": self._stats["tasks_failed"],
            "registered_agents": len(self._registered_agents),
            "healthy_agents": len([a for a in self._registered_agents.values() if a.is_healthy]),
            "vulnerabilities_found": self._stats["vulnerabilities_found"],
            "statistics": self._stats
        }
