"""Agent communication system with typed Pub/Sub messaging.

This module provides a sophisticated inter-agent communication framework
that enables real-time coordination, message passing, and state synchronization
between security testing agents.
"""

import asyncio
import json
import time
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Callable, Type, TypeVar, Generic
from dataclasses import dataclass, asdict, field
from abc import ABC, abstractmethod
from collections import defaultdict
import uuid

from ...utils.logging import get_logger

logger = get_logger(__name__)

T = TypeVar('T', bound='AgentMessage')


class MessageType(Enum):
    """Types of messages that can be sent between agents."""
    # System messages
    AGENT_STATUS = "agent_status"
    HEALTH_CHECK = "health_check"
    SHUTDOWN = "shutdown"
    
    # Discovery messages
    NEW_URL_DISCOVERED = "new_url_discovered"
    NEW_ENDPOINT_FOUND = "new_endpoint_found"
    SUBDOMAIN_DISCOVERED = "subdomain_discovered"
    TECHNOLOGY_IDENTIFIED = "technology_identified"
    
    # Vulnerability messages
    VULNERABILITY_FOUND = "vulnerability_found"
    POTENTIAL_VULNERABILITY = "potential_vulnerability"
    FALSE_POSITIVE = "false_positive"
    
    # Testing coordination
    TEST_ASSIGNMENT = "test_assignment"
    TEST_COMPLETED = "test_completed"
    TEST_FAILED = "test_failed"
    
    # Authentication messages
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    SESSION_EXPIRED = "session_expired"
    
    # Error and warning messages
    ERROR_OCCURRED = "error_occurred"
    WARNING_ISSUED = "warning_issued"
    SCOPE_VIOLATION = "scope_violation"


class MessagePriority(Enum):
    """Message priority levels for queue ordering."""
    LOW = 0
    NORMAL = 1
    HIGH = 2
    CRITICAL = 3


@dataclass
class AgentMessage:
    """Base class for all inter-agent messages."""
    
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: MessageType = MessageType.AGENT_STATUS
    sender_id: str = ""
    recipient_id: Optional[str] = None  # None for broadcast messages
    priority: MessagePriority = MessagePriority.NORMAL
    timestamp: float = field(default_factory=time.time)
    correlation_id: Optional[str] = None
    payload: Dict[str, Any] = field(default_factory=dict)
    ttl: Optional[float] = None  # Time to live in seconds
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert message to dictionary format."""
        return {
            "id": self.id,
            "type": self.type.value,
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
            "priority": self.priority.value,
            "timestamp": self.timestamp,
            "correlation_id": self.correlation_id,
            "payload": self.payload,
            "ttl": self.ttl
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AgentMessage':
        """Create message from dictionary format."""
        return cls(
            id=data["id"],
            type=MessageType(data["type"]),
            sender_id=data["sender_id"],
            recipient_id=data.get("recipient_id"),
            priority=MessagePriority(data["priority"]),
            timestamp=data["timestamp"],
            correlation_id=data.get("correlation_id"),
            payload=data.get("payload", {}),
            ttl=data.get("ttl")
        )
    
    def is_expired(self) -> bool:
        """Check if message has expired based on TTL."""
        if self.ttl is None:
            return False
        return time.time() > (self.timestamp + self.ttl)


# Specific message types for type safety

@dataclass
class VulnerabilityFoundMessage(AgentMessage):
    """Message sent when a vulnerability is discovered."""
    
    def __post_init__(self):
        self.type = MessageType.VULNERABILITY_FOUND
        self.priority = MessagePriority.HIGH


@dataclass
class NewURLDiscoveredMessage(AgentMessage):
    """Message sent when a new URL is discovered."""
    
    def __post_init__(self):
        self.type = MessageType.NEW_URL_DISCOVERED
        self.priority = MessagePriority.NORMAL


@dataclass
class SubdomainDiscoveredMessage(AgentMessage):
    """Message sent when a new subdomain is discovered."""
    
    def __post_init__(self):
        self.type = MessageType.SUBDOMAIN_DISCOVERED
        self.priority = MessagePriority.NORMAL


@dataclass
class HealthCheckMessage(AgentMessage):
    """Health check message for agent monitoring."""
    
    def __post_init__(self):
        self.type = MessageType.HEALTH_CHECK
        self.priority = MessagePriority.LOW
        self.ttl = 30.0  # Health checks expire after 30 seconds


class MessageHandler(ABC):
    """Abstract base class for message handlers."""
    
    @abstractmethod
    async def handle_message(self, message: AgentMessage) -> None:
        """Handle an incoming message.
        
        Args:
            message: The message to handle
        """
        pass
    
    @abstractmethod
    def can_handle(self, message_type: MessageType) -> bool:
        """Check if this handler can process the given message type.
        
        Args:
            message_type: Type of message to check
            
        Returns:
            True if this handler can process the message type
        """
        pass


class MessageBus:
    """Central message bus for inter-agent communication."""
    
    def __init__(self):
        self._subscribers: Dict[MessageType, List[Callable]] = defaultdict(list)
        self._message_queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self._handlers: List[MessageHandler] = []
        self._running = False
        self._processor_task: Optional[asyncio.Task] = None
        self._message_history: List[AgentMessage] = []
        self._max_history = 1000  # Keep last 1000 messages
        
        # Statistics
        self._stats = {
            "messages_sent": 0,
            "messages_processed": 0,
            "messages_dropped": 0,
            "subscriber_count": 0
        }
    
    async def start(self) -> None:
        """Start the message bus processor."""
        if self._running:
            return
        
        self._running = True
        self._processor_task = asyncio.create_task(self._process_messages())
        logger.info("Message bus started")
    
    async def stop(self) -> None:
        """Stop the message bus processor."""
        if not self._running:
            return
        
        self._running = False
        
        if self._processor_task:
            self._processor_task.cancel()
            try:
                await self._processor_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Message bus stopped")
    
    def subscribe(self, message_type: MessageType, callback: Callable[[AgentMessage], None]) -> None:
        """Subscribe to messages of a specific type.
        
        Args:
            message_type: Type of messages to subscribe to
            callback: Callback function to handle messages
        """
        self._subscribers[message_type].append(callback)
        self._stats["subscriber_count"] += 1
        logger.debug(f"New subscriber for {message_type.value}: {callback.__name__}")
    
    def unsubscribe(self, message_type: MessageType, callback: Callable[[AgentMessage], None]) -> None:
        """Unsubscribe from messages of a specific type.
        
        Args:
            message_type: Type of messages to unsubscribe from
            callback: Callback function to remove
        """
        if callback in self._subscribers[message_type]:
            self._subscribers[message_type].remove(callback)
            self._stats["subscriber_count"] -= 1
            logger.debug(f"Unsubscribed from {message_type.value}: {callback.__name__}")
    
    def add_handler(self, handler: MessageHandler) -> None:
        """Add a message handler.
        
        Args:
            handler: Message handler to add
        """
        self._handlers.append(handler)
        logger.debug(f"Added message handler: {handler.__class__.__name__}")
    
    def remove_handler(self, handler: MessageHandler) -> None:
        """Remove a message handler.
        
        Args:
            handler: Message handler to remove
        """
        if handler in self._handlers:
            self._handlers.remove(handler)
            logger.debug(f"Removed message handler: {handler.__class__.__name__}")
    
    async def publish(self, message: AgentMessage) -> None:
        """Publish a message to the bus.
        
        Args:
            message: Message to publish
        """
        # Check if message has expired
        if message.is_expired():
            logger.warning(f"Dropping expired message: {message.id}")
            self._stats["messages_dropped"] += 1
            return
        
        # Add to queue with priority
        priority_value = -message.priority.value  # Negative for max priority queue
        await self._message_queue.put((priority_value, message.timestamp, message))
        
        self._stats["messages_sent"] += 1
        logger.debug(f"Published message: {message.type.value} from {message.sender_id}")
    
    async def _process_messages(self) -> None:
        """Process messages from the queue."""
        logger.info("Message processor started")
        
        while self._running:
            try:
                # Wait for a message with timeout
                _, _, message = await asyncio.wait_for(
                    self._message_queue.get(),
                    timeout=1.0
                )
                
                # Check if message has expired
                if message.is_expired():
                    logger.warning(f"Dropping expired message in processing: {message.id}")
                    self._stats["messages_dropped"] += 1
                    continue
                
                # Process the message
                await self._handle_message(message)
                self._stats["messages_processed"] += 1
                
                # Add to history
                self._add_to_history(message)
                
            except asyncio.TimeoutError:
                # No message available, continue loop
                continue
            except Exception as e:
                logger.error(f"Error processing message: {e}", exc_info=True)
        
        logger.info("Message processor stopped")
    
    async def _handle_message(self, message: AgentMessage) -> None:
        """Handle a single message by notifying subscribers and handlers.
        
        Args:
            message: Message to handle
        """
        logger.debug(f"Handling message: {message.type.value} (ID: {message.id})")
        
        # Notify subscribers
        subscribers = self._subscribers.get(message.type, [])
        for callback in subscribers:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(message)
                else:
                    callback(message)
            except Exception as e:
                logger.error(
                    f"Error in subscriber callback {callback.__name__}: {e}",
                    exc_info=True
                )
        
        # Notify handlers
        for handler in self._handlers:
            try:
                if handler.can_handle(message.type):
                    await handler.handle_message(message)
            except Exception as e:
                logger.error(
                    f"Error in message handler {handler.__class__.__name__}: {e}",
                    exc_info=True
                )
    
    def _add_to_history(self, message: AgentMessage) -> None:
        """Add message to history, maintaining size limit.
        
        Args:
            message: Message to add to history
        """
        self._message_history.append(message)
        
        # Trim history if it exceeds max size
        if len(self._message_history) > self._max_history:
            self._message_history = self._message_history[-self._max_history:]
    
    def get_message_history(self, 
                          message_type: Optional[MessageType] = None,
                          sender_id: Optional[str] = None,
                          limit: int = 100) -> List[AgentMessage]:
        """Get message history with optional filtering.
        
        Args:
            message_type: Filter by message type
            sender_id: Filter by sender ID
            limit: Maximum number of messages to return
            
        Returns:
            List of messages matching criteria
        """
        messages = self._message_history
        
        # Apply filters
        if message_type:
            messages = [m for m in messages if m.type == message_type]
        
        if sender_id:
            messages = [m for m in messages if m.sender_id == sender_id]
        
        # Return most recent messages up to limit
        return messages[-limit:]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get message bus statistics.
        
        Returns:
            Dictionary containing statistics
        """
        return {
            **self._stats,
            "queue_size": self._message_queue.qsize(),
            "history_size": len(self._message_history),
            "active_subscribers": sum(len(subs) for subs in self._subscribers.values()),
            "handler_count": len(self._handlers)
        }
    
    async def broadcast(self, message: AgentMessage) -> None:
        """Broadcast a message to all subscribers.
        
        Args:
            message: Message to broadcast
        """
        message.recipient_id = None  # Ensure it's a broadcast
        await self.publish(message)
    
    async def send_to_agent(self, recipient_id: str, message: AgentMessage) -> None:
        """Send a message to a specific agent.
        
        Args:
            recipient_id: ID of the recipient agent
            message: Message to send
        """
        message.recipient_id = recipient_id
        await self.publish(message)


class AgentCommunicationMixin:
    """Mixin class to add communication capabilities to agents."""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._message_bus: Optional[MessageBus] = None
        self._agent_id: str = getattr(self, 'name', 'unknown_agent')
    
    def set_message_bus(self, message_bus: MessageBus) -> None:
        """Set the message bus for this agent.
        
        Args:
            message_bus: Message bus instance
        """
        self._message_bus = message_bus
    
    async def send_message(self, message: AgentMessage) -> None:
        """Send a message via the message bus.
        
        Args:
            message: Message to send
        """
        if not self._message_bus:
            logger.warning(f"Agent {self._agent_id} has no message bus configured")
            return
        
        message.sender_id = self._agent_id
        await self._message_bus.publish(message)
    
    async def broadcast_message(self, message: AgentMessage) -> None:
        """Broadcast a message to all agents.
        
        Args:
            message: Message to broadcast
        """
        if not self._message_bus:
            logger.warning(f"Agent {self._agent_id} has no message bus configured")
            return
        
        message.sender_id = self._agent_id
        await self._message_bus.broadcast(message)
    
    def subscribe_to_messages(self, message_type: MessageType, 
                            callback: Callable[[AgentMessage], None]) -> None:
        """Subscribe to messages of a specific type.
        
        Args:
            message_type: Type of messages to subscribe to
            callback: Callback function to handle messages
        """
        if not self._message_bus:
            logger.warning(f"Agent {self._agent_id} has no message bus configured")
            return
        
        self._message_bus.subscribe(message_type, callback)
    
    async def send_health_check(self, status: str = "healthy") -> None:
        """Send a health check message.
        
        Args:
            status: Health status to report
        """
        message = HealthCheckMessage(
            payload={"status": status, "timestamp": time.time()}
        )
        await self.send_message(message)
    
    async def report_vulnerability(self, vulnerability_data: Dict[str, Any]) -> None:
        """Report a discovered vulnerability.
        
        Args:
            vulnerability_data: Vulnerability details
        """
        message = VulnerabilityFoundMessage(
            payload=vulnerability_data,
            correlation_id=vulnerability_data.get('scan_id')
        )
        await self.broadcast_message(message)
    
    async def report_new_url(self, url: str, source: str = "unknown") -> None:
        """Report a newly discovered URL.
        
        Args:
            url: The discovered URL
            source: Source of the discovery
        """
        message = NewURLDiscoveredMessage(
            payload={"url": url, "source": source}
        )
        await self.broadcast_message(message)
    
    async def report_subdomain(self, subdomain: str, source: str = "unknown") -> None:
        """Report a newly discovered subdomain.
        
        Args:
            subdomain: The discovered subdomain
            source: Source of the discovery
        """
        message = SubdomainDiscoveredMessage(
            payload={"subdomain": subdomain, "source": source}
        )
        await self.broadcast_message(message)


# Global message bus instance
_global_message_bus: Optional[MessageBus] = None


def get_message_bus() -> MessageBus:
    """Get the global message bus instance.
    
    Returns:
        Global message bus instance
    """
    global _global_message_bus
    if _global_message_bus is None:
        _global_message_bus = MessageBus()
    return _global_message_bus


async def initialize_communication() -> MessageBus:
    """Initialize the global communication system.
    
    Returns:
        Initialized message bus
    """
    message_bus = get_message_bus()
    await message_bus.start()
    logger.info("Agent communication system initialized")
    return message_bus


async def shutdown_communication() -> None:
    """Shutdown the global communication system."""
    global _global_message_bus
    if _global_message_bus:
        await _global_message_bus.stop()
        _global_message_bus = None
    logger.info("Agent communication system shutdown")
