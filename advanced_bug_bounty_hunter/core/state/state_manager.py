"""State management for cross-agent communication and data sharing.

This module provides a centralized state management system that allows
different agents to share data, coordinate activities, and maintain
overall testing session state.
"""

import asyncio
import json
import time
from typing import Any, Dict, List, Optional, Set
from dataclasses import asdict
from collections import defaultdict

from ..config.settings import SecurityTestingConfig
from ..utils.logging import get_logger
from ...agents.base import Vulnerability

logger = get_logger(__name__)


class StateManager:
    """Manages shared state across all security testing agents."""
    
    def __init__(self, config: SecurityTestingConfig):
        """Initialize the state manager.
        
        Args:
            config: Security testing configuration
        """
        self.config = config
        self._state: Dict[str, Any] = {}
        self._vulnerabilities: List[Vulnerability] = []
        self._discovered_urls: Set[str] = set()
        self._tested_endpoints: Dict[str, Dict[str, Any]] = {}
        self._agent_status: Dict[str, str] = {}
        self._scan_metadata: Dict[str, Any] = {
            "start_time": time.time(),
            "target_url": str(config.target.primary_url),
            "scan_id": f"scan_{int(time.time())}",
        }
        
        # Thread safety
        self._lock = asyncio.Lock()
    
    async def initialize(self) -> None:
        """Initialize the state manager."""
        logger.info("Initializing state manager")
        
        async with self._lock:
            # Initialize basic state structure
            self._state.update({
                "reconnaissance": {
                    "discovered_domains": set(),
                    "discovered_subdomains": set(),
                    "technology_stack": {},
                    "endpoints": set(),
                },
                "authentication": {
                    "valid_credentials": [],
                    "session_tokens": {},
                    "auth_endpoints": [],
                },
                "injection": {
                    "vulnerable_parameters": [],
                    "tested_payloads": {},
                    "successful_injections": [],
                },
                "xss": {
                    "vulnerable_endpoints": [],
                    "reflected_parameters": [],
                    "stored_xss_locations": [],
                },
            })
        
        logger.info("State manager initialized")
    
    async def get(self, key: str) -> Optional[Any]:
        """Get a value from the shared state.
        
        Args:
            key: State key (supports dot notation for nested access)
            
        Returns:
            Value associated with the key, or None if not found
        """
        async with self._lock:
            keys = key.split('.')
            current = self._state
            
            try:
                for k in keys:
                    current = current[k]
                return current
            except (KeyError, TypeError):
                return None
    
    async def set(self, key: str, value: Any) -> None:
        """Set a value in the shared state.
        
        Args:
            key: State key (supports dot notation for nested setting)
            value: Value to store
        """
        async with self._lock:
            keys = key.split('.')
            current = self._state
            
            # Navigate to the parent of the target key
            for k in keys[:-1]:
                if k not in current:
                    current[k] = {}
                current = current[k]
            
            # Set the final value
            current[keys[-1]] = value
            
        logger.debug(f"State updated: {key} = {value}")
    
    async def append(self, key: str, value: Any) -> None:
        """Append a value to a list in shared state.
        
        Args:
            key: State key
            value: Value to append
        """
        async with self._lock:
            current = await self.get(key)
            if current is None:
                current = []
            elif not isinstance(current, list):
                raise ValueError(f"Cannot append to non-list value at key: {key}")
            
            current.append(value)
            await self.set(key, current)
    
    async def add_to_set(self, key: str, value: Any) -> None:
        """Add a value to a set in shared state.
        
        Args:
            key: State key
            value: Value to add to set
        """
        async with self._lock:
            current = await self.get(key)
            if current is None:
                current = set()
            elif not isinstance(current, set):
                raise ValueError(f"Cannot add to non-set value at key: {key}")
            
            current.add(value)
            await self.set(key, current)
    
    async def add_vulnerability(self, vulnerability: Vulnerability) -> None:
        """Add a vulnerability to the shared state.
        
        Args:
            vulnerability: Vulnerability instance to add
        """
        async with self._lock:
            self._vulnerabilities.append(vulnerability)
            
        logger.info(
            f"Vulnerability added to state: {vulnerability.title} "
            f"({vulnerability.severity.value})"
        )
    
    async def get_vulnerabilities(self, 
                                severity_filter: Optional[str] = None,
                                category_filter: Optional[str] = None) -> List[Vulnerability]:
        """Get vulnerabilities with optional filtering.
        
        Args:
            severity_filter: Filter by severity level
            category_filter: Filter by vulnerability category
            
        Returns:
            List of vulnerabilities matching filters
        """
        async with self._lock:
            vulnerabilities = self._vulnerabilities.copy()
        
        if severity_filter:
            vulnerabilities = [
                v for v in vulnerabilities 
                if v.severity.value == severity_filter
            ]
        
        if category_filter:
            vulnerabilities = [
                v for v in vulnerabilities 
                if v.category == category_filter
            ]
        
        return vulnerabilities
    
    async def add_discovered_url(self, url: str) -> None:
        """Add a discovered URL to the state.
        
        Args:
            url: URL to add
        """
        async with self._lock:
            self._discovered_urls.add(url)
        
        logger.debug(f"URL added to discovered list: {url}")
    
    async def get_discovered_urls(self) -> Set[str]:
        """Get all discovered URLs.
        
        Returns:
            Set of discovered URLs
        """
        async with self._lock:
            return self._discovered_urls.copy()
    
    async def mark_endpoint_tested(self, 
                                 endpoint: str, 
                                 method: str,
                                 test_type: str,
                                 result: Dict[str, Any]) -> None:
        """Mark an endpoint as tested with specific test type.
        
        Args:
            endpoint: Endpoint URL
            method: HTTP method
            test_type: Type of test performed
            result: Test result data
        """
        async with self._lock:
            endpoint_key = f"{method}:{endpoint}"
            
            if endpoint_key not in self._tested_endpoints:
                self._tested_endpoints[endpoint_key] = {
                    "endpoint": endpoint,
                    "method": method,
                    "tests": {},
                    "first_tested": time.time(),
                }
            
            self._tested_endpoints[endpoint_key]["tests"][test_type] = {
                "result": result,
                "timestamp": time.time(),
            }
        
        logger.debug(f"Endpoint marked as tested: {method} {endpoint} ({test_type})")
    
    async def is_endpoint_tested(self, 
                               endpoint: str, 
                               method: str,
                               test_type: str) -> bool:
        """Check if an endpoint has been tested with a specific test type.
        
        Args:
            endpoint: Endpoint URL
            method: HTTP method
            test_type: Type of test
            
        Returns:
            True if endpoint has been tested with the specified test type
        """
        async with self._lock:
            endpoint_key = f"{method}:{endpoint}"
            
            if endpoint_key not in self._tested_endpoints:
                return False
            
            return test_type in self._tested_endpoints[endpoint_key]["tests"]
    
    async def update_agent_status(self, agent_name: str, status: str) -> None:
        """Update the status of a specific agent.
        
        Args:
            agent_name: Name of the agent
            status: Current status
        """
        async with self._lock:
            self._agent_status[agent_name] = status
        
        logger.debug(f"Agent status updated: {agent_name} -> {status}")
    
    async def get_agent_status(self, agent_name: str) -> Optional[str]:
        """Get the status of a specific agent.
        
        Args:
            agent_name: Name of the agent
            
        Returns:
            Agent status or None if not found
        """
        async with self._lock:
            return self._agent_status.get(agent_name)
    
    async def get_all_agent_statuses(self) -> Dict[str, str]:
        """Get status of all agents.
        
        Returns:
            Dictionary mapping agent names to their statuses
        """
        async with self._lock:
            return self._agent_status.copy()
    
    async def get_scan_summary(self) -> Dict[str, Any]:
        """Get a summary of the current scan state.
        
        Returns:
            Dictionary containing scan summary information
        """
        async with self._lock:
            vulnerability_counts = defaultdict(int)
            for vuln in self._vulnerabilities:
                vulnerability_counts[vuln.severity.value] += 1
            
            return {
                "scan_metadata": self._scan_metadata.copy(),
                "agent_statuses": self._agent_status.copy(),
                "vulnerability_summary": {
                    "total": len(self._vulnerabilities),
                    "by_severity": dict(vulnerability_counts),
                },
                "discovery_summary": {
                    "urls_discovered": len(self._discovered_urls),
                    "endpoints_tested": len(self._tested_endpoints),
                },
                "current_time": time.time(),
            }
    
    async def export_state(self) -> Dict[str, Any]:
        """Export the complete state for serialization.
        
        Returns:
            Complete state dictionary
        """
        async with self._lock:
            return {
                "state": self._state,
                "vulnerabilities": [asdict(v) for v in self._vulnerabilities],
                "discovered_urls": list(self._discovered_urls),
                "tested_endpoints": self._tested_endpoints,
                "agent_status": self._agent_status,
                "scan_metadata": self._scan_metadata,
            }
    
    async def cleanup(self) -> None:
        """Clean up state manager resources."""
        logger.info("Cleaning up state manager")
        
        async with self._lock:
            # Clear all state but preserve metadata for final report
            self._state.clear()
            self._discovered_urls.clear()
            self._tested_endpoints.clear()
            self._agent_status.clear()
        
        logger.info("State manager cleanup completed")
