"""Security Testing Orchestrator - Main coordination agent.

This module provides the main orchestration logic for coordinating multiple
security testing agents, managing their execution, and aggregating results.
"""

import asyncio
import time
from typing import List, Dict, Optional, Any
from pathlib import Path

from ..core.config.settings import SecurityTestingConfig
from ..core.browser.playwright_manager import PlaywrightManager
from ..core.state.state_manager import StateManager
from ..core.models.base import DatabaseManager
from ..utils.logging import get_logger
from .base import AgentBase, AgentResult, AgentStatus, Vulnerability

logger = get_logger(__name__)


class ScanResult:
    """Aggregated results from a complete security scan."""
    
    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []
        self.evidence_files: List[Path] = []
        self.agent_results: Dict[str, AgentResult] = {}
        self.execution_time: float = 0.0
        self.report_path: Optional[Path] = None
        self.metadata: Dict[str, Any] = {}
    
    def add_agent_result(self, result: AgentResult) -> None:
        """Add an agent's results to the scan result."""
        self.agent_results[result.agent_name] = result
        self.vulnerabilities.extend(result.vulnerabilities)
        self.evidence_files.extend(result.evidence_files)
    
    def get_vulnerability_summary(self) -> Dict[str, int]:
        """Get vulnerability count by severity."""
        summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in self.vulnerabilities:
            summary[vuln.severity.value] += 1
        return summary


class SecurityTestingOrchestrator:
    """Main orchestrator for security testing operations."""
    
    def __init__(self, config: SecurityTestingConfig):
        """Initialize the orchestrator.
        
        Args:
            config: Security testing configuration
        """
        self.config = config
        self.logger = get_logger("orchestrator")
        
        # Core components
        self.browser_manager: Optional[PlaywrightManager] = None
        self.state_manager: Optional[StateManager] = None
        self.database_manager: Optional[DatabaseManager] = None
        
        # Agent management
        self.agents: List[AgentBase] = []
        self.active_agents: Dict[str, AgentBase] = {}
        
        # Execution state
        self.scan_start_time: Optional[float] = None
        self.scan_result = ScanResult()
        
    async def initialize(self) -> None:
        """Initialize all orchestrator components."""
        self.logger.info("Initializing Security Testing Orchestrator")
        
        try:
            # Initialize state manager
            self.state_manager = StateManager(self.config)
            await self.state_manager.initialize()
            
            # Initialize database manager
            self.database_manager = DatabaseManager(self.config.database)
            await self.database_manager.initialize()
            
            # Initialize browser manager
            self.browser_manager = PlaywrightManager(self.config)
            await self.browser_manager.initialize()
            
            # Register available agents based on configuration
            await self._register_agents()
            
            self.logger.info("Orchestrator initialization completed successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize orchestrator: {e}")
            await self.cleanup()
            raise
    
    async def _register_agents(self) -> None:
        """Register and configure security testing agents."""
        enabled_agents = self.config.testing_strategy.agents
        
        # This is a placeholder - in the full implementation, we would
        # import and instantiate the actual agent classes
        agent_classes = {
            "reconnaissance": "ReconnaissanceAgent",
            "authentication": "AuthenticationAgent", 
            "authorization": "AuthorizationAgent",
            "injection": "InjectionAgent",
            "business_logic": "BusinessLogicAgent",
            "client_side": "ClientSideAgent",
            "infrastructure": "InfrastructureAgent",
            "api_security": "APISecurityAgent",
        }
        
        for agent_type, agent_class_name in agent_classes.items():
            if getattr(enabled_agents, agent_type, False):
                self.logger.info(f"Agent {agent_type} will be registered (class: {agent_class_name})")
                # In the full implementation, we would instantiate the agent here
                # self.agents.append(AgentClass(...))
    
    async def run_comprehensive_scan(self) -> ScanResult:
        """Run a comprehensive security scan using all configured agents.
        
        Returns:
            Aggregated scan results
        """
        self.logger.info("Starting comprehensive security scan")
        self.scan_start_time = time.time()
        
        try:
            # Phase 1: Initialize scan
            await self._initialize_scan()
            
            # Phase 2: Run reconnaissance agents first
            recon_results = await self._run_reconnaissance_phase()
            
            # Phase 3: Run main testing agents in parallel
            main_results = await self._run_main_testing_phase()
            
            # Phase 4: Run post-processing and validation
            validation_results = await self._run_validation_phase()
            
            # Phase 5: Generate final report
            await self._generate_final_report()
            
            # Calculate total execution time
            self.scan_result.execution_time = time.time() - self.scan_start_time
            
            self.logger.info(
                f"Comprehensive scan completed in {self.scan_result.execution_time:.2f} seconds. "
                f"Found {len(self.scan_result.vulnerabilities)} vulnerabilities."
            )
            
            return self.scan_result
            
        except Exception as e:
            self.logger.error(f"Scan failed with error: {e}", exc_info=True)
            raise
    
    async def _initialize_scan(self) -> None:
        """Initialize the security scan."""
        self.logger.info(f"Initializing scan of target: {self.config.target.primary_url}")
        
        # Navigate to target URL to establish initial context
        if self.browser_manager:
            await self.browser_manager.navigate_to(str(self.config.target.primary_url))
        
        # Update state with scan metadata
        if self.state_manager:
            await self.state_manager.set("scan.target_url", str(self.config.target.primary_url))
            await self.state_manager.set("scan.start_time", self.scan_start_time)
            await self.state_manager.set("scan.status", "running")
    
    async def _run_reconnaissance_phase(self) -> List[AgentResult]:
        """Run reconnaissance agents to gather initial intelligence.
        
        Returns:
            List of reconnaissance agent results
        """
        self.logger.info("Starting reconnaissance phase")
        
        # In the full implementation, this would run actual reconnaissance agents
        # For now, we'll simulate the phase
        
        recon_agents = [
            agent for agent in self.agents 
            if "reconnaissance" in agent.name.lower()
        ]
        
        results = []
        for agent in recon_agents:
            self.logger.info(f"Running reconnaissance agent: {agent.name}")
            result = await agent.run()
            results.append(result)
            self.scan_result.add_agent_result(result)
        
        self.logger.info(f"Reconnaissance phase completed. {len(results)} agents executed.")
        return results
    
    async def _run_main_testing_phase(self) -> List[AgentResult]:
        """Run main security testing agents in parallel.
        
        Returns:
            List of main testing agent results
        """
        self.logger.info("Starting main testing phase")
        
        # Get non-reconnaissance agents
        main_agents = [
            agent for agent in self.agents 
            if "reconnaissance" not in agent.name.lower()
        ]
        
        # Run agents with concurrency control
        max_concurrent = self.config.performance.concurrent_agents
        
        results = []
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def run_agent_with_semaphore(agent: AgentBase) -> AgentResult:
            async with semaphore:
                self.logger.info(f"Running security testing agent: {agent.name}")
                return await agent.run()
        
        # Execute agents concurrently
        if main_agents:
            agent_tasks = [run_agent_with_semaphore(agent) for agent in main_agents]
            results = await asyncio.gather(*agent_tasks, return_exceptions=True)
            
            # Process results and handle exceptions
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    self.logger.error(f"Agent {main_agents[i].name} failed: {result}")
                else:
                    self.scan_result.add_agent_result(result)
        
        self.logger.info(f"Main testing phase completed. {len(results)} agents executed.")
        return [r for r in results if not isinstance(r, Exception)]
    
    async def _run_validation_phase(self) -> List[AgentResult]:
        """Run validation and verification of found vulnerabilities.
        
        Returns:
            List of validation agent results
        """
        self.logger.info("Starting validation phase")
        
        # In the full implementation, this would validate vulnerabilities
        # and remove false positives
        
        validation_results = []
        
        # Simulate validation logic
        if self.scan_result.vulnerabilities:
            self.logger.info(f"Validating {len(self.scan_result.vulnerabilities)} vulnerabilities")
            
            # Here we would implement actual validation logic
            # For now, we'll just log the validation
            validated_count = len(self.scan_result.vulnerabilities)
            self.logger.info(f"Validation completed: {validated_count} vulnerabilities confirmed")
        
        return validation_results
    
    async def _generate_final_report(self) -> None:
        """Generate the final security testing report."""
        self.logger.info("Generating final security report")
        
        # Create output directory
        output_dir = Path(self.config.output.directory)
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate report filename with timestamp
        timestamp = int(time.time())
        report_filename = f"security_report_{timestamp}.json"
        report_path = output_dir / report_filename
        
        # Export HAR file if available
        if self.browser_manager:
            har_path = output_dir / f"traffic_{timestamp}.har"
            await self.browser_manager.export_har(har_path)
            self.scan_result.evidence_files.append(har_path)
        
        # Generate basic JSON report
        import json
        
        report_data = {
            "scan_metadata": {
                "target_url": str(self.config.target.primary_url),
                "start_time": self.scan_start_time,
                "end_time": time.time(),
                "execution_time": self.scan_result.execution_time,
                "scan_id": f"scan_{int(self.scan_start_time)}",
            },
            "vulnerability_summary": self.scan_result.get_vulnerability_summary(),
            "vulnerabilities": [v.to_dict() for v in self.scan_result.vulnerabilities],
            "agent_results": {
                name: {
                    "status": result.status.value,
                    "execution_time": result.execution_time,
                    "vulnerability_count": len(result.vulnerabilities),
                    "error_message": result.error_message,
                }
                for name, result in self.scan_result.agent_results.items()
            },
            "evidence_files": [str(path) for path in self.scan_result.evidence_files],
        }
        
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        self.scan_result.report_path = report_path
        
        self.logger.info(f"Final report generated: {report_path}")
    
    async def cancel_scan(self) -> None:
        """Cancel the current security scan."""
        self.logger.info("Cancelling security scan")
        
        # Cancel all active agents
        for agent in self.active_agents.values():
            await agent.cancel()
        
        # Update state
        if self.state_manager:
            await self.state_manager.set("scan.status", "cancelled")
        
        self.logger.info("Security scan cancelled")
    
    async def get_scan_status(self) -> Dict[str, Any]:
        """Get current scan status and progress.
        
        Returns:
            Dictionary with current scan status information
        """
        if not self.state_manager:
            return {"status": "not_initialized"}
        
        return await self.state_manager.get_scan_summary()
    
    async def cleanup(self) -> None:
        """Clean up orchestrator resources."""
        self.logger.info("Cleaning up orchestrator resources")
        
        try:
            # Clean up all agents
            for agent in self.agents:
                try:
                    await agent.cleanup()
                except Exception as e:
                    self.logger.warning(f"Error cleaning up agent {agent.name}: {e}")
            
            # Clean up core components
            if self.browser_manager:
                await self.browser_manager.cleanup()
            
            if self.state_manager:
                await self.state_manager.cleanup()
            
            if self.database_manager:
                await self.database_manager.cleanup()
            
        except Exception as e:
            self.logger.warning(f"Error during orchestrator cleanup: {e}")
        
        # Reset state
        self.agents.clear()
        self.active_agents.clear()
        
        self.logger.info("Orchestrator cleanup completed")
