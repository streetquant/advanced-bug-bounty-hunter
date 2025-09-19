"""Integration test for the reconnaissance CLI flow.

This test verifies the end-to-end flow from CLI command to orchestrator
to reconnaissance agent execution.
"""

import pytest
import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from typing import Dict, Any

from advanced_bug_bounty_hunter.core.config.settings import SecurityTestingConfig
from advanced_bug_bounty_hunter.core.state.state_manager import StateManager
from advanced_bug_bounty_hunter.agents.base.communication import MessageBus, MessageType
from advanced_bug_bounty_hunter.agents.strategic.orchestrator import StrategicOrchestrator, AgentType
from advanced_bug_bounty_hunter.agents.strategic.reconnaissance import ReconnaissanceAgent
from advanced_bug_bounty_hunter.utils.logging import setup_logging, LogContext, generate_correlation_id


class TestReconnaissanceIntegration:
    """Integration tests for reconnaissance workflow."""
    
    @pytest.mark.asyncio
    async def test_full_recon_cli_workflow(
        self,
        test_config: SecurityTestingConfig,
        state_manager: StateManager,
        message_bus: MessageBus,
        mock_browser_manager: AsyncMock,
        mock_aiohttp_session: AsyncMock,
        temp_test_dir: Path
    ):
        """Test complete reconnaissance workflow from CLI to results.
        
        This test simulates the full workflow:
        1. CLI command initiates scan
        2. Orchestrator creates reconnaissance task
        3. Reconnaissance agent executes
        4. Results are collected and reported
        """
        # Set up test correlation ID
        correlation_id = generate_correlation_id()
        
        with LogContext(correlation_id=correlation_id, scan_id="test_scan_001"):
            # Update config for test
            test_config.target.primary_url = "https://httpbin.org"
            test_config.output.directory = str(temp_test_dir)
            
            # Create orchestrator
            orchestrator = StrategicOrchestrator(
                config=test_config,
                browser_manager=mock_browser_manager,
                state_manager=state_manager,
                message_bus=message_bus
            )
            
            # Create reconnaissance agent with mocked HTTP session
            recon_agent = ReconnaissanceAgent(
                config=test_config,
                browser_manager=mock_browser_manager,
                state_manager=state_manager
            )
            
            # Register agent with orchestrator
            orchestrator.register_agent(
                recon_agent,
                AgentType.RECONNAISSANCE,
                capabilities=["passive_intel", "subdomain_enum", "tech_fingerprint"]
            )
            
            # Set up agent communication
            recon_agent.set_message_bus(message_bus)
            
            try:
                # Initialize components
                await orchestrator.initialize()
                
                # Mock the reconnaissance agent's HTTP session
                with patch.object(recon_agent, '_session', mock_aiohttp_session):
                    await recon_agent.initialize()
                    
                    # Create a reconnaissance task manually
                    task_id = orchestrator.create_task(
                        AgentType.RECONNAISSANCE,
                        "Test passive reconnaissance",
                        priority=5,
                        payload={
                            "target_url": "https://httpbin.org",
                            "mode": "passive"
                        }
                    )
                    
                    # Verify task was created
                    assert task_id in orchestrator._tasks
                    task = orchestrator._tasks[task_id]
                    assert task.type == AgentType.RECONNAISSANCE
                    assert task.description == "Test passive reconnaissance"
                    
                    # Execute reconnaissance agent directly
                    result = await recon_agent.execute()
                    
                    # Verify agent execution results
                    assert result is not None
                    assert result.agent_name == "reconnaissance_agent"
                    assert "subdomains_found" in result.metadata
                    assert "technologies_detected" in result.metadata
                    
                    # Check that subdomains were discovered
                    subdomains_found = result.metadata["subdomains_found"]
                    assert subdomains_found > 0, "Should have found at least some subdomains"
                    
                    # Verify state manager has the results
                    discovered_subdomains = await state_manager.get("reconnaissance.discovered_subdomains")
                    assert discovered_subdomains is not None
                    assert len(discovered_subdomains) > 0
                    
                    # Verify technology detection results
                    tech_stack = await state_manager.get("reconnaissance.technology_stack")
                    assert tech_stack is not None
                    
                    # Check that URLs were added to discovered list
                    discovered_urls = await state_manager.get_discovered_urls()
                    assert len(discovered_urls) > 0
                    
                    print(f"\n=== Reconnaissance Results ===")
                    print(f"Subdomains found: {subdomains_found}")
                    print(f"Technologies detected: {len(tech_stack) if tech_stack else 0}")
                    print(f"URLs discovered: {len(discovered_urls)}")
                    print(f"Agent execution time: {result.execution_time:.2f}s")
                    
                    # Verify specific expected subdomains from mock data
                    recon_data = result.metadata.get("recon_data", {})
                    subdomains = recon_data.get("subdomains", [])
                    
                    expected_subdomains = {"api.httpbin.org", "test.httpbin.org", "eu.httpbin.org"}
                    found_subdomains = set(subdomains)
                    
                    # At least some expected subdomains should be found
                    assert len(expected_subdomains.intersection(found_subdomains)) > 0, \
                        f"Expected to find subdomains from {expected_subdomains}, but got {found_subdomains}"
                    
                    # Test message bus communication
                    stats = message_bus.get_statistics()
                    assert stats["messages_sent"] > 0, "Should have sent messages via bus"
                    
            finally:
                # Clean up
                await recon_agent.cleanup()
                await orchestrator.cleanup()
    
    @pytest.mark.asyncio
    async def test_orchestrator_task_assignment(
        self,
        test_config: SecurityTestingConfig,
        state_manager: StateManager,
        message_bus: MessageBus,
        mock_browser_manager: AsyncMock
    ):
        """Test orchestrator task assignment and management."""
        
        orchestrator = StrategicOrchestrator(
            config=test_config,
            browser_manager=mock_browser_manager,
            state_manager=state_manager,
            message_bus=message_bus
        )
        
        # Create a mock agent
        mock_agent = AsyncMock()
        mock_agent.name = "test_recon_agent"
        
        try:
            await orchestrator.initialize()
            
            # Register the mock agent
            orchestrator.register_agent(
                mock_agent,
                AgentType.RECONNAISSANCE,
                capabilities=["test_capability"]
            )
            
            # Verify agent was registered
            assert "test_recon_agent" in orchestrator._registered_agents
            agent_info = orchestrator._registered_agents["test_recon_agent"]
            assert agent_info.type == AgentType.RECONNAISSANCE
            assert "test_capability" in agent_info.capabilities
            
            # Create a task
            task_id = orchestrator.create_task(
                AgentType.RECONNAISSANCE,
                "Test task",
                priority=3,
                payload={"test": "data"}
            )
            
            # Verify task creation
            assert task_id in orchestrator._tasks
            task = orchestrator._tasks[task_id]
            assert task.description == "Test task"
            assert task.priority == 3
            assert task.payload["test"] == "data"
            
            # Test orchestration status
            status = orchestrator.get_orchestration_status()
            assert status["total_tasks"] == len(orchestrator._tasks)  # Initial tasks + our test task
            assert status["registered_agents"] == 1
            
        finally:
            await orchestrator.cleanup()
    
    @pytest.mark.asyncio
    async def test_message_bus_communication(
        self,
        message_bus: MessageBus
    ):
        """Test message bus communication between components."""
        
        # Test message subscription and delivery
        received_messages = []
        
        async def message_handler(message):
            received_messages.append(message)
        
        # Subscribe to vulnerability messages
        message_bus.subscribe(MessageType.VULNERABILITY_FOUND, message_handler)
        
        # Create and send a test message
        from advanced_bug_bounty_hunter.agents.base.communication import VulnerabilityFoundMessage
        
        test_message = VulnerabilityFoundMessage(
            sender_id="test_agent",
            payload={
                "title": "Test Vulnerability",
                "severity": "high",
                "url": "https://httpbin.org/test"
            }
        )
        
        await message_bus.publish(test_message)
        
        # Give message bus time to process
        await asyncio.sleep(0.1)
        
        # Verify message was received
        assert len(received_messages) == 1
        assert received_messages[0].type == MessageType.VULNERABILITY_FOUND
        assert received_messages[0].payload["title"] == "Test Vulnerability"
        
        # Test statistics
        stats = message_bus.get_statistics()
        assert stats["messages_sent"] >= 1
        assert stats["messages_processed"] >= 1
    
    @pytest.mark.asyncio
    async def test_state_manager_data_flow(
        self,
        state_manager: StateManager
    ):
        """Test state manager data storage and retrieval."""
        
        # Test basic state operations
        await state_manager.set("test.key", "test_value")
        value = await state_manager.get("test.key")
        assert value == "test_value"
        
        # Test nested state operations
        await state_manager.set("reconnaissance.test_data", {"subdomains": ["test.example.com"]})
        recon_data = await state_manager.get("reconnaissance.test_data")
        assert recon_data["subdomains"] == ["test.example.com"]
        
        # Test URL discovery tracking
        test_url = "https://test.example.com"
        await state_manager.add_discovered_url(test_url)
        discovered_urls = await state_manager.get_discovered_urls()
        assert test_url in discovered_urls
        
        # Test set operations
        await state_manager.add_to_set("test.set", "item1")
        await state_manager.add_to_set("test.set", "item2")
        test_set = await state_manager.get("test.set")
        assert "item1" in test_set
        assert "item2" in test_set
        
        # Test scan summary
        summary = await state_manager.get_scan_summary()
        assert "scan_metadata" in summary
        assert "discovery_summary" in summary
        assert summary["discovery_summary"]["urls_discovered"] > 0
    
    @pytest.mark.asyncio
    async def test_error_handling_and_recovery(
        self,
        test_config: SecurityTestingConfig,
        state_manager: StateManager,
        message_bus: MessageBus,
        mock_browser_manager: AsyncMock
    ):
        """Test error handling and recovery in the reconnaissance flow."""
        
        # Create agent with intentionally failing HTTP session
        failing_session = AsyncMock()
        failing_session.get.side_effect = Exception("Network error")
        failing_session.close.return_value = None
        
        recon_agent = ReconnaissanceAgent(
            config=test_config,
            browser_manager=mock_browser_manager,
            state_manager=state_manager
        )
        
        try:
            # Mock the failing session
            with patch.object(recon_agent, '_session', failing_session):
                await recon_agent.initialize()
                
                # Agent should handle errors gracefully
                result = await recon_agent.execute()
                
                # Even with failures, agent should complete
                assert result is not None
                assert result.agent_name == "reconnaissance_agent"
                
                # Should have attempted operations despite failures
                assert result.execution_time > 0
                
        finally:
            await recon_agent.cleanup()
    
    def test_configuration_validation(
        self,
        test_config: SecurityTestingConfig
    ):
        """Test configuration validation and settings."""
        
        # Verify test configuration is valid
        assert test_config.target.primary_url == "https://httpbin.org"
        assert ".httpbin.org" in test_config.target.scope.included_domains
        assert test_config.performance.concurrent_agents == 2
        
        # Test configuration serialization
        config_dict = test_config.model_dump()
        assert config_dict["target"]["primary_url"] == "https://httpbin.org"
        
        # Verify agent configuration flags
        assert test_config.testing_strategy.agents.reconnaissance is True
        assert test_config.configuration.reconnaissance.passive_intel is True
        assert test_config.configuration.reconnaissance.technology_fingerprinting is True
    
    @pytest.mark.asyncio 
    async def test_correlation_id_tracking(
        self,
        test_config: SecurityTestingConfig,
        state_manager: StateManager
    ):
        """Test correlation ID tracking through the system."""
        
        correlation_id = generate_correlation_id()
        
        with LogContext(correlation_id=correlation_id):
            # Operations within this context should be tracked
            await state_manager.set("test.correlation", "test_data")
            
            # Verify the correlation ID is accessible
            from advanced_bug_bounty_hunter.utils.logging import get_correlation_id
            assert get_correlation_id() == correlation_id
        
        # Context should be reset outside the block
        from advanced_bug_bounty_hunter.utils.logging import get_correlation_id
        current_id = get_correlation_id()
        assert current_id != correlation_id or current_id == ""  # May be empty or different
    
    @pytest.mark.asyncio
    async def test_performance_and_timeouts(
        self,
        test_config: SecurityTestingConfig,
        state_manager: StateManager,
        mock_browser_manager: AsyncMock
    ):
        """Test performance characteristics and timeout handling."""
        
        # Create slow mock session to test timeouts
        slow_session = AsyncMock()
        
        async def slow_response(*args, **kwargs):
            await asyncio.sleep(0.1)  # Simulate slow response
            response = AsyncMock()
            response.status = 200
            response.json.return_value = []
            return response
        
        slow_session.get.side_effect = slow_response
        slow_session.close.return_value = None
        
        recon_agent = ReconnaissanceAgent(
            config=test_config,
            browser_manager=mock_browser_manager,
            state_manager=state_manager
        )
        
        try:
            with patch.object(recon_agent, '_session', slow_session):
                await recon_agent.initialize()
                
                # Measure execution time
                import time
                start_time = time.time()
                
                result = await recon_agent.execute()
                
                end_time = time.time()
                execution_time = end_time - start_time
                
                # Verify reasonable execution time
                assert result.execution_time > 0
                assert execution_time < 30  # Should complete within 30 seconds
                
                print(f"\nPerformance Test Results:")
                print(f"Execution time: {execution_time:.2f}s")
                print(f"Agent reported time: {result.execution_time:.2f}s")
                
        finally:
            await recon_agent.cleanup()
