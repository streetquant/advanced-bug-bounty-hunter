"""Pytest configuration and fixtures for Advanced Bug Bounty Hunter tests."""

import pytest
import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
from typing import AsyncGenerator, Generator

from advanced_bug_bounty_hunter.core.config.settings import SecurityTestingConfig
from advanced_bug_bounty_hunter.core.browser.playwright_manager import PlaywrightManager
from advanced_bug_bounty_hunter.core.state.state_manager import StateManager
from advanced_bug_bounty_hunter.agents.base.communication import MessageBus, initialize_communication
from advanced_bug_bounty_hunter.utils.logging import setup_logging


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def test_config() -> SecurityTestingConfig:
    """Create a test configuration."""
    config = SecurityTestingConfig()
    
    # Override with test-specific values
    config.target.primary_url = "https://httpbin.org"
    config.target.scope.included_domains = [".httpbin.org"]
    config.testing_strategy.methodology = "adaptive"
    config.performance.concurrent_agents = 2
    config.performance.timeout_settings.request = 10
    config.gemini.api_key = "test_api_key"
    config.database.type = "sqlite"
    config.database.name = ":memory:"
    config.output.directory = "./test_reports"
    config.logging.level = "DEBUG"
    
    return config


@pytest.fixture
async def mock_browser_manager() -> AsyncMock:
    """Create a mock browser manager."""
    mock = AsyncMock(spec=PlaywrightManager)
    mock.initialize.return_value = None
    mock.cleanup.return_value = None
    mock.navigate_to.return_value = MagicMock(status=200)
    mock.export_har.return_value = None
    mock.take_screenshot.return_value = b"fake_screenshot_data"
    return mock


@pytest.fixture
async def state_manager(test_config: SecurityTestingConfig) -> AsyncGenerator[StateManager, None]:
    """Create a real state manager for testing."""
    manager = StateManager(test_config)
    await manager.initialize()
    yield manager
    await manager.cleanup()


@pytest.fixture
async def message_bus() -> AsyncGenerator[MessageBus, None]:
    """Create a message bus for testing."""
    bus = await initialize_communication()
    yield bus
    await bus.stop()


@pytest.fixture(autouse=True)
def setup_test_logging():
    """Set up logging for tests."""
    setup_logging(
        level="DEBUG",
        format_type="simple",
        enable_sensitive_data_redaction=False  # Disable for easier testing
    )


@pytest.fixture
def mock_aiohttp_session():
    """Create a mock aiohttp session."""
    from unittest.mock import AsyncMock, MagicMock
    
    session = AsyncMock()
    
    # Mock response for crt.sh
    crt_response = AsyncMock()
    crt_response.status = 200
    crt_response.json.return_value = [
        {"name_value": "api.httpbin.org\ntest.httpbin.org"}
    ]
    
    # Mock response for DNSDumpster
    dns_response = AsyncMock()
    dns_response.status = 200
    dns_response.text.return_value = """
    <table class="table">
        <tr><td>api.httpbin.org</td></tr>
        <tr><td>eu.httpbin.org</td></tr>
    </table>
    """
    
    # Mock GitHub API response
    github_response = AsyncMock()
    github_response.status = 200
    github_response.json.return_value = {
        "items": [
            {
                "full_name": "test/httpbin-related",
                "description": "Test repository for httpbin.org",
                "html_url": "https://github.com/test/httpbin-related",
                "updated_at": "2023-01-01T00:00:00Z"
            }
        ]
    }
    
    # Mock Wayback Machine response
    wayback_response = AsyncMock()
    wayback_response.status = 200
    wayback_response.json.return_value = [
        ["timestamp", "original", "url", "status"],
        ["20230101000000", "https://httpbin.org/get", "https://httpbin.org/get", "200"]
    ]
    
    # Configure session.get to return appropriate responses
    def get_side_effect(url, **kwargs):
        if "crt.sh" in url:
            return crt_response
        elif "dnsdumpster.com" in url:
            return dns_response
        elif "api.github.com" in url:
            return github_response
        elif "web.archive.org" in url:
            return wayback_response
        else:
            # Default response
            default_response = AsyncMock()
            default_response.status = 200
            default_response.text.return_value = "<html><body>Test</body></html>"
            default_response.headers = {"server": "nginx", "content-type": "text/html"}
            return default_response
    
    session.get.side_effect = get_side_effect
    session.post.side_effect = get_side_effect
    session.close.return_value = None
    
    return session


@pytest.fixture
def temp_test_dir(tmp_path: Path) -> Path:
    """Create a temporary directory for test files."""
    test_dir = tmp_path / "bbhunter_test"
    test_dir.mkdir(parents=True, exist_ok=True)
    return test_dir


class AsyncContextManager:
    """Helper class for creating async context managers in tests."""
    
    def __init__(self, return_value=None):
        self.return_value = return_value
    
    async def __aenter__(self):
        return self.return_value
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


@pytest.fixture
def async_context_manager():
    """Factory for creating async context managers."""
    return AsyncContextManager
