"""Playwright browser management for automated security testing.

This module provides a comprehensive Playwright wrapper that handles browser
lifecycle management, request/response interception, HAR file generation,
and advanced automation features specifically designed for security testing.
"""

import asyncio
import json
import time
from pathlib import Path
from typing import Optional, Dict, List, Any, Callable, AsyncContextManager
from contextlib import asynccontextmanager

from playwright.async_api import (
    async_playwright, 
    Browser, 
    BrowserContext, 
    Page,
    Request,
    Response,
    Route,
    Playwright
)

from ..config.settings import SecurityTestingConfig, StealthConfig
from ..utils.logging import get_logger
from .request_interceptor import RequestInterceptor

logger = get_logger(__name__)


class PlaywrightManager:
    """Manages Playwright browser instances and automation for security testing."""
    
    def __init__(self, config: SecurityTestingConfig):
        """Initialize the Playwright manager.
        
        Args:
            config: Security testing configuration
        """
        self.config = config
        self.playwright: Optional[Playwright] = None
        self.browser: Optional[Browser] = None
        self.context: Optional[BrowserContext] = None
        self.page: Optional[Page] = None
        self.request_interceptor: Optional[RequestInterceptor] = None
        
        # Request/Response storage for HAR generation
        self._requests: List[Dict[str, Any]] = []
        self._responses: List[Dict[str, Any]] = []
        self._start_time = time.time()
        
        # Browser configuration
        self._browser_options = self._get_browser_options()
        self._context_options = self._get_context_options()
        
    async def initialize(self) -> None:
        """Initialize Playwright and browser instances."""
        logger.info("Initializing Playwright browser manager")
        
        try:
            # Start Playwright
            self.playwright = await async_playwright().start()
            
            # Launch browser (default to Chromium for security testing)
            self.browser = await self.playwright.chromium.launch(**self._browser_options)
            
            # Create browser context with security testing optimizations
            self.context = await self.browser.new_context(**self._context_options)
            
            # Create main page
            self.page = await self.context.new_page()
            
            # Initialize request interceptor
            self.request_interceptor = RequestInterceptor(
                self.page, 
                self.config
            )
            await self.request_interceptor.initialize()
            
            # Set up request/response logging for HAR generation
            await self._setup_har_logging()
            
            logger.info("Playwright browser manager initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize Playwright manager: {e}")
            await self.cleanup()
            raise
    
    def _get_browser_options(self) -> Dict[str, Any]:
        """Get browser launch options optimized for security testing.
        
        Returns:
            Dictionary of browser launch options
        """
        options = {
            "headless": True,  # Always headless for security testing
            "args": [
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--disable-web-security",  # For CORS bypass testing
                "--disable-features=VizDisplayCompositor",
                "--ignore-certificate-errors",  # For SSL testing
                "--ignore-ssl-errors",
                "--ignore-certificate-errors-spki-list",
                "--allow-running-insecure-content",
                "--disable-blink-features=AutomationControlled",  # Anti-detection
                "--disable-extensions",
                "--disable-plugins",
                "--disable-images",  # Speed optimization
                "--disable-javascript",  # Can be overridden per context
                "--user-agent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ]
        }
        
        # Add stealth options if enabled
        if self.config.stealth.enabled:
            options["args"].extend([
                "--disable-blink-features=AutomationControlled",
                "--exclude-switches=enable-automation",
                "--disable-extensions-http-throttling"
            ])
        
        return options
    
    def _get_context_options(self) -> Dict[str, Any]:
        """Get browser context options for security testing.
        
        Returns:
            Dictionary of browser context options
        """
        stealth_config = self.config.stealth
        
        options = {
            "viewport": {"width": 1920, "height": 1080},
            "ignore_https_errors": True,  # For SSL testing
            "java_script_enabled": True,  # Enable JS by default
            "accept_downloads": True,
            "bypass_csp": True,  # For XSS testing
        }
        
        # Add stealth user agent rotation
        if stealth_config.enabled and stealth_config.user_agents:
            import random
            options["user_agent"] = random.choice(stealth_config.user_agents)
        
        # Add proxy configuration if available
        # This would be extended based on proxy rotation needs
        
        return options
    
    async def _setup_har_logging(self) -> None:
        """Set up request/response logging for HAR file generation."""
        if not self.page:
            return
            
        async def log_request(request: Request) -> None:
            """Log request for HAR generation."""
            try:
                request_data = {
                    "method": request.method,
                    "url": request.url,
                    "headers": dict(request.headers),
                    "postData": request.post_data if request.post_data else None,
                    "timestamp": time.time(),
                    "resourceType": request.resource_type
                }
                self._requests.append(request_data)
            except Exception as e:
                logger.warning(f"Failed to log request: {e}")
        
        async def log_response(response: Response) -> None:
            """Log response for HAR generation."""
            try:
                response_data = {
                    "status": response.status,
                    "statusText": response.status_text,
                    "url": response.url,
                    "headers": dict(response.headers),
                    "timestamp": time.time(),
                    "size": len(await response.body()) if response.ok else 0
                }
                self._responses.append(response_data)
            except Exception as e:
                logger.warning(f"Failed to log response: {e}")
        
        # Attach event listeners
        self.page.on("request", log_request)
        self.page.on("response", log_response)
    
    async def navigate_to(self, url: str, wait_for: str = "networkidle") -> Optional[Response]:
        """Navigate to a URL with security testing optimizations.
        
        Args:
            url: Target URL to navigate to
            wait_for: Wait condition (networkidle, load, domcontentloaded)
            
        Returns:
            Response object from the navigation
        """
        if not self.page:
            raise RuntimeError("Browser not initialized. Call initialize() first.")
        
        logger.info(f"Navigating to: {url}")
        
        try:
            # Apply stealth delays if enabled
            if self.config.stealth.enabled:
                import random
                delay_config = self.config.stealth.request_delays
                delay = random.uniform(delay_config.min, delay_config.max)
                await asyncio.sleep(delay)
            
            # Navigate with timeout
            response = await self.page.goto(
                url, 
                wait_until=wait_for,
                timeout=self.config.performance.timeout_settings.request * 1000
            )
            
            logger.info(f"Successfully navigated to {url} - Status: {response.status if response else 'N/A'}")
            return response
            
        except Exception as e:
            logger.error(f"Failed to navigate to {url}: {e}")
            raise
    
    async def execute_javascript(self, script: str) -> Any:
        """Execute JavaScript in the current page context.
        
        Args:
            script: JavaScript code to execute
            
        Returns:
            Result of the JavaScript execution
        """
        if not self.page:
            raise RuntimeError("Browser not initialized")
        
        try:
            result = await self.page.evaluate(script)
            logger.debug(f"Executed JavaScript: {script[:100]}...")
            return result
        except Exception as e:
            logger.error(f"Failed to execute JavaScript: {e}")
            raise
    
    async def take_screenshot(self, path: Optional[Path] = None, full_page: bool = True) -> bytes:
        """Take a screenshot of the current page.
        
        Args:
            path: Optional path to save screenshot
            full_page: Whether to capture the full page
            
        Returns:
            Screenshot data as bytes
        """
        if not self.page:
            raise RuntimeError("Browser not initialized")
        
        screenshot_options = {
            "full_page": full_page,
            "type": "png"
        }
        
        if path:
            screenshot_options["path"] = str(path)
        
        return await self.page.screenshot(**screenshot_options)
    
    async def export_har(self, output_path: Path) -> None:
        """Export collected requests/responses as HAR file.
        
        Args:
            output_path: Path where to save the HAR file
        """
        logger.info(f"Exporting HAR file to: {output_path}")
        
        # Create HAR structure
        har_data = {
            "log": {
                "version": "1.2",
                "creator": {
                    "name": "Advanced Bug Bounty Hunter",
                    "version": "0.1.0"
                },
                "browser": {
                    "name": "Chromium",
                    "version": "120.0.0.0"
                },
                "pages": [],
                "entries": []
            }
        }
        
        # Combine requests and responses into HAR entries
        for i, request in enumerate(self._requests):
            # Find matching response
            response = None
            for resp in self._responses:
                if resp["url"] == request["url"]:
                    response = resp
                    break
            
            if not response:
                response = {
                    "status": 0,
                    "statusText": "No Response",
                    "headers": {},
                    "timestamp": request["timestamp"],
                    "size": 0
                }
            
            # Create HAR entry
            entry = {
                "startedDateTime": time.strftime(
                    "%Y-%m-%dT%H:%M:%S.%fZ",
                    time.gmtime(request["timestamp"])
                ),
                "time": (response["timestamp"] - request["timestamp"]) * 1000,
                "request": {
                    "method": request["method"],
                    "url": request["url"],
                    "headers": [
                        {"name": k, "value": v} 
                        for k, v in request["headers"].items()
                    ],
                    "postData": {
                        "mimeType": "application/x-www-form-urlencoded",
                        "text": request["postData"] or ""
                    } if request["postData"] else None
                },
                "response": {
                    "status": response["status"],
                    "statusText": response["statusText"],
                    "headers": [
                        {"name": k, "value": v}
                        for k, v in response["headers"].items()
                    ],
                    "content": {
                        "size": response["size"],
                        "mimeType": response["headers"].get("content-type", "")
                    }
                },
                "cache": {},
                "timings": {
                    "send": 0,
                    "wait": (response["timestamp"] - request["timestamp"]) * 1000,
                    "receive": 0
                }
            }
            
            har_data["log"]["entries"].append(entry)
        
        # Save HAR file
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(har_data, f, indent=2)
        
        logger.info(f"HAR file exported with {len(har_data['log']['entries'])} entries")
    
    async def cleanup(self) -> None:
        """Clean up browser resources."""
        logger.info("Cleaning up Playwright resources")
        
        try:
            if self.request_interceptor:
                await self.request_interceptor.cleanup()
            
            if self.context:
                await self.context.close()
            
            if self.browser:
                await self.browser.close()
            
            if self.playwright:
                await self.playwright.stop()
                
        except Exception as e:
            logger.warning(f"Error during cleanup: {e}")
        
        # Reset state
        self.page = None
        self.context = None
        self.browser = None
        self.playwright = None
        self.request_interceptor = None
        
        logger.info("Playwright cleanup completed")
    
    @asynccontextmanager
    async def browser_session(self) -> AsyncContextManager['PlaywrightManager']:
        """Context manager for browser session lifecycle.
        
        Yields:
            Initialized PlaywrightManager instance
        """
        await self.initialize()
        try:
            yield self
        finally:
            await self.cleanup()
    
    async def __aenter__(self) -> 'PlaywrightManager':
        """Async context manager entry."""
        await self.initialize()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.cleanup()
