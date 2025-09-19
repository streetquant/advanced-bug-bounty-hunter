"""Request interception and modification for security testing.

This module provides sophisticated request interception capabilities
for analyzing and modifying HTTP requests/responses during security testing.
"""

import asyncio
import json
from typing import Dict, List, Optional, Callable, Any, Pattern
import re
from urllib.parse import urlparse, parse_qs

from playwright.async_api import Page, Request, Response, Route

from ..config.settings import SecurityTestingConfig
from ..utils.logging import get_logger

logger = get_logger(__name__)


class RequestInterceptor:
    """Handles request/response interception and modification for security testing."""
    
    def __init__(self, page: Page, config: SecurityTestingConfig):
        """Initialize the request interceptor.
        
        Args:
            page: Playwright page instance
            config: Security testing configuration
        """
        self.page = page
        self.config = config
        self._intercept_rules: List[Dict[str, Any]] = []
        self._blocked_urls: List[Pattern] = []
        self._modified_headers: Dict[str, str] = {}
        self._payload_mutations: List[Callable[[str], str]] = []
        
        # Statistics
        self.intercepted_requests = 0
        self.blocked_requests = 0
        self.modified_requests = 0
    
    async def initialize(self) -> None:
        """Initialize request interception."""
        logger.info("Initializing request interceptor")
        
        # Enable request interception
        await self.page.route("**/*", self._intercept_request)
        
        # Set up default security testing rules
        await self._setup_default_rules()
        
        logger.info("Request interceptor initialized")
    
    async def _setup_default_rules(self) -> None:
        """Set up default interception rules for security testing."""
        
        # Block unnecessary resources for performance
        self._blocked_urls = [
            re.compile(r"\.(css|js|png|jpg|jpeg|gif|svg|woff|woff2)$", re.IGNORECASE),
            re.compile(r"(google-analytics|googletagmanager|facebook|twitter)", re.IGNORECASE),
        ]
        
        # Add security testing headers
        self._modified_headers.update({
            "X-Forwarded-For": "127.0.0.1",
            "X-Real-IP": "127.0.0.1",
            "X-Originating-IP": "127.0.0.1",
            "X-Remote-IP": "127.0.0.1",
            "X-Client-IP": "127.0.0.1",
        })
        
        # Add payload mutation functions for injection testing
        self._payload_mutations = [
            self._add_sql_injection_payloads,
            self._add_xss_payloads,
            self._add_command_injection_payloads,
        ]
    
    async def _intercept_request(self, route: Route) -> None:
        """Main request interception handler.
        
        Args:
            route: Playwright route object
        """
        request = route.request
        self.intercepted_requests += 1
        
        try:
            # Check if request should be blocked
            if self._should_block_request(request):
                await route.abort()
                self.blocked_requests += 1
                logger.debug(f"Blocked request: {request.url}")
                return
            
            # Check if request should be modified
            if self._should_modify_request(request):
                modified_request = await self._modify_request(request)
                await route.continue_(**modified_request)
                self.modified_requests += 1
                logger.debug(f"Modified request: {request.url}")
                return
            
            # Continue with original request
            await route.continue_()
            
        except Exception as e:
            logger.error(f"Error in request interception: {e}")
            await route.continue_()  # Fallback to original request
    
    def _should_block_request(self, request: Request) -> bool:
        """Determine if a request should be blocked.
        
        Args:
            request: Playwright request object
            
        Returns:
            True if request should be blocked
        """
        url = request.url
        
        # Check against blocked URL patterns
        for pattern in self._blocked_urls:
            if pattern.search(url):
                return True
        
        # Block requests outside of scope
        target_domain = urlparse(self.config.target.primary_url).netloc
        request_domain = urlparse(url).netloc
        
        if not self._is_in_scope(request_domain, target_domain):
            return True
        
        return False
    
    def _is_in_scope(self, request_domain: str, target_domain: str) -> bool:
        """Check if a domain is within testing scope.
        
        Args:
            request_domain: Domain of the request
            target_domain: Target domain from configuration
            
        Returns:
            True if domain is in scope
        """
        # Check included domains
        for included_domain in self.config.target.scope.included_domains:
            if included_domain.startswith('.'):
                # Subdomain wildcard
                if request_domain.endswith(included_domain[1:]):
                    return True
            else:
                # Exact match
                if request_domain == included_domain:
                    return True
        
        # Check if it's the primary target domain
        if request_domain == target_domain:
            return True
        
        return False
    
    def _should_modify_request(self, request: Request) -> bool:
        """Determine if a request should be modified for testing.
        
        Args:
            request: Playwright request object
            
        Returns:
            True if request should be modified
        """
        # Only modify requests with parameters or POST data
        if request.method in ['GET', 'POST'] and (
            '?' in request.url or 
            request.post_data or 
            request.method == 'POST'
        ):
            return True
        
        return False
    
    async def _modify_request(self, request: Request) -> Dict[str, Any]:
        """Modify request for security testing.
        
        Args:
            request: Original request object
            
        Returns:
            Modified request parameters
        """
        modifications = {
            "headers": dict(request.headers)
        }
        
        # Add security testing headers
        modifications["headers"].update(self._modified_headers)
        
        # Modify POST data if present
        if request.post_data:
            modified_post_data = await self._modify_post_data(request.post_data)
            if modified_post_data != request.post_data:
                modifications["post_data"] = modified_post_data
        
        # Modify URL parameters for GET requests
        if request.method == 'GET' and '?' in request.url:
            modified_url = self._modify_url_parameters(request.url)
            if modified_url != request.url:
                modifications["url"] = modified_url
        
        return modifications
    
    async def _modify_post_data(self, post_data: str) -> str:
        """Modify POST data with security testing payloads.
        
        Args:
            post_data: Original POST data
            
        Returns:
            Modified POST data with testing payloads
        """
        modified_data = post_data
        
        # Apply payload mutations
        for mutation_func in self._payload_mutations:
            try:
                modified_data = mutation_func(modified_data)
            except Exception as e:
                logger.warning(f"Failed to apply payload mutation: {e}")
        
        return modified_data
    
    def _modify_url_parameters(self, url: str) -> str:
        """Modify URL parameters with security testing payloads.
        
        Args:
            url: Original URL with parameters
            
        Returns:
            Modified URL with testing payloads
        """
        # This would implement URL parameter mutation logic
        # For now, return the original URL
        return url
    
    def _add_sql_injection_payloads(self, data: str) -> str:
        """Add SQL injection testing payloads.
        
        Args:
            data: Original data
            
        Returns:
            Data with SQL injection payloads appended
        """
        sql_payloads = [
            "'",
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT NULL, NULL, NULL--",
        ]
        
        # This is a simplified implementation
        # In a real scenario, you'd intelligently insert payloads
        # into specific parameters based on context
        return data
    
    def _add_xss_payloads(self, data: str) -> str:
        """Add XSS testing payloads.
        
        Args:
            data: Original data
            
        Returns:
            Data with XSS payloads appended
        """
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
        ]
        
        # Simplified implementation
        return data
    
    def _add_command_injection_payloads(self, data: str) -> str:
        """Add command injection testing payloads.
        
        Args:
            data: Original data
            
        Returns:
            Data with command injection payloads
        """
        cmd_payloads = [
            "| whoami",
            "; cat /etc/passwd",
            "$(id)",
            "`uname -a`",
        ]
        
        # Simplified implementation
        return data
    
    async def add_intercept_rule(self, pattern: str, action: str, **kwargs) -> None:
        """Add a custom interception rule.
        
        Args:
            pattern: URL pattern to match
            action: Action to take (block, modify, log)
            **kwargs: Additional rule parameters
        """
        rule = {
            "pattern": re.compile(pattern),
            "action": action,
            **kwargs
        }
        self._intercept_rules.append(rule)
        logger.info(f"Added intercept rule: {pattern} -> {action}")
    
    async def get_statistics(self) -> Dict[str, int]:
        """Get interception statistics.
        
        Returns:
            Dictionary with interception statistics
        """
        return {
            "intercepted_requests": self.intercepted_requests,
            "blocked_requests": self.blocked_requests,
            "modified_requests": self.modified_requests,
        }
    
    async def cleanup(self) -> None:
        """Clean up request interceptor resources."""
        logger.info("Cleaning up request interceptor")
        
        try:
            # Remove all routes (Playwright handles this automatically on page close)
            await self.page.unroute("**/*")
        except Exception as e:
            logger.warning(f"Error during request interceptor cleanup: {e}")
        
        # Reset statistics
        self.intercepted_requests = 0
        self.blocked_requests = 0
        self.modified_requests = 0
        
        logger.info("Request interceptor cleanup completed")
