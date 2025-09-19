"""Advanced request interception and modification for security testing.

This module provides sophisticated request/response interception capabilities
for analyzing and modifying HTTP traffic during security testing, with
database integration for persistence and intelligent payload injection.
"""

import asyncio
import json
import time
import hashlib
from typing import Dict, List, Optional, Callable, Any, Pattern, Tuple
import re
from urllib.parse import urlparse, parse_qs, urlencode
from dataclasses import dataclass, asdict

from playwright.async_api import Page, Request, Response, Route

from ..config.settings import SecurityTestingConfig
from ..models.base import DatabaseManager
from ...utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class InterceptedRequest:
    """Represents an intercepted HTTP request."""
    
    id: str
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[str]
    timestamp: float
    resource_type: str
    frame_url: Optional[str] = None
    is_navigation_request: bool = False
    post_data: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return asdict(self)


@dataclass
class InterceptedResponse:
    """Represents an intercepted HTTP response."""
    
    request_id: str
    status_code: int
    status_text: str
    headers: Dict[str, str]
    body: Optional[bytes]
    timestamp: float
    url: str
    size: int = 0
    mime_type: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        data = asdict(self)
        # Convert bytes to base64 string for JSON serialization
        if self.body:
            import base64
            data['body'] = base64.b64encode(self.body).decode('utf-8')
        return data


@dataclass
class PayloadInjectionRule:
    """Rule for payload injection."""
    
    name: str
    pattern: Pattern[str]
    payloads: List[str]
    parameter_types: List[str]  # ['query', 'form', 'header', 'path']
    enabled: bool = True
    max_injections_per_request: int = 3
    
    def matches_request(self, request: InterceptedRequest) -> bool:
        """Check if this rule should apply to the request."""
        if not self.enabled:
            return False
        return bool(self.pattern.search(request.url))


class PayloadGenerator:
    """Generates security testing payloads."""
    
    def __init__(self):
        self.logger = get_logger(f"{__name__}.payload_generator")
        
        # SQL Injection payloads
        self.sql_payloads = [
            "'",
            "''",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "'; DROP TABLE users; --",
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "1' AND (SELECT COUNT(*) FROM sysobjects)>0--",
            "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
        ]
        
        # XSS payloads
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<body onload=alert('XSS')>",
            "<div onclick=alert('XSS')>Click me</div>",
            "';alert('XSS');//",
            '";alert("XSS");//',
            "</script><script>alert('XSS')</script>",
        ]
        
        # Command injection payloads
        self.command_payloads = [
            "; whoami",
            "| whoami",
            "& whoami",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "& type C:\\windows\\system32\\drivers\\etc\\hosts",
            "$(whoami)",
            "`whoami`",
            "${7*7}",
            "#{7*7}",
        ]
        
        # Path traversal payloads
        self.path_traversal_payloads = [
            "../",
            "..\\//",
            "....//",
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "%2e%2e%2f",
            "%2e%2e%5c",
            "..%252f",
            "..%255c",
        ]
        
        # LDAP injection payloads
        self.ldap_payloads = [
            "*",
            "*)(&",
            "*))%00",
            ")(cn=*",
            "))(|(cn=*",
            "*)(uid=*",
            "*)(|(uid=*",
        ]
    
    def get_payloads_for_context(self, context: str, parameter_name: str = "") -> List[str]:
        """Get appropriate payloads based on context.
        
        Args:
            context: Context type (sql, xss, command, path, ldap)
            parameter_name: Name of the parameter being tested
            
        Returns:
            List of relevant payloads
        """
        context = context.lower()
        
        if context == "sql":
            return self.sql_payloads[:5]  # Limit for testing
        elif context == "xss":
            return self.xss_payloads[:5]
        elif context == "command":
            return self.command_payloads[:5]
        elif context == "path":
            return self.path_traversal_payloads[:5]
        elif context == "ldap":
            return self.ldap_payloads[:5]
        else:
            # Return a mixed set for general testing
            return (
                self.sql_payloads[:2] + 
                self.xss_payloads[:2] + 
                self.command_payloads[:1]
            )
    
    def generate_contextual_payload(self, original_value: str, context: str) -> str:
        """Generate a contextual payload based on original value.
        
        Args:
            original_value: Original parameter value
            context: Testing context
            
        Returns:
            Generated payload
        """
        payloads = self.get_payloads_for_context(context)
        
        if not payloads:
            return original_value
        
        # Select payload based on original value characteristics
        if original_value.isdigit():
            # Numeric context - prefer SQL injection
            sql_payloads = [p for p in payloads if "'" in p or "1" in p]
            return sql_payloads[0] if sql_payloads else payloads[0]
        
        elif "@" in original_value:
            # Email context - prefer XSS
            xss_payloads = [p for p in payloads if "<" in p]
            return xss_payloads[0] if xss_payloads else payloads[0]
        
        else:
            # General string context
            return payloads[0]


class AdvancedRequestInterceptor:
    """Advanced request interceptor with database integration."""
    
    def __init__(self, page: Page, config: SecurityTestingConfig, 
                 db_manager: Optional[DatabaseManager] = None):
        """Initialize the request interceptor.
        
        Args:
            page: Playwright page instance
            config: Security testing configuration
            db_manager: Database manager for persistence
        """
        self.page = page
        self.config = config
        self.db_manager = db_manager
        self.logger = get_logger(f"{__name__}.advanced_interceptor")
        
        # Payload generator
        self.payload_generator = PayloadGenerator()
        
        # Interception rules
        self._injection_rules: List[PayloadInjectionRule] = []
        self._blocked_urls: List[Pattern] = []
        self._modified_headers: Dict[str, str] = {}
        
        # Storage for requests and responses
        self._requests: Dict[str, InterceptedRequest] = {}
        self._responses: Dict[str, InterceptedResponse] = {}
        
        # Statistics
        self._stats = {
            "requests_intercepted": 0,
            "responses_intercepted": 0,
            "requests_modified": 0,
            "payloads_injected": 0,
            "requests_blocked": 0,
            "database_saves": 0
        }
        
        # Setup default rules
        self._setup_default_rules()
    
    async def initialize(self) -> None:
        """Initialize request interception."""
        self.logger.info("Initializing advanced request interceptor")
        
        # Enable request interception
        await self.page.route("**/*", self._intercept_request)
        
        # Set up response handling
        self.page.on("response", self._handle_response)
        
        self.logger.info("Advanced request interceptor initialized")
    
    def _setup_default_rules(self) -> None:
        """Set up default interception and injection rules."""
        
        # Block unnecessary resources for performance
        self._blocked_urls = [
            re.compile(r"\.(css|js|png|jpg|jpeg|gif|svg|woff|woff2|ico)$", re.IGNORECASE),
            re.compile(r"(google-analytics|googletagmanager|facebook|twitter|doubleclick)", re.IGNORECASE),
        ]
        
        # Add security testing headers
        self._modified_headers.update({
            "X-Forwarded-For": "127.0.0.1",
            "X-Real-IP": "127.0.0.1",
            "X-Originating-IP": "127.0.0.1",
            "X-Remote-IP": "127.0.0.1",
            "X-Client-IP": "127.0.0.1",
        })
        
        # SQL injection rules
        sql_rule = PayloadInjectionRule(
            name="sql_injection",
            pattern=re.compile(r"\.(php|asp|aspx|jsp).*[?&](id|user|search|q)=", re.IGNORECASE),
            payloads=self.payload_generator.sql_payloads[:3],
            parameter_types=["query", "form"]
        )
        self._injection_rules.append(sql_rule)
        
        # XSS injection rules
        xss_rule = PayloadInjectionRule(
            name="xss_injection",
            pattern=re.compile(r"[?&](search|q|name|comment|message)=", re.IGNORECASE),
            payloads=self.payload_generator.xss_payloads[:3],
            parameter_types=["query", "form"]
        )
        self._injection_rules.append(xss_rule)
    
    async def _intercept_request(self, route: Route) -> None:
        """Main request interception handler.
        
        Args:
            route: Playwright route object
        """
        request = route.request
        request_id = self._generate_request_id(request)
        
        self._stats["requests_intercepted"] += 1
        
        try:
            # Create intercepted request object
            intercepted_request = InterceptedRequest(
                id=request_id,
                method=request.method,
                url=request.url,
                headers=dict(request.headers),
                body=request.post_data,
                timestamp=time.time(),
                resource_type=request.resource_type,
                frame_url=request.frame.url if request.frame else None,
                is_navigation_request=request.is_navigation_request(),
                post_data=request.post_data
            )
            
            # Store request
            self._requests[request_id] = intercepted_request
            
            # Check if request should be blocked
            if self._should_block_request(intercepted_request):
                await route.abort()
                self._stats["requests_blocked"] += 1
                self.logger.debug(f"Blocked request: {request.url}")
                return
            
            # Check if request should be modified
            modifications = await self._get_request_modifications(intercepted_request)
            
            if modifications:
                await route.continue_(**modifications)
                self._stats["requests_modified"] += 1
                self.logger.debug(f"Modified request: {request.url}")
            else:
                await route.continue_()
            
            # Save to database if available
            if self.db_manager:
                await self._save_request_to_db(intercepted_request)
            
        except Exception as e:
            self.logger.error(f"Error in request interception: {e}", exc_info=True)
            await route.continue_()  # Fallback to original request
    
    async def _handle_response(self, response: Response) -> None:
        """Handle response interception.
        
        Args:
            response: Playwright response object
        """
        request_id = self._generate_request_id(response.request)
        
        self._stats["responses_intercepted"] += 1
        
        try:
            # Get response body (with size limit)
            body = None
            try:
                if response.status < 400 and 'text' in response.headers.get('content-type', '').lower():
                    body_text = await response.text()
                    if len(body_text) < 1024 * 1024:  # 1MB limit
                        body = body_text.encode('utf-8')
            except Exception:
                pass  # Skip body if there's an error
            
            # Create intercepted response object
            intercepted_response = InterceptedResponse(
                request_id=request_id,
                status_code=response.status,
                status_text=response.status_text,
                headers=dict(response.headers),
                body=body,
                timestamp=time.time(),
                url=response.url,
                size=len(body) if body else 0,
                mime_type=response.headers.get('content-type')
            )
            
            # Store response
            self._responses[request_id] = intercepted_response
            
            # Analyze response for vulnerabilities
            await self._analyze_response_for_vulnerabilities(intercepted_response)
            
            # Save to database if available
            if self.db_manager:
                await self._save_response_to_db(intercepted_response)
            
        except Exception as e:
            self.logger.error(f"Error handling response: {e}", exc_info=True)
    
    def _generate_request_id(self, request: Request) -> str:
        """Generate unique ID for a request.
        
        Args:
            request: Playwright request object
            
        Returns:
            Unique request ID
        """
        # Create ID based on method, URL, and timestamp
        id_string = f"{request.method}:{request.url}:{time.time()}"
        return hashlib.md5(id_string.encode()).hexdigest()[:12]
    
    def _should_block_request(self, request: InterceptedRequest) -> bool:
        """Determine if a request should be blocked.
        
        Args:
            request: Intercepted request object
            
        Returns:
            True if request should be blocked
        """
        url = request.url
        
        # Check against blocked URL patterns
        for pattern in self._blocked_urls:
            if pattern.search(url):
                return True
        
        # Check scope restrictions
        if not self._is_in_scope(url):
            return True
        
        return False
    
    def _is_in_scope(self, url: str) -> bool:
        """Check if URL is within testing scope.
        
        Args:
            url: URL to check
            
        Returns:
            True if URL is in scope
        """
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        
        # Check included domains
        target_domain = urlparse(str(self.config.target.primary_url)).netloc
        included_domains = self.config.target.scope.included_domains
        
        domain_in_scope = False
        for included_domain in included_domains:
            if included_domain.startswith('.'):
                # Subdomain wildcard
                if domain.endswith(included_domain[1:]) or domain == included_domain[1:]:
                    domain_in_scope = True
                    break
            else:
                if domain == included_domain:
                    domain_in_scope = True
                    break
        
        # Check primary target domain
        if domain == target_domain:
            domain_in_scope = True
        
        if not domain_in_scope:
            return False
        
        # Check excluded paths
        for excluded_path in self.config.target.scope.excluded_paths:
            if path.startswith(excluded_path):
                return False
        
        return True
    
    async def _get_request_modifications(self, request: InterceptedRequest) -> Optional[Dict[str, Any]]:
        """Get modifications to apply to a request.
        
        Args:
            request: Intercepted request object
            
        Returns:
            Dictionary of modifications or None
        """
        modifications = {}
        
        # Add security testing headers
        modified_headers = dict(request.headers)
        modified_headers.update(self._modified_headers)
        modifications["headers"] = modified_headers
        
        # Apply payload injection if applicable
        if self._should_inject_payloads(request):
            injected_request = await self._inject_payloads(request)
            if injected_request:
                if injected_request.body != request.body:
                    modifications["post_data"] = injected_request.body
                if injected_request.url != request.url:
                    modifications["url"] = injected_request.url
                self._stats["payloads_injected"] += 1
        
        return modifications if len(modifications) > 1 else None  # Only return if more than just headers
    
    def _should_inject_payloads(self, request: InterceptedRequest) -> bool:
        """Check if payloads should be injected into this request.
        
        Args:
            request: Intercepted request object
            
        Returns:
            True if payloads should be injected
        """
        # Only inject into GET/POST requests with parameters
        if request.method not in ['GET', 'POST']:
            return False
        
        # Check if any injection rules match
        for rule in self._injection_rules:
            if rule.matches_request(request):
                return True
        
        return False
    
    async def _inject_payloads(self, request: InterceptedRequest) -> Optional[InterceptedRequest]:
        """Inject security testing payloads into a request.
        
        Args:
            request: Original request object
            
        Returns:
            Modified request object or None
        """
        modified_request = InterceptedRequest(**asdict(request))
        injected_any = False
        
        # Find applicable injection rules
        applicable_rules = [rule for rule in self._injection_rules if rule.matches_request(request)]
        
        if not applicable_rules:
            return None
        
        for rule in applicable_rules[:1]:  # Limit to one rule per request
            # Inject into query parameters
            if "query" in rule.parameter_types and "?" in request.url:
                modified_url = self._inject_into_query_params(request.url, rule)
                if modified_url != request.url:
                    modified_request.url = modified_url
                    injected_any = True
            
            # Inject into form data
            if "form" in rule.parameter_types and request.post_data:
                modified_body = self._inject_into_form_data(request.post_data, rule)
                if modified_body != request.post_data:
                    modified_request.body = modified_body
                    modified_request.post_data = modified_body
                    injected_any = True
        
        return modified_request if injected_any else None
    
    def _inject_into_query_params(self, url: str, rule: PayloadInjectionRule) -> str:
        """Inject payloads into query parameters.
        
        Args:
            url: Original URL
            rule: Injection rule to apply
            
        Returns:
            Modified URL with injected payloads
        """
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            
            # Inject into first few parameters
            injected_count = 0
            for param_name, values in params.items():
                if injected_count >= rule.max_injections_per_request:
                    break
                
                if values:
                    original_value = values[0]
                    payload = self.payload_generator.generate_contextual_payload(
                        original_value, rule.name.split('_')[0]
                    )
                    params[param_name] = [payload]
                    injected_count += 1
            
            # Reconstruct URL
            new_query = urlencode(params, doseq=True)
            return parsed._replace(query=new_query).geturl()
            
        except Exception as e:
            self.logger.warning(f"Error injecting into query params: {e}")
            return url
    
    def _inject_into_form_data(self, post_data: str, rule: PayloadInjectionRule) -> str:
        """Inject payloads into form data.
        
        Args:
            post_data: Original POST data
            rule: Injection rule to apply
            
        Returns:
            Modified POST data with injected payloads
        """
        try:
            # Handle URL-encoded form data
            if 'application/x-www-form-urlencoded' in str(post_data).lower() or '&' in post_data:
                params = parse_qs(post_data, keep_blank_values=True)
                
                injected_count = 0
                for param_name, values in params.items():
                    if injected_count >= rule.max_injections_per_request:
                        break
                    
                    if values:
                        original_value = values[0]
                        payload = self.payload_generator.generate_contextual_payload(
                            original_value, rule.name.split('_')[0]
                        )
                        params[param_name] = [payload]
                        injected_count += 1
                
                return urlencode(params, doseq=True)
            
            # Handle JSON data
            elif post_data.strip().startswith('{'):
                try:
                    data = json.loads(post_data)
                    injected_count = 0
                    
                    for key, value in list(data.items()):
                        if injected_count >= rule.max_injections_per_request:
                            break
                        
                        if isinstance(value, str):
                            payload = self.payload_generator.generate_contextual_payload(
                                value, rule.name.split('_')[0]
                            )
                            data[key] = payload
                            injected_count += 1
                    
                    return json.dumps(data)
                    
                except json.JSONDecodeError:
                    pass
            
            return post_data
            
        except Exception as e:
            self.logger.warning(f"Error injecting into form data: {e}")
            return post_data
    
    async def _analyze_response_for_vulnerabilities(self, response: InterceptedResponse) -> None:
        """Analyze response for potential vulnerabilities.
        
        Args:
            response: Intercepted response object
        """
        try:
            # Analyze headers for security issues
            headers = response.headers
            
            # Check for missing security headers
            security_headers = [
                'x-frame-options',
                'x-content-type-options',
                'x-xss-protection',
                'strict-transport-security',
                'content-security-policy'
            ]
            
            missing_headers = [h for h in security_headers if h not in headers]
            if missing_headers:
                self.logger.info(f"Missing security headers: {missing_headers} for {response.url}")
            
            # Analyze body for error messages or sensitive information
            if response.body and response.status_code >= 400:
                body_text = response.body.decode('utf-8', errors='ignore').lower()
                
                error_patterns = [
                    (r'sql.*error', 'SQL Error Disclosure'),
                    (r'mysql.*error', 'MySQL Error Disclosure'),
                    (r'oracle.*error', 'Oracle Error Disclosure'),
                    (r'postgresql.*error', 'PostgreSQL Error Disclosure'),
                    (r'php.*error', 'PHP Error Disclosure'),
                    (r'java\..*exception', 'Java Exception Disclosure'),
                    (r'stack trace', 'Stack Trace Disclosure'),
                ]
                
                for pattern, vuln_type in error_patterns:
                    if re.search(pattern, body_text):
                        self.logger.warning(f"Potential {vuln_type} detected in {response.url}")
            
        except Exception as e:
            self.logger.warning(f"Error analyzing response: {e}")
    
    async def _save_request_to_db(self, request: InterceptedRequest) -> None:
        """Save request to database.
        
        Args:
            request: Request to save
        """
        try:
            if not self.db_manager:
                return
            
            # This would insert into a requests table
            # Implementation depends on the database schema
            self.logger.debug(f"Saved request {request.id} to database")
            self._stats["database_saves"] += 1
            
        except Exception as e:
            self.logger.error(f"Error saving request to database: {e}")
    
    async def _save_response_to_db(self, response: InterceptedResponse) -> None:
        """Save response to database.
        
        Args:
            response: Response to save
        """
        try:
            if not self.db_manager:
                return
            
            # This would insert into a responses table
            # Implementation depends on the database schema
            self.logger.debug(f"Saved response for {response.request_id} to database")
            self._stats["database_saves"] += 1
            
        except Exception as e:
            self.logger.error(f"Error saving response to database: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get interception statistics.
        
        Returns:
            Dictionary with statistics
        """
        return {
            **self._stats,
            "stored_requests": len(self._requests),
            "stored_responses": len(self._responses),
            "injection_rules": len(self._injection_rules)
        }
    
    def get_request_response_pairs(self) -> List[Tuple[InterceptedRequest, Optional[InterceptedResponse]]]:
        """Get all request-response pairs.
        
        Returns:
            List of (request, response) tuples
        """
        pairs = []
        for request_id, request in self._requests.items():
            response = self._responses.get(request_id)
            pairs.append((request, response))
        return pairs
    
    async def cleanup(self) -> None:
        """Clean up interceptor resources."""
        self.logger.info("Cleaning up request interceptor")
        
        try:
            # Remove all routes
            await self.page.unroute("**/*")
        except Exception as e:
            self.logger.warning(f"Error during interceptor cleanup: {e}")
        
        # Clear stored data
        self._requests.clear()
        self._responses.clear()
        
        self.logger.info("Request interceptor cleanup completed")
