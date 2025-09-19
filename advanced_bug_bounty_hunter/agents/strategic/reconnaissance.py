"""Reconnaissance agent for passive and active intelligence gathering.

This module implements sophisticated reconnaissance capabilities including
subdomain enumeration, technology fingerprinting, endpoint discovery,
and passive intelligence gathering from various sources.
"""

import asyncio
import json
import re
import time
from typing import Dict, List, Set, Optional, Any
from urllib.parse import urlparse, urljoin
from dataclasses import dataclass, field

import aiohttp
from bs4 import BeautifulSoup

from ..base import AgentBase, AgentResult, AgentStatus, Vulnerability, VulnerabilitySeverity
from ..base.communication import AgentCommunicationMixin, MessageType, SubdomainDiscoveredMessage
from ...core.config.settings import SecurityTestingConfig
from ...core.browser.playwright_manager import PlaywrightManager
from ...core.state.state_manager import StateManager
from ...utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class ReconResult:
    """Results from reconnaissance activities."""
    
    subdomains: Set[str] = field(default_factory=set)
    endpoints: Set[str] = field(default_factory=set)
    technologies: Dict[str, str] = field(default_factory=dict)
    dns_records: Dict[str, List[str]] = field(default_factory=dict)
    certificates: List[Dict[str, Any]] = field(default_factory=list)
    social_media: List[str] = field(default_factory=list)
    emails: Set[str] = field(default_factory=set)
    phone_numbers: Set[str] = field(default_factory=set)
    interesting_files: List[str] = field(default_factory=list)
    error_pages: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format."""
        return {
            "subdomains": list(self.subdomains),
            "endpoints": list(self.endpoints),
            "technologies": self.technologies,
            "dns_records": self.dns_records,
            "certificates": self.certificates,
            "social_media": self.social_media,
            "emails": list(self.emails),
            "phone_numbers": list(self.phone_numbers),
            "interesting_files": self.interesting_files,
            "error_pages": self.error_pages
        }


class PassiveReconEngine:
    """Engine for passive reconnaissance activities."""
    
    def __init__(self, session: aiohttp.ClientSession):
        self.session = session
        self.logger = get_logger(f"{__name__}.passive")
    
    async def enumerate_subdomains_crtsh(self, domain: str) -> Set[str]:
        """Enumerate subdomains using crt.sh certificate transparency logs.
        
        Args:
            domain: Target domain
            
        Returns:
            Set of discovered subdomains
        """
        self.logger.info(f"Enumerating subdomains for {domain} using crt.sh")
        subdomains = set()
        
        try:
            # Query crt.sh for certificates
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            
            async with self.session.get(url, timeout=30) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for cert in data:
                        names = cert.get('name_value', '').split('\n')
                        for name in names:
                            name = name.strip().lower()
                            # Remove wildcards and validate
                            if name.startswith('*.'):
                                name = name[2:]
                            
                            if self._is_valid_subdomain(name, domain):
                                subdomains.add(name)
                                self.logger.debug(f"Found subdomain via crt.sh: {name}")
                
                self.logger.info(f"crt.sh found {len(subdomains)} subdomains")
                
        except Exception as e:
            self.logger.error(f"Error querying crt.sh: {e}")
        
        return subdomains
    
    async def enumerate_subdomains_dnsdumpster(self, domain: str) -> Set[str]:
        """Enumerate subdomains using DNSDumpster.
        
        Args:
            domain: Target domain
            
        Returns:
            Set of discovered subdomains
        """
        self.logger.info(f"Enumerating subdomains for {domain} using DNSDumpster")
        subdomains = set()
        
        try:
            # First get the CSRF token
            url = "https://dnsdumpster.com/"
            async with self.session.get(url, timeout=30) as response:
                if response.status != 200:
                    return subdomains
                
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                csrf_token = None
                
                # Find CSRF token
                csrf_input = soup.find('input', {'name': 'csrfmiddlewaretoken'})
                if csrf_input:
                    csrf_token = csrf_input.get('value')
                
                if not csrf_token:
                    self.logger.warning("Could not find CSRF token for DNSDumpster")
                    return subdomains
            
            # Submit domain query
            data = {
                'csrfmiddlewaretoken': csrf_token,
                'targetip': domain,
                'user': 'free'
            }
            
            headers = {
                'Referer': 'https://dnsdumpster.com/',
                'Origin': 'https://dnsdumpster.com'
            }
            
            async with self.session.post(url, data=data, headers=headers, timeout=30) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    
                    # Parse results from the table
                    for table in soup.find_all('table', class_='table'):
                        for row in table.find_all('tr'):
                            cells = row.find_all('td')
                            if len(cells) >= 1:
                                subdomain_cell = cells[0].get_text().strip()
                                # Extract subdomain from cell content
                                if subdomain_cell and '.' in subdomain_cell:
                                    lines = subdomain_cell.split('\n')
                                    for line in lines:
                                        line = line.strip().lower()
                                        if self._is_valid_subdomain(line, domain):
                                            subdomains.add(line)
                                            self.logger.debug(f"Found subdomain via DNSDumpster: {line}")
                
                self.logger.info(f"DNSDumpster found {len(subdomains)} subdomains")
                
        except Exception as e:
            self.logger.error(f"Error querying DNSDumpster: {e}")
        
        return subdomains
    
    async def search_github_repos(self, domain: str) -> Dict[str, Any]:
        """Search GitHub repositories for mentions of the domain.
        
        Args:
            domain: Target domain
            
        Returns:
            Dictionary with found repositories and information
        """
        self.logger.info(f"Searching GitHub for {domain}")
        results = {
            "repositories": [],
            "potential_secrets": [],
            "subdomains": set()
        }
        
        try:
            # Search GitHub API (Note: Real implementation would use GitHub token)
            query = f"{domain}"
            url = f"https://api.github.com/search/repositories?q={query}&sort=updated&order=desc"
            
            async with self.session.get(url, timeout=30) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for repo in data.get('items', [])[:10]:  # Limit to first 10 results
                        repo_info = {
                            "name": repo.get('full_name'),
                            "description": repo.get('description'),
                            "url": repo.get('html_url'),
                            "updated_at": repo.get('updated_at')
                        }
                        results["repositories"].append(repo_info)
                        
                        # Look for potential subdomains in repo names/descriptions
                        text = f"{repo.get('name', '')} {repo.get('description', '')}".lower()
                        potential_subdomains = self._extract_subdomains_from_text(text, domain)
                        results["subdomains"].update(potential_subdomains)
                
                self.logger.info(f"GitHub search found {len(results['repositories'])} repositories")
                
        except Exception as e:
            self.logger.error(f"Error searching GitHub: {e}")
        
        return results
    
    async def search_web_archives(self, domain: str) -> Set[str]:
        """Search web archives for historical data about the domain.
        
        Args:
            domain: Target domain
            
        Returns:
            Set of discovered URLs and subdomains
        """
        self.logger.info(f"Searching web archives for {domain}")
        results = set()
        
        try:
            # Use Wayback Machine API
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&limit=100"
            
            async with self.session.get(url, timeout=30) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    for entry in data[1:]:  # Skip header
                        if len(entry) > 2:
                            archived_url = entry[2]
                            if archived_url.startswith('http'):
                                results.add(archived_url)
                                
                                # Extract subdomain
                                parsed = urlparse(archived_url)
                                if self._is_valid_subdomain(parsed.netloc, domain):
                                    results.add(parsed.netloc)
                
                self.logger.info(f"Web archives found {len(results)} entries")
                
        except Exception as e:
            self.logger.error(f"Error searching web archives: {e}")
        
        return results
    
    def _is_valid_subdomain(self, subdomain: str, base_domain: str) -> bool:
        """Validate if a subdomain is valid for the base domain.
        
        Args:
            subdomain: Potential subdomain
            base_domain: Base domain
            
        Returns:
            True if valid subdomain
        """
        if not subdomain or not base_domain:
            return False
        
        # Basic validation
        if not re.match(r'^[a-zA-Z0-9.-]+$', subdomain):
            return False
        
        # Must end with base domain
        if not subdomain.endswith(f'.{base_domain}') and subdomain != base_domain:
            return False
        
        # Avoid common false positives
        invalid_patterns = [
            r'\*',  # Wildcards
            r'\s',  # Whitespace
            r'^\.',  # Leading dots
            r'\.$',  # Trailing dots
        ]
        
        for pattern in invalid_patterns:
            if re.search(pattern, subdomain):
                return False
        
        return True
    
    def _extract_subdomains_from_text(self, text: str, domain: str) -> Set[str]:
        """Extract potential subdomains from text.
        
        Args:
            text: Text to search
            domain: Base domain
            
        Returns:
            Set of potential subdomains
        """
        subdomains = set()
        
        # Regex pattern for subdomains
        pattern = rf'([a-zA-Z0-9.-]*\.{re.escape(domain)})'
        matches = re.findall(pattern, text, re.IGNORECASE)
        
        for match in matches:
            if self._is_valid_subdomain(match, domain):
                subdomains.add(match.lower())
        
        return subdomains


class ActiveReconEngine:
    """Engine for active reconnaissance activities."""
    
    def __init__(self, session: aiohttp.ClientSession, browser_manager: PlaywrightManager):
        self.session = session
        self.browser_manager = browser_manager
        self.logger = get_logger(f"{__name__}.active")
    
    async def probe_subdomains(self, subdomains: Set[str]) -> Dict[str, Dict[str, Any]]:
        """Probe discovered subdomains to check if they're alive.
        
        Args:
            subdomains: Set of subdomains to probe
            
        Returns:
            Dictionary mapping live subdomains to their response data
        """
        self.logger.info(f"Probing {len(subdomains)} subdomains")
        live_subdomains = {}
        
        # Create semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(10)
        
        async def probe_single(subdomain: str) -> Optional[Dict[str, Any]]:
            async with semaphore:
                return await self._probe_single_subdomain(subdomain)
        
        # Probe all subdomains concurrently
        tasks = [probe_single(sub) for sub in subdomains]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        for subdomain, result in zip(subdomains, results):
            if isinstance(result, dict) and result:
                live_subdomains[subdomain] = result
                self.logger.debug(f"Live subdomain: {subdomain}")
        
        self.logger.info(f"Found {len(live_subdomains)} live subdomains")
        return live_subdomains
    
    async def _probe_single_subdomain(self, subdomain: str) -> Optional[Dict[str, Any]]:
        """Probe a single subdomain.
        
        Args:
            subdomain: Subdomain to probe
            
        Returns:
            Response data if subdomain is live
        """
        protocols = ['https', 'http']
        
        for protocol in protocols:
            try:
                url = f"{protocol}://{subdomain}"
                
                async with self.session.get(
                    url, 
                    timeout=10,
                    allow_redirects=True,
                    ssl=False  # Don't verify SSL for discovery
                ) as response:
                    return {
                        "url": url,
                        "status_code": response.status,
                        "headers": dict(response.headers),
                        "server": response.headers.get('server', 'unknown'),
                        "content_type": response.headers.get('content-type', 'unknown'),
                        "content_length": response.headers.get('content-length', 0),
                        "protocol": protocol,
                        "response_time": 0  # Would measure actual response time
                    }
                    
            except Exception:
                continue  # Try next protocol
        
        return None
    
    async def fingerprint_technologies(self, url: str) -> Dict[str, str]:
        """Fingerprint technologies used by a web application.
        
        Args:
            url: URL to fingerprint
            
        Returns:
            Dictionary of detected technologies
        """
        self.logger.info(f"Fingerprinting technologies for {url}")
        technologies = {}
        
        try:
            async with self.session.get(url, timeout=30) as response:
                if response.status != 200:
                    return technologies
                
                headers = response.headers
                content = await response.text()
                
                # Analyze headers
                tech_from_headers = self._analyze_headers(headers)
                technologies.update(tech_from_headers)
                
                # Analyze content
                tech_from_content = self._analyze_content(content)
                technologies.update(tech_from_content)
                
                self.logger.info(f"Detected {len(technologies)} technologies")
                
        except Exception as e:
            self.logger.error(f"Error fingerprinting {url}: {e}")
        
        return technologies
    
    def _analyze_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Analyze HTTP headers for technology indicators.
        
        Args:
            headers: HTTP response headers
            
        Returns:
            Dictionary of detected technologies from headers
        """
        technologies = {}
        
        # Server header
        server = headers.get('server', '').lower()
        if 'nginx' in server:
            technologies['web_server'] = 'Nginx'
        elif 'apache' in server:
            technologies['web_server'] = 'Apache'
        elif 'iis' in server:
            technologies['web_server'] = 'IIS'
        
        # X-Powered-By header
        powered_by = headers.get('x-powered-by', '').lower()
        if 'php' in powered_by:
            technologies['language'] = 'PHP'
        elif 'asp.net' in powered_by:
            technologies['language'] = 'ASP.NET'
        elif 'express' in powered_by:
            technologies['framework'] = 'Express.js'
        
        # Other technology indicators
        if 'x-aspnet-version' in headers:
            technologies['framework'] = 'ASP.NET'
        
        if 'x-drupal-cache' in headers:
            technologies['cms'] = 'Drupal'
        
        return technologies
    
    def _analyze_content(self, content: str) -> Dict[str, str]:
        """Analyze page content for technology indicators.
        
        Args:
            content: HTML content
            
        Returns:
            Dictionary of detected technologies from content
        """
        technologies = {}
        
        try:
            soup = BeautifulSoup(content, 'html.parser')
            
            # Meta tags
            for meta in soup.find_all('meta'):
                name = meta.get('name', '').lower()
                content_attr = meta.get('content', '').lower()
                
                if 'generator' in name:
                    if 'wordpress' in content_attr:
                        technologies['cms'] = 'WordPress'
                    elif 'drupal' in content_attr:
                        technologies['cms'] = 'Drupal'
                    elif 'joomla' in content_attr:
                        technologies['cms'] = 'Joomla'
            
            # Script tags
            for script in soup.find_all('script'):
                src = script.get('src', '').lower()
                
                if 'jquery' in src:
                    technologies['javascript_library'] = 'jQuery'
                elif 'angular' in src:
                    technologies['javascript_framework'] = 'AngularJS'
                elif 'react' in src:
                    technologies['javascript_framework'] = 'React'
                elif 'vue' in src:
                    technologies['javascript_framework'] = 'Vue.js'
            
            # Link tags
            for link in soup.find_all('link'):
                href = link.get('href', '').lower()
                
                if 'bootstrap' in href:
                    technologies['css_framework'] = 'Bootstrap'
            
        except Exception as e:
            self.logger.warning(f"Error analyzing content: {e}")
        
        return technologies


class ReconnaissanceAgent(AgentBase, AgentCommunicationMixin):
    """Reconnaissance agent for intelligence gathering."""
    
    def __init__(self,
                 config: SecurityTestingConfig,
                 browser_manager: PlaywrightManager,
                 state_manager: StateManager):
        """Initialize the reconnaissance agent.
        
        Args:
            config: Security testing configuration
            browser_manager: Browser manager instance
            state_manager: State manager instance
        """
        super().__init__(
            name="reconnaissance_agent",
            config=config,
            browser_manager=browser_manager,
            state_manager=state_manager
        )
        
        # HTTP session for API calls
        self._session: Optional[aiohttp.ClientSession] = None
        
        # Reconnaissance engines
        self._passive_engine: Optional[PassiveReconEngine] = None
        self._active_engine: Optional[ActiveReconEngine] = None
        
        # Results storage
        self._recon_results = ReconResult()
        
        # Configuration
        self._target_domain = urlparse(str(config.target.primary_url)).netloc
        self._recon_config = config.configuration.reconnaissance
    
    async def initialize(self) -> None:
        """Initialize the reconnaissance agent."""
        self.logger.info("Initializing Reconnaissance Agent")
        
        # Create HTTP session
        connector = aiohttp.TCPConnector(
            limit=50,
            limit_per_host=10,
            ssl=False  # Don't verify SSL for reconnaissance
        )
        
        timeout = aiohttp.ClientTimeout(total=30)
        
        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            }
        )
        
        # Initialize reconnaissance engines
        self._passive_engine = PassiveReconEngine(self._session)
        self._active_engine = ActiveReconEngine(self._session, self.browser_manager)
        
        self.logger.info("Reconnaissance Agent initialized")
    
    async def execute(self) -> AgentResult:
        """Execute reconnaissance activities.
        
        Returns:
            Reconnaissance results
        """
        self.logger.info(f"Starting reconnaissance of {self._target_domain}")
        
        try:
            # Phase 1: Passive reconnaissance
            if self._recon_config.passive_intel:
                await self._passive_reconnaissance()
            
            # Phase 2: Active reconnaissance
            if self._recon_config.active_scanning:
                await self._active_reconnaissance()
            
            # Phase 3: Technology fingerprinting
            if self._recon_config.technology_fingerprinting:
                await self._technology_fingerprinting()
            
            # Save results to state
            await self._save_results_to_state()
            
            # Create agent result
            result = AgentResult(
                agent_name=self.name,
                status=AgentStatus.COMPLETED
            )
            
            # Add metadata
            result.metadata = {
                "subdomains_found": len(self._recon_results.subdomains),
                "endpoints_found": len(self._recon_results.endpoints),
                "technologies_detected": len(self._recon_results.technologies),
                "emails_found": len(self._recon_results.emails),
                "recon_data": self._recon_results.to_dict()
            }
            
            self.logger.info(
                f"Reconnaissance completed. Found {len(self._recon_results.subdomains)} subdomains, "
                f"{len(self._recon_results.technologies)} technologies"
            )
            
            return result
            
        except Exception as e:
            self.logger.error(f"Reconnaissance failed: {e}", exc_info=True)
            raise
    
    async def cleanup(self) -> None:
        """Clean up reconnaissance agent resources."""
        self.logger.info("Cleaning up Reconnaissance Agent")
        
        if self._session:
            await self._session.close()
        
        self.logger.info("Reconnaissance Agent cleanup completed")
    
    async def _passive_reconnaissance(self) -> None:
        """Perform passive reconnaissance."""
        self.logger.info("Starting passive reconnaissance")
        
        if not self._passive_engine:
            return
        
        # Subdomain enumeration from certificate transparency
        crtsh_subdomains = await self._passive_engine.enumerate_subdomains_crtsh(self._target_domain)
        self._recon_results.subdomains.update(crtsh_subdomains)
        
        # Report discovered subdomains
        for subdomain in crtsh_subdomains:
            await self.report_subdomain(subdomain, "crt.sh")
        
        # Subdomain enumeration from DNSDumpster
        dnsdumpster_subdomains = await self._passive_engine.enumerate_subdomains_dnsdumpster(self._target_domain)
        self._recon_results.subdomains.update(dnsdumpster_subdomains)
        
        # Report newly discovered subdomains
        new_subdomains = dnsdumpster_subdomains - crtsh_subdomains
        for subdomain in new_subdomains:
            await self.report_subdomain(subdomain, "dnsdumpster")
        
        # Search GitHub
        github_results = await self._passive_engine.search_github_repos(self._target_domain)
        self._recon_results.subdomains.update(github_results["subdomains"])
        
        # Search web archives
        archive_results = await self._passive_engine.search_web_archives(self._target_domain)
        # Filter URLs vs subdomains
        for item in archive_results:
            if item.startswith('http'):
                self._recon_results.endpoints.add(item)
            else:
                self._recon_results.subdomains.add(item)
        
        self.logger.info(f"Passive reconnaissance found {len(self._recon_results.subdomains)} subdomains")
    
    async def _active_reconnaissance(self) -> None:
        """Perform active reconnaissance."""
        self.logger.info("Starting active reconnaissance")
        
        if not self._active_engine or not self._recon_results.subdomains:
            return
        
        # Probe discovered subdomains
        live_subdomains = await self._active_engine.probe_subdomains(self._recon_results.subdomains)
        
        # Update results with live subdomain data
        for subdomain, data in live_subdomains.items():
            self._recon_results.endpoints.add(data["url"])
            
            # Extract server information
            server = data.get("server", "unknown")
            if server != "unknown":
                self._recon_results.technologies[f"{subdomain}_server"] = server
        
        self.logger.info(f"Active reconnaissance found {len(live_subdomains)} live subdomains")
    
    async def _technology_fingerprinting(self) -> None:
        """Perform technology fingerprinting."""
        self.logger.info("Starting technology fingerprinting")
        
        if not self._active_engine:
            return
        
        # Fingerprint main target
        main_url = str(self.config.target.primary_url)
        main_tech = await self._active_engine.fingerprint_technologies(main_url)
        self._recon_results.technologies.update(main_tech)
        
        # Fingerprint discovered endpoints (limited to avoid overwhelming target)
        endpoints_to_check = list(self._recon_results.endpoints)[:5]
        
        for endpoint in endpoints_to_check:
            try:
                tech = await self._active_engine.fingerprint_technologies(endpoint)
                # Prefix with endpoint for uniqueness
                prefixed_tech = {f"{urlparse(endpoint).netloc}_{k}": v for k, v in tech.items()}
                self._recon_results.technologies.update(prefixed_tech)
            except Exception as e:
                self.logger.warning(f"Failed to fingerprint {endpoint}: {e}")
        
        self.logger.info(f"Technology fingerprinting found {len(main_tech)} technologies")
    
    async def _save_results_to_state(self) -> None:
        """Save reconnaissance results to shared state."""
        self.logger.info("Saving reconnaissance results to state")
        
        # Save discovered subdomains
        for subdomain in self._recon_results.subdomains:
            await self.state_manager.add_to_set("reconnaissance.discovered_subdomains", subdomain)
            await self.state_manager.add_discovered_url(f"https://{subdomain}")
        
        # Save discovered endpoints
        for endpoint in self._recon_results.endpoints:
            await self.state_manager.add_to_set("reconnaissance.endpoints", endpoint)
            await self.state_manager.add_discovered_url(endpoint)
        
        # Save technology information
        await self.state_manager.set("reconnaissance.technology_stack", self._recon_results.technologies)
        
        # Save complete reconnaissance results
        await self.state_manager.set("reconnaissance.results", self._recon_results.to_dict())
        
        self.logger.info("Reconnaissance results saved to state")
