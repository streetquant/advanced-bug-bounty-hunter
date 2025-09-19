"""Pydantic settings models for configuration validation.

This module defines the complete configuration schema using Pydantic models
for type safety, validation, and documentation.
"""

from typing import List, Optional, Dict, Any, Union, Literal
from pathlib import Path
from pydantic import BaseModel, Field, validator, HttpUrl
from pydantic_settings import BaseSettings


class TargetConfig(BaseModel):
    """Configuration for target application settings."""
    
    primary_url: HttpUrl = Field(
        default="https://target.example.com",
        description="Main target URL for security testing"
    )
    
    class ScopeConfig(BaseModel):
        """Scope configuration for testing boundaries."""
        included_domains: List[str] = Field(
            default_factory=lambda: [".target.example.com"],
            description="Domains included in testing scope"
        )
        excluded_paths: List[str] = Field(
            default_factory=lambda: ["/logout", "/admin/dangerous"],
            description="Paths to exclude from testing"
        )
        ip_ranges: List[str] = Field(
            default_factory=lambda: ["192.168.1.0/24"],
            description="IP ranges included in scope"
        )
    
    scope: ScopeConfig = Field(default_factory=ScopeConfig)


class AuthenticationConfig(BaseModel):
    """Authentication configuration for accessing protected resources."""
    
    class AuthMethod(BaseModel):
        """Individual authentication method configuration."""
        type: Literal["form", "oauth2", "jwt", "basic", "digest"] = "form"
        login_url: Optional[HttpUrl] = None
        credentials: Optional[Dict[str, str]] = None
        mfa_token: Optional[str] = None
        client_id: Optional[str] = None
        client_secret: Optional[str] = None
        auth_url: Optional[HttpUrl] = None
        token: Optional[str] = None
    
    methods: List[AuthMethod] = Field(
        default_factory=lambda: [
            AuthMethod(
                type="form",
                login_url="https://target.com/login",
                credentials={"username": "testuser", "password": "testpass123"}
            )
        ]
    )


class TestingStrategyConfig(BaseModel):
    """Configuration for testing methodology and approach."""
    
    methodology: Literal["adaptive", "comprehensive", "targeted", "stealth"] = "adaptive"
    depth_level: int = Field(default=4, ge=1, le=5, description="Testing depth from 1-5")
    aggressiveness: Literal["passive", "moderate", "aggressive"] = "moderate"
    time_budget: str = Field(default="4h", description="Maximum testing duration")
    
    class AgentConfig(BaseModel):
        """Configuration for which agents to enable."""
        reconnaissance: bool = True
        authentication: bool = True
        authorization: bool = True
        injection: bool = True
        business_logic: bool = True
        client_side: bool = True
        infrastructure: bool = True
        api_security: bool = True
    
    agents: AgentConfig = Field(default_factory=AgentConfig)


class ConfigurationConfig(BaseModel):
    """Detailed configuration for specific testing categories."""
    
    class ReconnaissanceConfig(BaseModel):
        """Reconnaissance testing configuration."""
        passive_intel: bool = True
        active_scanning: bool = True
        subdomain_bruteforce: bool = True
        technology_fingerprinting: bool = True
    
    class InjectionConfig(BaseModel):
        """Injection testing configuration."""
        
        class SQLInjectionConfig(BaseModel):
            """SQL injection specific configuration."""
            databases: List[str] = Field(
                default_factory=lambda: ["mysql", "postgresql", "mssql", "oracle"]
            )
            techniques: List[str] = Field(
                default_factory=lambda: ["boolean", "time", "error", "union"]
            )
            payloads: Literal["basic", "comprehensive", "advanced"] = "comprehensive"
        
        class NoSQLInjectionConfig(BaseModel):
            """NoSQL injection configuration."""
            databases: List[str] = Field(
                default_factory=lambda: ["mongodb", "couchdb", "redis"]
            )
        
        class CommandInjectionConfig(BaseModel):
            """Command injection configuration."""
            operating_systems: List[str] = Field(
                default_factory=lambda: ["linux", "windows", "macos"]
            )
        
        sql_injection: SQLInjectionConfig = Field(default_factory=SQLInjectionConfig)
        nosql_injection: NoSQLInjectionConfig = Field(default_factory=NoSQLInjectionConfig)
        command_injection: CommandInjectionConfig = Field(default_factory=CommandInjectionConfig)
    
    reconnaissance: ReconnaissanceConfig = Field(default_factory=ReconnaissanceConfig)
    injection: InjectionConfig = Field(default_factory=InjectionConfig)


class PerformanceConfig(BaseModel):
    """Performance and concurrency settings."""
    
    concurrent_agents: int = Field(default=8, ge=1, le=50)
    request_rate: int = Field(default=10, ge=1, le=100, description="Requests per second")
    
    class TimeoutConfig(BaseModel):
        """Timeout settings for various operations."""
        request: int = Field(default=30, description="Request timeout in seconds")
        agent_task: int = Field(default=300, description="Agent task timeout in seconds")
        total_scan: int = Field(default=14400, description="Total scan timeout in seconds")
    
    timeout_settings: TimeoutConfig = Field(default_factory=TimeoutConfig)


class GeminiConfig(BaseModel):
    """Google Gemini LLM configuration."""
    
    api_key: str = Field(default="YOUR_GEMINI_API_KEY", description="Gemini API key")
    model: str = Field(default="gemini-1.5-pro", description="Primary model to use")
    fallback_model: str = Field(default="gemini-1.0-pro", description="Fallback model")
    rate_limit: int = Field(default=60, description="Requests per minute")
    
    @validator('api_key')
    def validate_api_key(cls, v):
        """Validate API key is not the default placeholder."""
        if v == "YOUR_GEMINI_API_KEY":
            raise ValueError("Please set a valid Gemini API key")
        return v


class StealthConfig(BaseModel):
    """Stealth and evasion configuration."""
    
    enabled: bool = False
    user_agents: List[str] = Field(
        default_factory=lambda: [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
        ]
    )
    proxy_rotation: bool = True
    
    class RequestDelayConfig(BaseModel):
        """Request delay configuration for stealth."""
        min: float = Field(default=0.5, ge=0.0)
        max: float = Field(default=3.0, ge=0.0)
        
        @validator('max')
        def validate_max_delay(cls, v, values):
            """Ensure max delay is greater than min delay."""
            if 'min' in values and v < values['min']:
                raise ValueError("Max delay must be greater than min delay")
            return v
    
    request_delays: RequestDelayConfig = Field(default_factory=RequestDelayConfig)


class OutputConfig(BaseModel):
    """Output and reporting configuration."""
    
    formats: List[Literal["json", "html", "pdf", "markdown"]] = Field(
        default_factory=lambda: ["json", "html", "pdf", "markdown"]
    )
    directory: str = Field(default="./reports", description="Output directory for reports")
    evidence_capture: bool = True
    video_recording: bool = True


class NotificationConfig(BaseModel):
    """Notification configuration."""
    
    critical_findings: bool = True
    
    class WebhookConfig(BaseModel):
        """Webhook notification configuration."""
        url: HttpUrl
        events: List[Literal["critical_vulnerability", "scan_complete", "error"]] = Field(
            default_factory=lambda: ["critical_vulnerability", "scan_complete"]
        )
    
    webhooks: List[WebhookConfig] = Field(default_factory=list)


class ComplianceConfig(BaseModel):
    """Compliance and audit configuration."""
    
    audit_logging: bool = True
    evidence_retention: str = Field(default="30d", description="Evidence retention period")
    gdpr_compliant: bool = True


class DatabaseConfig(BaseModel):
    """Database connection configuration."""
    
    type: Literal["postgresql", "mysql", "sqlite"] = "postgresql"
    host: str = "localhost"
    port: int = 5432
    name: str = "bbhunter"
    username: str = "bbhunter"
    password: str = "secure_password"
    
    @property
    def connection_string(self) -> str:
        """Generate database connection string."""
        if self.type == "sqlite":
            return f"sqlite:///{self.name}.db"
        else:
            return f"{self.type}://{self.username}:{self.password}@{self.host}:{self.port}/{self.name}"


class CacheConfig(BaseModel):
    """Cache configuration."""
    
    type: Literal["redis", "memory"] = "redis"
    host: str = "localhost"
    port: int = 6379
    db: int = 0
    ttl: int = Field(default=3600, description="Time to live in seconds")


class LoggingConfig(BaseModel):
    """Logging configuration."""
    
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    format: Literal["structured", "simple"] = "structured"
    file: str = "logs/bbhunter.log"
    max_size: str = "100MB"
    backup_count: int = 5


class SecurityTestingConfig(BaseSettings):
    """Main configuration model for the security testing platform."""
    
    target: TargetConfig = Field(default_factory=TargetConfig)
    authentication: AuthenticationConfig = Field(default_factory=AuthenticationConfig)
    testing_strategy: TestingStrategyConfig = Field(default_factory=TestingStrategyConfig)
    configuration: ConfigurationConfig = Field(default_factory=ConfigurationConfig)
    performance: PerformanceConfig = Field(default_factory=PerformanceConfig)
    gemini: GeminiConfig = Field(default_factory=GeminiConfig)
    stealth: StealthConfig = Field(default_factory=StealthConfig)
    output: OutputConfig = Field(default_factory=OutputConfig)
    notifications: NotificationConfig = Field(default_factory=NotificationConfig)
    compliance: ComplianceConfig = Field(default_factory=ComplianceConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    
    class Config:
        """Pydantic model configuration."""
        env_prefix = "BBHUNTER_"
        env_nested_delimiter = "__"
        case_sensitive = False
        validate_assignment = True
        extra = "forbid"  # Forbid extra fields not defined in schema
