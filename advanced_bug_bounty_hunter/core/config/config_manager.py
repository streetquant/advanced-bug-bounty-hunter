"""Configuration management for the Advanced Bug Bounty Hunter.

This module handles loading, validation, and management of configuration files
using Pydantic for type safety and validation.
"""

import os
from pathlib import Path
from typing import Optional, Dict, Any
import yaml
from pydantic import ValidationError

from .settings import SecurityTestingConfig
from ..utils.logging import get_logger

logger = get_logger(__name__)


class ConfigManager:
    """Manages configuration loading, validation, and access."""
    
    def __init__(self, config_path: Optional[Path] = None):
        """Initialize the configuration manager.
        
        Args:
            config_path: Optional path to configuration file.
                        Defaults to config/default.yaml
        """
        self.config_path = config_path or Path("config/default.yaml")
        self._config: Optional[SecurityTestingConfig] = None
        
    def load_config(self) -> SecurityTestingConfig:
        """Load and validate configuration from file.
        
        Returns:
            Validated SecurityTestingConfig instance
            
        Raises:
            FileNotFoundError: If config file doesn't exist
            ValidationError: If config validation fails
            yaml.YAMLError: If YAML parsing fails
        """
        if self._config is not None:
            return self._config
            
        try:
            # Load YAML configuration
            with open(self.config_path, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f)
                
            # Apply environment variable overrides
            config_data = self._apply_env_overrides(config_data)
            
            # Validate and create config object
            self._config = SecurityTestingConfig(**config_data)
            
            logger.info(f"Configuration loaded successfully from {self.config_path}")
            return self._config
            
        except FileNotFoundError:
            logger.error(f"Configuration file not found: {self.config_path}")
            raise
            
        except yaml.YAMLError as e:
            logger.error(f"YAML parsing error in {self.config_path}: {e}")
            raise
            
        except ValidationError as e:
            logger.error(f"Configuration validation failed: {e}")
            raise
    
    def _apply_env_overrides(self, config_data: Dict[str, Any]) -> Dict[str, Any]:
        """Apply environment variable overrides to configuration.
        
        Environment variables should be prefixed with BBHUNTER_ and use
        double underscores for nested keys. For example:
        BBHUNTER_GEMINI__API_KEY=your_key
        
        Args:
            config_data: Original configuration dictionary
            
        Returns:
            Configuration with environment overrides applied
        """
        env_prefix = "BBHUNTER_"
        
        for key, value in os.environ.items():
            if not key.startswith(env_prefix):
                continue
                
            # Remove prefix and convert to nested keys
            config_key = key[len(env_prefix):].lower()
            key_parts = config_key.split("__")
            
            # Navigate to the correct nested location
            current_dict = config_data
            for part in key_parts[:-1]:
                if part not in current_dict:
                    current_dict[part] = {}
                current_dict = current_dict[part]
            
            # Set the value (attempt type conversion)
            final_key = key_parts[-1]
            current_dict[final_key] = self._convert_env_value(value)
            
        return config_data
    
    def _convert_env_value(self, value: str) -> Any:
        """Convert environment variable string to appropriate type.
        
        Args:
            value: Environment variable string value
            
        Returns:
            Converted value (bool, int, float, or string)
        """
        # Boolean conversion
        if value.lower() in ('true', '1', 'yes', 'on'):
            return True
        elif value.lower() in ('false', '0', 'no', 'off'):
            return False
            
        # Number conversion
        try:
            if '.' in value:
                return float(value)
            else:
                return int(value)
        except ValueError:
            pass
            
        # Return as string
        return value
    
    def validate_config(self) -> bool:
        """Validate the current configuration.
        
        Returns:
            True if configuration is valid, False otherwise
        """
        try:
            self.load_config()
            return True
        except (FileNotFoundError, ValidationError, yaml.YAMLError):
            return False
    
    def create_default_config(self, output_path: Optional[Path] = None) -> Path:
        """Create a default configuration file.
        
        Args:
            output_path: Where to save the config. Defaults to config/default.yaml
            
        Returns:
            Path to the created configuration file
        """
        output_path = output_path or Path("config/default.yaml")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Create default config instance
        default_config = SecurityTestingConfig()
        
        # Convert to dictionary and save as YAML
        config_dict = default_config.model_dump()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            yaml.dump(config_dict, f, default_flow_style=False, indent=2)
            
        logger.info(f"Default configuration created at {output_path}")
        return output_path
    
    def get_config(self) -> SecurityTestingConfig:
        """Get the current configuration, loading if necessary.
        
        Returns:
            Current SecurityTestingConfig instance
        """
        if self._config is None:
            return self.load_config()
        return self._config
    
    def reload_config(self) -> SecurityTestingConfig:
        """Force reload of configuration from file.
        
        Returns:
            Newly loaded SecurityTestingConfig instance
        """
        self._config = None
        return self.load_config()
