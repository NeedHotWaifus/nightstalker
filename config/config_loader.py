#!/usr/bin/env python3
"""
NightStalker Configuration Loader
Manages framework configuration and settings
"""

import os
import yaml
import json
from pathlib import Path
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

class NightStalkerConfig:
    """Configuration manager for NightStalker framework"""
    
    def __init__(self, config_path: str = "config/nightstalker_config.yaml"):
        """Initialize configuration manager"""
        self.config_path = config_path
        self.config = {}
        self.load_config()
        
    def load_config(self) -> bool:
        """Load configuration from file"""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    self.config = yaml.safe_load(f)
                logger.info(f"Configuration loaded from {self.config_path}")
                return True
            else:
                logger.warning(f"Configuration file not found: {self.config_path}")
                self.config = self._get_default_config()
                return False
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            self.config = self._get_default_config()
            return False
    
    def save_config(self) -> bool:
        """Save configuration to file"""
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            with open(self.config_path, 'w', encoding='utf-8') as f:
                yaml.dump(self.config, f, default_flow_style=False, indent=2)
            logger.info(f"Configuration saved to {self.config_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save configuration: {e}")
            return False
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value using dot notation"""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any) -> bool:
        """Set configuration value using dot notation"""
        try:
            keys = key.split('.')
            config = self.config
            
            # Navigate to the parent of the target key
            for k in keys[:-1]:
                if k not in config:
                    config[k] = {}
                config = config[k]
            
            # Set the value
            config[keys[-1]] = value
            return True
        except Exception as e:
            logger.error(f"Failed to set configuration value: {e}")
            return False
    
    def get_exfiltration_config(self) -> Dict[str, Any]:
        """Get exfiltration configuration"""
        return self.config.get('exfiltration', {})
    
    def get_payload_config(self) -> Dict[str, Any]:
        """Get payload builder configuration"""
        return self.config.get('payload_builder', {})
    
    def get_c2_config(self) -> Dict[str, Any]:
        """Get command & control configuration"""
        return self.config.get('c2', {})
    
    def get_stealth_config(self) -> Dict[str, Any]:
        """Get stealth configuration"""
        return self.config.get('stealth', {})
    
    def get_profile(self, profile_name: str) -> Dict[str, Any]:
        """Get configuration profile"""
        profiles = self.config.get('profiles', {})
        return profiles.get(profile_name, {})
    
    def apply_profile(self, profile_name: str) -> bool:
        """Apply a configuration profile"""
        try:
            profile = self.get_profile(profile_name)
            if not profile:
                logger.warning(f"Profile '{profile_name}' not found")
                return False
            
            # Apply profile settings
            for section, settings in profile.items():
                if section in self.config:
                    self.config[section].update(settings)
                else:
                    self.config[section] = settings
            
            logger.info(f"Applied profile: {profile_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to apply profile: {e}")
            return False
    
    def get_exfiltration_methods(self) -> list:
        """Get list of enabled exfiltration methods"""
        exfil_config = self.get_exfiltration_config()
        methods = []
        
        for method, config in exfil_config.items():
            if method != 'primary_method' and isinstance(config, dict):
                if config.get('enabled', False):
                    methods.append(method)
        
        return methods
    
    def get_primary_exfiltration_method(self) -> str:
        """Get primary exfiltration method"""
        return self.get('exfiltration.primary_method', 'dns')
    
    def is_exfiltration_enabled(self, method: str) -> bool:
        """Check if specific exfiltration method is enabled"""
        return self.get(f'exfiltration.{method}.enabled', False)
    
    def get_exfiltration_settings(self, method: str) -> Dict[str, Any]:
        """Get settings for specific exfiltration method"""
        return self.get(f'exfiltration.{method}', {})
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'framework': {
                'name': 'NightStalker',
                'version': '1.0.0',
                'mode': 'stealth',
                'log_level': 'INFO'
            },
            'exfiltration': {
                'primary_method': 'dns',
                'dns': {
                    'enabled': True,
                    'domain': 'attacker.com',
                    'chunk_size': 50,
                    'delay_between_chunks': 1.0
                },
                'https': {
                    'enabled': True,
                    'target_url': 'https://httpbin.org/post'
                }
            },
            'payload_builder': {
                'default_format': 'python',
                'compression_enabled': False,
                'encryption_enabled': False
            }
        }
    
    def validate_config(self) -> bool:
        """Validate configuration"""
        try:
            required_sections = ['framework', 'exfiltration', 'payload_builder']
            
            for section in required_sections:
                if section not in self.config:
                    logger.error(f"Missing required configuration section: {section}")
                    return False
            
            # Validate exfiltration configuration
            exfil_config = self.get_exfiltration_config()
            primary_method = exfil_config.get('primary_method')
            
            if primary_method and primary_method not in exfil_config:
                logger.error(f"Primary exfiltration method '{primary_method}' not configured")
                return False
            
            logger.info("Configuration validation passed")
            return True
        except Exception as e:
            logger.error(f"Configuration validation failed: {e}")
            return False
    
    def export_config(self, format: str = 'yaml') -> str:
        """Export configuration in specified format"""
        try:
            if format.lower() == 'json':
                return json.dumps(self.config, indent=2)
            elif format.lower() == 'yaml':
                return yaml.dump(self.config, default_flow_style=False, indent=2)
            else:
                raise ValueError(f"Unsupported format: {format}")
        except Exception as e:
            logger.error(f"Failed to export configuration: {e}")
            return ""
    
    def create_example_config(self) -> bool:
        """Create example configuration file"""
        try:
            example_config = {
                'framework': {
                    'name': 'NightStalker',
                    'version': '1.0.0',
                    'mode': 'stealth'
                },
                'exfiltration': {
                    'primary_method': 'dns',
                    'dns': {
                        'enabled': True,
                        'domain': 'your-domain.com'
                    },
                    'github_gist': {
                        'enabled': False,
                        'gist_id': 'your-gist-id',
                        'token': 'your-github-token'
                    }
                }
            }
            
            example_path = f"{self.config_path}.example"
            with open(example_path, 'w', encoding='utf-8') as f:
                yaml.dump(example_config, f, default_flow_style=False, indent=2)
            
            logger.info(f"Example configuration created: {example_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to create example configuration: {e}")
            return False

def load_config(config_path: str = "config/nightstalker_config.yaml") -> NightStalkerConfig:
    """Load NightStalker configuration"""
    return NightStalkerConfig(config_path)

def get_config() -> NightStalkerConfig:
    """Get global configuration instance"""
    if not hasattr(get_config, '_instance'):
        get_config._instance = load_config()
    return get_config._instance

# Example usage
if __name__ == "__main__":
    # Load configuration
    config = load_config()
    
    # Print configuration
    print("🌙 NightStalker Configuration")
    print("=" * 40)
    
    # Framework info
    framework_name = config.get('framework.name', 'Unknown')
    framework_version = config.get('framework.version', 'Unknown')
    print(f"Framework: {framework_name} v{framework_version}")
    
    # Exfiltration methods
    primary_method = config.get_primary_exfiltration_method()
    enabled_methods = config.get_exfiltration_methods()
    print(f"Primary exfiltration: {primary_method}")
    print(f"Enabled methods: {', '.join(enabled_methods)}")
    
    # Validate configuration
    if config.validate_config():
        print("✅ Configuration is valid")
    else:
        print("❌ Configuration has errors")
    
    # Export configuration
    print("\n📋 Configuration Export (YAML):")
    print(config.export_config('yaml')) 