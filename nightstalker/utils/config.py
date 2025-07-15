#!/usr/bin/env python3
"""
NightStalker Config Module
Provides configuration management for the NightStalker framework
"""

import os
import yaml
import json
from pathlib import Path
from typing import Dict, Any, Optional

class Config:
    """Configuration management class for NightStalker"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.config_file = config_file or "config/nightstalker_config.yaml"
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        config_path = Path(self.config_file)
        
        if not config_path.exists():
            return self._get_default_config()
        
        try:
            with open(config_path, 'r') as f:
                if config_path.suffix.lower() in ['.yaml', '.yml']:
                    return yaml.safe_load(f) or {}
                elif config_path.suffix.lower() == '.json':
                    return json.load(f)
                else:
                    return {}
        except Exception as e:
            print(f"Warning: Could not load config file {config_path}: {e}")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            'stealth': {
                'default_lhost': '127.0.0.1',
                'default_lport': 4444,
                'default_encryption_key': 'nightstalker2024',
                'default_payload_name': 'system_update',
                'default_registry_key': 'WindowsUpdate',
                'use_https': False
            },
            'c2': {
                'default_port': 4444,
                'max_clients': 10,
                'timeout': 30
            },
            'logging': {
                'level': 'INFO',
                'file': 'data/logs/framework.log',
                'console': True
            },
            'paths': {
                'output': 'output',
                'payloads': 'payloads',
                'logs': 'data/logs',
                'config': 'config'
            }
        }
    
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
    
    def set(self, key: str, value: Any) -> None:
        """Set configuration value using dot notation"""
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def save(self) -> None:
        """Save configuration to file"""
        config_path = Path(self.config_file)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(config_path, 'w') as f:
                if config_path.suffix.lower() in ['.yaml', '.yml']:
                    yaml.dump(self.config, f, default_flow_style=False)
                elif config_path.suffix.lower() == '.json':
                    json.dump(self.config, f, indent=2)
        except Exception as e:
            print(f"Error saving config file {config_path}: {e}")
    
    def reload(self) -> None:
        """Reload configuration from file"""
        self.config = self._load_config()
    
    def get_all(self) -> Dict[str, Any]:
        """Get all configuration"""
        return self.config.copy()

# Global config instance
config = Config()

def get_config() -> Config:
    """Get global config instance"""
    return config 