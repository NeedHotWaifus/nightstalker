#!/usr/bin/env python3
"""
Configuration Management for NightStalker WebXF
Unified configuration system with YAML support
"""

import os
import yaml
import json
from pathlib import Path
from typing import Dict, Any, Optional, Union
import logging

# Global configuration instance
_config_instance = None

class ConfigManager:
    """Configuration manager for NightStalker WebXF"""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize configuration manager"""
        self.config_path = config_path or self._get_default_config_path()
        self.config = self._load_config()
        self._setup_logging()
    
    def _get_default_config_path(self) -> str:
        """Get default configuration file path"""
        # Try to find config in current directory or project root
        possible_paths = [
            "config/default.yaml",
            "nightstalker_webxf/config/default.yaml",
            str(Path(__file__).parent.parent / "config" / "default.yaml"),
            str(Path.home() / ".nightstalker_webxf" / "config.yaml")
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
        
        # Return default path for creation
        return "config/default.yaml"
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file"""
        try:
            if os.path.exists(self.config_path):
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    config = yaml.safe_load(f)
                    if config is None:
                        config = {}
            else:
                config = {}
            
            # Merge with default configuration
            default_config = self._get_default_config()
            merged_config = self._merge_configs(default_config, config)
            
            return merged_config
        
        except Exception as e:
            logging.error(f"Failed to load configuration: {e}")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration"""
        return {
            "framework": {
                "name": "NightStalker WebXF",
                "version": "2.0.0",
                "debug": False,
                "stealth_mode": True,
                "max_threads": 10,
                "timeout": 300
            },
            "tools": {
                "sqlmap": {
                    "path": "/usr/local/bin/sqlmap",
                    "timeout": 300,
                    "threads": 10,
                    "risk_level": 1,
                    "level": 1
                },
                "nuclei": {
                    "path": "/usr/local/bin/nuclei",
                    "templates_path": "~/.local/share/nuclei/templates",
                    "timeout": 300,
                    "severity": ["low", "medium", "high", "critical"],
                    "threads": 50
                },
                "xsstrike": {
                    "path": "/usr/local/bin/xsstrike",
                    "timeout": 300,
                    "crawl": True,
                    "blind": False
                },
                "metasploit": {
                    "path": "/usr/bin/msfconsole",
                    "workspace": "nightstalker_webxf",
                    "timeout": 600
                },
                "nmap": {
                    "path": "/usr/bin/nmap",
                    "timeout": 300,
                    "default_ports": [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995]
                }
            },
            "recon": {
                "subdomain_enumeration": {
                    "enabled": True,
                    "tools": ["subfinder", "amass", "sublist3r"],
                    "wordlists": ["/usr/share/wordlists/subdomains.txt"],
                    "threads": 10
                },
                "port_scanning": {
                    "enabled": True,
                    "tools": ["nmap", "masscan"],
                    "default_ports": [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995],
                    "threads": 10
                },
                "directory_enumeration": {
                    "enabled": True,
                    "tools": ["gobuster", "dirb", "dirsearch"],
                    "wordlists": ["/usr/share/wordlists/dirb/common.txt"],
                    "extensions": [".php", ".html", ".js", ".css"],
                    "threads": 10
                },
                "vulnerability_scanning": {
                    "enabled": True,
                    "tools": ["nuclei", "nikto"],
                    "severity_levels": ["low", "medium", "high", "critical"],
                    "threads": 10
                }
            },
            "exploitation": {
                "sql_injection": {
                    "enabled": True,
                    "risk_level": 1,
                    "threads": 10,
                    "dump_databases": True
                },
                "xss_detection": {
                    "enabled": True,
                    "payloads_file": "config/payloads/xss.txt",
                    "crawl_mode": True,
                    "blind_detection": False
                },
                "vulnerability_scanning": {
                    "enabled": True,
                    "severity_levels": ["low", "medium", "high", "critical"],
                    "update_templates": True
                }
            },
            "bruteforce": {
                "http_auth": {
                    "enabled": True,
                    "default_wordlists": ["/usr/share/wordlists/rockyou.txt"],
                    "rate_limit": 10,
                    "threads": 10
                },
                "ssh": {
                    "enabled": True,
                    "default_wordlists": ["/usr/share/wordlists/ssh_users.txt"],
                    "rate_limit": 5,
                    "threads": 5
                },
                "ftp": {
                    "enabled": True,
                    "default_wordlists": ["/usr/share/wordlists/rockyou.txt"],
                    "rate_limit": 5,
                    "threads": 5
                },
                "smtp": {
                    "enabled": True,
                    "default_wordlists": ["/usr/share/wordlists/email_users.txt"],
                    "rate_limit": 5,
                    "threads": 5
                }
            },
            "post_exploitation": {
                "session_management": {
                    "enabled": True,
                    "persistence": True,
                    "cleanup": True
                },
                "lateral_movement": {
                    "enabled": True,
                    "tools": ["psexec", "wmic", "powershell"]
                },
                "data_exfiltration": {
                    "enabled": True,
                    "encryption": True,
                    "compression": True
                }
            },
            "logging": {
                "level": "INFO",
                "file": "logs/framework.log",
                "max_size": "10MB",
                "backup_count": 5,
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                "console_output": True,
                "colored_output": True
            },
            "output": {
                "directory": "loot",
                "format": "json",
                "include_screenshots": True,
                "include_logs": True,
                "compress_results": True,
                "encrypt_sensitive": True
            },
            "security": {
                "stealth_mode": True,
                "rate_limiting": True,
                "user_agent_rotation": True,
                "proxy_support": False,
                "proxy_list": [],
                "encryption": True,
                "obfuscation": False
            },
            "network": {
                "timeout": 30,
                "retries": 3,
                "verify_ssl": False,
                "follow_redirects": True,
                "max_redirects": 5
            }
        }
    
    def _merge_configs(self, default: Dict[str, Any], user: Dict[str, Any]) -> Dict[str, Any]:
        """Merge user configuration with default configuration"""
        merged = default.copy()
        
        def merge_dicts(base: Dict[str, Any], override: Dict[str, Any]) -> None:
            for key, value in override.items():
                if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                    merge_dicts(base[key], value)
                else:
                    base[key] = value
        
        merge_dicts(merged, user)
        return merged
    
    def _setup_logging(self) -> None:
        """Setup logging configuration"""
        log_config = self.config.get("logging", {})
        log_level = getattr(logging, log_config.get("level", "INFO").upper())
        
        # Create logs directory if it doesn't exist
        log_file = log_config.get("file", "logs/framework.log")
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        
        # Configure logging
        logging.basicConfig(
            level=log_level,
            format=log_config.get("format", "%(asctime)s - %(name)s - %(levelname)s - %(message)s"),
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler() if log_config.get("console_output", True) else logging.NullHandler()
            ]
        )
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key (supports dot notation)"""
        keys = key.split('.')
        value = self.config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any) -> None:
        """Set configuration value by key (supports dot notation)"""
        keys = key.split('.')
        config = self.config
        
        # Navigate to the parent of the target key
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        # Set the value
        config[keys[-1]] = value
    
    def save(self) -> None:
        """Save configuration to file"""
        try:
            # Create directory if it doesn't exist
            config_dir = os.path.dirname(self.config_path)
            if config_dir and not os.path.exists(config_dir):
                os.makedirs(config_dir, exist_ok=True)
            
            with open(self.config_path, 'w', encoding='utf-8') as f:
                yaml.dump(self.config, f, default_flow_style=False, indent=2)
        
        except Exception as e:
            logging.error(f"Failed to save configuration: {e}")
    
    def reload(self) -> None:
        """Reload configuration from file"""
        self.config = self._load_config()
        self._setup_logging()
    
    def get_tool_config(self, tool_name: str) -> Dict[str, Any]:
        """Get configuration for a specific tool"""
        return self.config.get("tools", {}).get(tool_name, {})
    
    def get_recon_config(self, recon_type: str) -> Dict[str, Any]:
        """Get configuration for a specific reconnaissance type"""
        return self.config.get("recon", {}).get(recon_type, {})
    
    def get_exploitation_config(self, exploit_type: str) -> Dict[str, Any]:
        """Get configuration for a specific exploitation type"""
        return self.config.get("exploitation", {}).get(exploit_type, {})
    
    def get_bruteforce_config(self, bruteforce_type: str) -> Dict[str, Any]:
        """Get configuration for a specific bruteforce type"""
        return self.config.get("bruteforce", {}).get(bruteforce_type, {})
    
    def is_enabled(self, module: str, feature: str) -> bool:
        """Check if a specific feature is enabled"""
        return self.config.get(module, {}).get(feature, {}).get("enabled", True)
    
    def get_output_dir(self, target: str) -> str:
        """Get output directory for a target"""
        base_dir = self.config.get("output", {}).get("directory", "loot")
        return os.path.join(base_dir, target.replace("://", "_").replace("/", "_"))
    
    def get_log_file(self) -> str:
        """Get log file path"""
        return self.config.get("logging", {}).get("file", "logs/framework.log")
    
    def is_debug_mode(self) -> bool:
        """Check if debug mode is enabled"""
        return self.config.get("framework", {}).get("debug", False)
    
    def is_stealth_mode(self) -> bool:
        """Check if stealth mode is enabled"""
        return self.config.get("framework", {}).get("stealth_mode", True)
    
    def get_max_threads(self) -> int:
        """Get maximum number of threads"""
        return self.config.get("framework", {}).get("max_threads", 10)
    
    def get_timeout(self) -> int:
        """Get default timeout"""
        return self.config.get("framework", {}).get("timeout", 300)

def init_config(config_path: Optional[str] = None) -> ConfigManager:
    """Initialize configuration manager"""
    global _config_instance
    
    if _config_instance is None:
        _config_instance = ConfigManager(config_path)
    
    return _config_instance

def get_config() -> ConfigManager:
    """Get configuration manager instance"""
    if _config_instance is None:
        return init_config()
    return _config_instance

def get_config_value(key: str, default: Any = None) -> Any:
    """Get configuration value by key"""
    config = get_config()
    return config.get(key, default)

def set_config_value(key: str, value: Any) -> None:
    """Set configuration value by key"""
    config = get_config()
    config.set(key, value)

def save_config() -> None:
    """Save configuration to file"""
    config = get_config()
    config.save()

def reload_config() -> None:
    """Reload configuration from file"""
    config = get_config()
    config.reload() 