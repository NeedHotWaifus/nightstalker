#!/usr/bin/env python3
"""
Utility Functions for NightStalker WebXF
Common utilities used across the framework
"""

import os
import sys
import platform
import socket
import hashlib
import base64
import json
import yaml
import re
import random
import string
import time
import threading
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Tuple
from urllib.parse import urlparse, urljoin
import ipaddress
import subprocess
import logging

from .config import get_config

class SystemUtils:
    """System utility functions"""
    
    @staticmethod
    def get_system_info() -> Dict[str, str]:
        """Get system information"""
        return {
            "platform": platform.system(),
            "platform_version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "python_version": sys.version,
            "hostname": socket.gethostname(),
            "username": os.getenv("USER", os.getenv("USERNAME", "unknown"))
        }
    
    @staticmethod
    def is_windows() -> bool:
        """Check if running on Windows"""
        return platform.system().lower() == "windows"
    
    @staticmethod
    def is_linux() -> bool:
        """Check if running on Linux"""
        return platform.system().lower() == "linux"
    
    @staticmethod
    def is_macos() -> bool:
        """Check if running on macOS"""
        return platform.system().lower() == "darwin"
    
    @staticmethod
    def is_root() -> bool:
        """Check if running as root/administrator"""
        if SystemUtils.is_windows():
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin()
            except:
                return False
        else:
            return os.geteuid() == 0
    
    @staticmethod
    def get_temp_dir() -> str:
        """Get temporary directory path"""
        return os.path.join(os.getcwd(), "temp")
    
    @staticmethod
    def create_temp_dir() -> str:
        """Create and return temporary directory"""
        temp_dir = SystemUtils.get_temp_dir()
        os.makedirs(temp_dir, exist_ok=True)
        return temp_dir
    
    @staticmethod
    def cleanup_temp_dir() -> None:
        """Clean up temporary directory"""
        temp_dir = SystemUtils.get_temp_dir()
        if os.path.exists(temp_dir):
            import shutil
            shutil.rmtree(temp_dir)
    
    @staticmethod
    def get_file_size(file_path: str) -> int:
        """Get file size in bytes"""
        try:
            return os.path.getsize(file_path)
        except OSError:
            return 0
    
    @staticmethod
    def is_file_readable(file_path: str) -> bool:
        """Check if file is readable"""
        return os.path.isfile(file_path) and os.access(file_path, os.R_OK)
    
    @staticmethod
    def is_file_writable(file_path: str) -> bool:
        """Check if file is writable"""
        return os.access(os.path.dirname(file_path), os.W_OK)
    
    @staticmethod
    def ensure_dir_exists(dir_path: str) -> None:
        """Ensure directory exists, create if necessary"""
        os.makedirs(dir_path, exist_ok=True)
    
    @staticmethod
    def get_file_hash(file_path: str, algorithm: str = "sha256") -> Optional[str]:
        """Calculate file hash"""
        try:
            hash_func = hashlib.new(algorithm)
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except Exception:
            return None

class NetworkUtils:
    """Network utility functions"""
    
    @staticmethod
    def is_valid_ip(ip: str) -> bool:
        """Check if string is a valid IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_valid_ip_range(ip_range: str) -> bool:
        """Check if string is a valid IP range"""
        try:
            ipaddress.ip_network(ip_range, strict=False)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def is_valid_domain(domain: str) -> bool:
        """Check if string is a valid domain name"""
        if not domain or len(domain) > 253:
            return False
        
        # Check for valid characters
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', domain):
            return False
        
        return True
    
    @staticmethod
    def is_valid_url(url: str) -> bool:
        """Check if string is a valid URL"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    @staticmethod
    def resolve_domain(domain: str) -> List[str]:
        """Resolve domain to IP addresses"""
        try:
            return [str(addr[4][0]) for addr in socket.getaddrinfo(domain, None)]
        except socket.gaierror:
            return []
    
    @staticmethod
    def reverse_dns_lookup(ip: str) -> Optional[str]:
        """Perform reverse DNS lookup"""
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return None
    
    @staticmethod
    def is_port_open(host: str, port: int, timeout: float = 1.0) -> bool:
        """Check if port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    @staticmethod
    def get_common_ports() -> List[int]:
        """Get list of common ports"""
        return [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 5432, 8080, 8443]
    
    @staticmethod
    def scan_ports(host: str, ports: List[int], timeout: float = 1.0) -> Dict[int, bool]:
        """Scan multiple ports on a host"""
        results = {}
        for port in ports:
            results[port] = NetworkUtils.is_port_open(host, port, timeout)
        return results
    
    @staticmethod
    def get_local_ip() -> str:
        """Get local IP address"""
        try:
            # Connect to a remote address to determine local IP
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]
            sock.close()
            return local_ip
        except Exception:
            return "127.0.0.1"
    
    @staticmethod
    def get_random_port(start: int = 1024, end: int = 65535) -> int:
        """Get a random available port"""
        while True:
            port = random.randint(start, end)
            if not NetworkUtils.is_port_open("127.0.0.1", port):
                return port

class CryptoUtils:
    """Cryptography utility functions"""
    
    @staticmethod
    def generate_random_string(length: int = 16) -> str:
        """Generate random string"""
        chars = string.ascii_letters + string.digits
        return ''.join(random.choice(chars) for _ in range(length))
    
    @staticmethod
    def generate_random_bytes(length: int = 32) -> bytes:
        """Generate random bytes"""
        return os.urandom(length)
    
    @staticmethod
    def hash_string(data: str, algorithm: str = "sha256") -> str:
        """Hash a string"""
        hash_func = hashlib.new(algorithm)
        hash_func.update(data.encode('utf-8'))
        return hash_func.hexdigest()
    
    @staticmethod
    def hash_file(file_path: str, algorithm: str = "sha256") -> Optional[str]:
        """Hash a file"""
        return SystemUtils.get_file_hash(file_path, algorithm)
    
    @staticmethod
    def base64_encode(data: Union[str, bytes]) -> str:
        """Base64 encode data"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        return base64.b64encode(data).decode('utf-8')
    
    @staticmethod
    def base64_decode(data: str) -> bytes:
        """Base64 decode data"""
        return base64.b64decode(data)
    
    @staticmethod
    def xor_encrypt(data: Union[str, bytes], key: Union[str, bytes]) -> bytes:
        """XOR encrypt/decrypt data"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        if isinstance(key, str):
            key = key.encode('utf-8')
        
        result = bytearray()
        for i, byte in enumerate(data):
            result.append(byte ^ key[i % len(key)])
        return bytes(result)

class FileUtils:
    """File utility functions"""
    
    @staticmethod
    def read_file(file_path: str, encoding: str = "utf-8") -> Optional[str]:
        """Read file content"""
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                return f.read()
        except Exception:
            return None
    
    @staticmethod
    def write_file(file_path: str, content: str, encoding: str = "utf-8") -> bool:
        """Write content to file"""
        try:
            SystemUtils.ensure_dir_exists(os.path.dirname(file_path))
            with open(file_path, 'w', encoding=encoding) as f:
                f.write(content)
            return True
        except Exception:
            return False
    
    @staticmethod
    def read_json(file_path: str) -> Optional[Dict[str, Any]]:
        """Read JSON file"""
        try:
            content = FileUtils.read_file(file_path)
            if content:
                return json.loads(content)
        except Exception:
            pass
        return None
    
    @staticmethod
    def write_json(file_path: str, data: Dict[str, Any], indent: int = 2) -> bool:
        """Write data to JSON file"""
        try:
            content = json.dumps(data, indent=indent)
            return FileUtils.write_file(file_path, content)
        except Exception:
            return False
    
    @staticmethod
    def read_yaml(file_path: str) -> Optional[Dict[str, Any]]:
        """Read YAML file"""
        try:
            content = FileUtils.read_file(file_path)
            if content:
                return yaml.safe_load(content)
        except Exception:
            pass
        return None
    
    @staticmethod
    def write_yaml(file_path: str, data: Dict[str, Any]) -> bool:
        """Write data to YAML file"""
        try:
            content = yaml.dump(data, default_flow_style=False, indent=2)
            return FileUtils.write_file(file_path, content)
        except Exception:
            return False
    
    @staticmethod
    def get_file_extension(file_path: str) -> str:
        """Get file extension"""
        return Path(file_path).suffix.lower()
    
    @staticmethod
    def get_file_name(file_path: str) -> str:
        """Get file name without extension"""
        return Path(file_path).stem
    
    @staticmethod
    def get_file_dir(file_path: str) -> str:
        """Get directory containing file"""
        return str(Path(file_path).parent)
    
    @staticmethod
    def list_files(directory: str, pattern: str = "*") -> List[str]:
        """List files in directory matching pattern"""
        try:
            return [str(f) for f in Path(directory).glob(pattern) if f.is_file()]
        except Exception:
            return []
    
    @staticmethod
    def list_directories(directory: str, pattern: str = "*") -> List[str]:
        """List directories in directory matching pattern"""
        try:
            return [str(f) for f in Path(directory).glob(pattern) if f.is_dir()]
        except Exception:
            return []

class ValidationUtils:
    """Validation utility functions"""
    
    @staticmethod
    def validate_required_fields(data: Dict[str, Any], required_fields: List[str]) -> List[str]:
        """Validate required fields in data dictionary"""
        missing_fields = []
        for field in required_fields:
            if field not in data or data[field] is None or data[field] == "":
                missing_fields.append(field)
        return missing_fields
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email address format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def validate_phone(phone: str) -> bool:
        """Validate phone number format"""
        pattern = r'^\+?[\d\s\-\(\)]{10,}$'
        return bool(re.match(pattern, phone))
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """Validate URL format"""
        return NetworkUtils.is_valid_url(url)
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename for safe filesystem usage"""
        # Remove or replace unsafe characters
        filename = re.sub(r'[<>:"/\\|?*]', '_', filename)
        # Remove leading/trailing spaces and dots
        filename = filename.strip('. ')
        # Limit length
        if len(filename) > 255:
            filename = filename[:255]
        return filename

class TimeUtils:
    """Time utility functions"""
    
    @staticmethod
    def get_timestamp() -> str:
        """Get current timestamp string"""
        return time.strftime("%Y%m%d_%H%M%S")
    
    @staticmethod
    def get_datetime() -> str:
        """Get current datetime string"""
        return time.strftime("%Y-%m-%d %H:%M:%S")
    
    @staticmethod
    def format_duration(seconds: float) -> str:
        """Format duration in human-readable format"""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f}m"
        else:
            hours = seconds / 3600
            return f"{hours:.1f}h"
    
    @staticmethod
    def sleep_with_jitter(base_time: float, jitter_percent: float = 0.1) -> None:
        """Sleep with random jitter to avoid detection"""
        jitter = base_time * jitter_percent
        sleep_time = base_time + random.uniform(-jitter, jitter)
        time.sleep(max(0, sleep_time))

class RateLimiter:
    """Rate limiter for API calls and requests"""
    
    def __init__(self, max_requests: int, time_window: float):
        """Initialize rate limiter"""
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = []
        self.lock = threading.Lock()
    
    def can_proceed(self) -> bool:
        """Check if request can proceed"""
        with self.lock:
            now = time.time()
            # Remove old requests outside time window
            self.requests = [req for req in self.requests if now - req < self.time_window]
            
            if len(self.requests) < self.max_requests:
                self.requests.append(now)
                return True
            return False
    
    def wait_if_needed(self) -> None:
        """Wait if rate limit is exceeded"""
        while not self.can_proceed():
            time.sleep(0.1)

def get_timestamp() -> str:
    """Get current timestamp"""
    return TimeUtils.get_timestamp()

def get_datetime() -> str:
    """Get current datetime"""
    return TimeUtils.get_datetime()

def create_output_dir(target: str) -> str:
    """Create output directory for target"""
    config = get_config()
    base_dir = config.get("output.directory", "loot")
    target_dir = target.replace("://", "_").replace("/", "_").replace(":", "_")
    output_dir = os.path.join(base_dir, target_dir)
    SystemUtils.ensure_dir_exists(output_dir)
    return output_dir

def save_results(target: str, results: Dict[str, Any], format: str = "json") -> str:
    """Save results to file"""
    output_dir = create_output_dir(target)
    timestamp = get_timestamp()
    
    if format.lower() == "json":
        filename = f"{target.replace('://', '_').replace('/', '_')}_{timestamp}.json"
        filepath = os.path.join(output_dir, filename)
        FileUtils.write_json(filepath, results)
    elif format.lower() == "yaml":
        filename = f"{target.replace('://', '_').replace('/', '_')}_{timestamp}.yaml"
        filepath = os.path.join(output_dir, filename)
        FileUtils.write_yaml(filepath, results)
    else:
        raise ValueError(f"Unsupported format: {format}")
    
    return filepath

def load_wordlist(file_path: str) -> List[str]:
    """Load wordlist from file"""
    try:
        content = FileUtils.read_file(file_path)
        if content:
            return [line.strip() for line in content.split('\n') if line.strip()]
    except Exception:
        pass
    return []

def chunk_list(lst: List[Any], chunk_size: int) -> List[List[Any]]:
    """Split list into chunks"""
    return [lst[i:i + chunk_size] for i in range(0, len(lst), chunk_size)]

def flatten_list(lst: List[List[Any]]) -> List[Any]:
    """Flatten nested list"""
    return [item for sublist in lst for item in sublist]

def remove_duplicates(lst: List[Any]) -> List[Any]:
    """Remove duplicates while preserving order"""
    seen = set()
    return [x for x in lst if not (x in seen or seen.add(x))] 