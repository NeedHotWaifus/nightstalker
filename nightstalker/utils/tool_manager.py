#!/usr/bin/env python3
"""
Tool Manager for NightStalker Framework
Handles installation and verification of external security tools
"""

import os
import sys
import subprocess
import shutil
import platform
import tempfile
import requests
import zipfile
import tarfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)

class ToolManager:
    """Manages external security tools installation and verification"""
    
    def __init__(self):
        self.tools = {
            # Web exploitation tools
            'nuclei': {
                'name': 'Nuclei',
                'description': 'Fast vulnerability scanner',
                'url': 'https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_2.9.4_linux_amd64.zip',
                'windows_url': 'https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_2.9.4_windows_amd64.zip',
                'install_path': '/usr/local/bin/nuclei',
                'windows_path': 'C:\\Tools\\nuclei.exe',
                'check_cmd': ['nuclei', '-version'],
                'required': True
            },
            'sqlmap': {
                'name': 'SQLMap',
                'description': 'SQL injection automation tool',
                'url': 'https://github.com/sqlmapproject/sqlmap/archive/refs/heads/master.zip',
                'install_path': '/opt/sqlmap',
                'windows_path': 'C:\\Tools\\sqlmap',
                'check_cmd': ['python3', '/opt/sqlmap/sqlmap.py', '--version'],
                'windows_check_cmd': ['python', 'C:\\Tools\\sqlmap\\sqlmap.py', '--version'],
                'required': True
            },
            'ffuf': {
                'name': 'ffuf',
                'description': 'Fast web fuzzer',
                'url': 'https://github.com/ffuf/ffuf/releases/latest/download/ffuf_1.5.0_linux_amd64.tar.gz',
                'windows_url': 'https://github.com/ffuf/ffuf/releases/latest/download/ffuf_1.5.0_windows_amd64.zip',
                'install_path': '/usr/local/bin/ffuf',
                'windows_path': 'C:\\Tools\\ffuf.exe',
                'check_cmd': ['ffuf', '-version'],
                'required': True
            },
            'amass': {
                'name': 'Amass',
                'description': 'Network reconnaissance tool',
                'url': 'https://github.com/owasp-amass/amass/releases/latest/download/amass_linux_amd64.zip',
                'windows_url': 'https://github.com/owasp-amass/amass/releases/latest/download/amass_windows_amd64.zip',
                'install_path': '/usr/local/bin/amass',
                'windows_path': 'C:\\Tools\\amass.exe',
                'check_cmd': ['amass', 'version'],
                'required': False
            },
            'nmap': {
                'name': 'Nmap',
                'description': 'Network discovery and security auditing',
                'install_cmd': ['apt-get', 'install', '-y', 'nmap'],
                'windows_install_cmd': ['choco', 'install', 'nmap'],
                'check_cmd': ['nmap', '--version'],
                'required': True
            },
            'msfconsole': {
                'name': 'Metasploit Framework',
                'description': 'Penetration testing framework',
                'install_cmd': ['apt-get', 'install', '-y', 'metasploit-framework'],
                'windows_install_cmd': ['choco', 'install', 'metasploit'],
                'check_cmd': ['msfconsole', '--version'],
                'required': False
            },
            'curl': {
                'name': 'cURL',
                'description': 'Command line tool for transferring data',
                'install_cmd': ['apt-get', 'install', '-y', 'curl'],
                'windows_install_cmd': ['choco', 'install', 'curl'],
                'check_cmd': ['curl', '--version'],
                'required': True
            },
            'wget': {
                'name': 'Wget',
                'description': 'Network utility to retrieve files',
                'install_cmd': ['apt-get', 'install', '-y', 'wget'],
                'windows_install_cmd': ['choco', 'install', 'wget'],
                'check_cmd': ['wget', '--version'],
                'required': True
            },
            'nc': {
                'name': 'Netcat',
                'description': 'Network utility for reading/writing network connections',
                'install_cmd': ['apt-get', 'install', '-y', 'netcat'],
                'windows_install_cmd': ['choco', 'install', 'netcat'],
                'check_cmd': ['nc', '-h'],
                'required': True
            },
            'socat': {
                'name': 'Socat',
                'description': 'Multipurpose relay for bidirectional data transfer',
                'install_cmd': ['apt-get', 'install', '-y', 'socat'],
                'windows_install_cmd': ['choco', 'install', 'socat'],
                'check_cmd': ['socat', '-h'],
                'required': False
            },
            'bluetooth-sendto': {
                'name': 'Bluetooth Send To',
                'description': 'Bluetooth file transfer utility',
                'install_cmd': ['apt-get', 'install', '-y', 'bluetooth'],
                'check_cmd': ['bluetooth-sendto', '--help'],
                'required': False
            },
            'obexftp': {
                'name': 'OBEX FTP',
                'description': 'OBEX file transfer utility',
                'install_cmd': ['apt-get', 'install', '-y', 'obexftp'],
                'check_cmd': ['obexftp', '--help'],
                'required': False
            },
            'smbclient': {
                'name': 'SMB Client',
                'description': 'SMB/CIFS client',
                'install_cmd': ['apt-get', 'install', '-y', 'smbclient'],
                'windows_install_cmd': ['choco', 'install', 'smbclient'],
                'check_cmd': ['smbclient', '--help'],
                'required': False
            },
            'paramiko': {
                'name': 'Paramiko',
                'description': 'SSH protocol implementation',
                'install_cmd': ['pip3', 'install', 'paramiko'],
                'check_cmd': ['python3', '-c', 'import paramiko; print(paramiko.__version__)'],
                'required': False
            },
            'psutil': {
                'name': 'psutil',
                'description': 'Cross-platform library for process and system monitoring',
                'install_cmd': ['pip3', 'install', 'psutil'],
                'check_cmd': ['python3', '-c', 'import psutil; print(psutil.__version__)'],
                'required': False
            }
        }
        
        self.is_windows = platform.system().lower() == 'windows'
        self.tools_dir = Path('C:\\Tools') if self.is_windows else Path('/opt/tools')
        
    def is_tool_installed(self, tool_name: str) -> bool:
        """Check if a tool is installed and accessible"""
        if tool_name not in self.tools:
            logger.warning(f"Unknown tool: {tool_name}")
            return False
        
        tool = self.tools[tool_name]
        
        # Check if tool exists in PATH
        if shutil.which(tool_name):
            return True
        
        # Check specific installation paths
        if self.is_windows and 'windows_path' in tool:
            return Path(tool['windows_path']).exists()
        elif 'install_path' in tool:
            return Path(tool['install_path']).exists()
        
        return False
    
    def install_tool(self, tool_name: str, force: bool = False) -> bool:
        """Install a tool"""
        if tool_name not in self.tools:
            logger.error(f"Unknown tool: {tool_name}")
            return False
        
        if not force and self.is_tool_installed(tool_name):
            logger.info(f"Tool {tool_name} is already installed")
            return True
        
        tool = self.tools[tool_name]
        logger.info(f"Installing {tool['name']}...")
        
        try:
            # Create tools directory if it doesn't exist
            if self.is_windows:
                self.tools_dir.mkdir(exist_ok=True)
            else:
                os.makedirs('/opt/tools', exist_ok=True)
            
            # Install based on method
            if 'install_cmd' in tool:
                return self._install_via_package_manager(tool, tool_name)
            elif 'url' in tool:
                return self._install_via_download(tool, tool_name)
            else:
                logger.error(f"No installation method defined for {tool_name}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to install {tool_name}: {e}")
            return False
    
    def _install_via_package_manager(self, tool: Dict, tool_name: str) -> bool:
        """Install tool via package manager"""
        try:
            if self.is_windows:
                cmd = tool.get('windows_install_cmd', tool['install_cmd'])
            else:
                cmd = tool['install_cmd']
            
            # Check if we have sudo/admin privileges
            if not self.is_windows and os.geteuid() != 0:
                cmd = ['sudo'] + cmd
            
            logger.info(f"Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                logger.info(f"Successfully installed {tool_name}")
                return True
            else:
                logger.error(f"Failed to install {tool_name}: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Package manager installation failed for {tool_name}: {e}")
            return False
    
    def _install_via_download(self, tool: Dict, tool_name: str) -> bool:
        """Install tool via direct download"""
        try:
            # Determine download URL
            if self.is_windows and 'windows_url' in tool:
                url = tool['windows_url']
            else:
                url = tool['url']
            
            # Download file
            logger.info(f"Downloading {tool_name} from {url}")
            response = requests.get(url, stream=True)
            response.raise_for_status()
            
            # Create temporary file
            with tempfile.NamedTemporaryFile(delete=False, suffix='.tmp') as tmp_file:
                for chunk in response.iter_content(chunk_size=8192):
                    tmp_file.write(chunk)
                tmp_file_path = tmp_file.name
            
            try:
                # Extract and install
                if url.endswith('.zip'):
                    return self._extract_zip(tmp_file_path, tool, tool_name)
                elif url.endswith('.tar.gz'):
                    return self._extract_targz(tmp_file_path, tool, tool_name)
                else:
                    logger.error(f"Unsupported file format for {tool_name}")
                    return False
                    
            finally:
                # Clean up temporary file
                try:
                    os.unlink(tmp_file_path)
                except:
                    pass
                    
        except Exception as e:
            logger.error(f"Download installation failed for {tool_name}: {e}")
            return False
    
    def _extract_zip(self, file_path: str, tool: Dict, tool_name: str) -> bool:
        """Extract and install ZIP file"""
        try:
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                # Extract to temporary directory
                with tempfile.TemporaryDirectory() as temp_dir:
                    zip_ref.extractall(temp_dir)
                    
                    # Find the executable
                    executable = None
                    for root, dirs, files in os.walk(temp_dir):
                        for file in files:
                            if file == tool_name or file == f"{tool_name}.exe":
                                executable = os.path.join(root, file)
                                break
                        if executable:
                            break
                    
                    if not executable:
                        logger.error(f"Could not find executable for {tool_name}")
                        return False
                    
                    # Install to target location
                    if self.is_windows:
                        target_path = tool.get('windows_path', str(self.tools_dir / f"{tool_name}.exe"))
                    else:
                        target_path = tool.get('install_path', f"/usr/local/bin/{tool_name}")
                    
                    # Copy executable
                    shutil.copy2(executable, target_path)
                    
                    # Make executable (Unix only)
                    if not self.is_windows:
                        os.chmod(target_path, 0o755)
                    
                    logger.info(f"Successfully installed {tool_name} to {target_path}")
                    return True
                    
        except Exception as e:
            logger.error(f"ZIP extraction failed for {tool_name}: {e}")
            return False
    
    def _extract_targz(self, file_path: str, tool: Dict, tool_name: str) -> bool:
        """Extract and install TAR.GZ file"""
        try:
            with tarfile.open(file_path, 'r:gz') as tar_ref:
                # Extract to temporary directory
                with tempfile.TemporaryDirectory() as temp_dir:
                    tar_ref.extractall(temp_dir)
                    
                    # Find the executable
                    executable = None
                    for root, dirs, files in os.walk(temp_dir):
                        for file in files:
                            if file == tool_name:
                                executable = os.path.join(root, file)
                                break
                        if executable:
                            break
                    
                    if not executable:
                        logger.error(f"Could not find executable for {tool_name}")
                        return False
                    
                    # Install to target location
                    target_path = tool.get('install_path', f"/usr/local/bin/{tool_name}")
                    
                    # Copy executable
                    shutil.copy2(executable, target_path)
                    
                    # Make executable
                    os.chmod(target_path, 0o755)
                    
                    logger.info(f"Successfully installed {tool_name} to {target_path}")
                    return True
                    
        except Exception as e:
            logger.error(f"TAR.GZ extraction failed for {tool_name}: {e}")
            return False
    
    def verify_tool(self, tool_name: str) -> bool:
        """Verify that a tool is working correctly"""
        if not self.is_tool_installed(tool_name):
            logger.warning(f"Tool {tool_name} is not installed")
            return False
        
        if tool_name not in self.tools:
            logger.warning(f"Unknown tool: {tool_name}")
            return False
        
        tool = self.tools[tool_name]
        
        try:
            # Run verification command
            if self.is_windows and 'windows_check_cmd' in tool:
                cmd = tool['windows_check_cmd']
            else:
                cmd = tool['check_cmd']
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                logger.info(f"Tool {tool_name} verified successfully")
                return True
            else:
                logger.warning(f"Tool {tool_name} verification failed: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Tool verification failed for {tool_name}: {e}")
            return False
    
    def install_required_tools(self) -> Dict[str, bool]:
        """Install all required tools"""
        results = {}
        
        for tool_name, tool in self.tools.items():
            if tool.get('required', False):
                logger.info(f"Checking required tool: {tool_name}")
                if not self.is_tool_installed(tool_name):
                    logger.info(f"Installing required tool: {tool_name}")
                    results[tool_name] = self.install_tool(tool_name)
                else:
                    results[tool_name] = True
        
        return results
    
    def list_installed_tools(self) -> List[str]:
        """List all installed tools"""
        installed = []
        
        for tool_name in self.tools:
            if self.is_tool_installed(tool_name):
                installed.append(tool_name)
        
        return installed
    
    def get_tool_info(self, tool_name: str) -> Optional[Dict]:
        """Get information about a tool"""
        if tool_name in self.tools:
            tool_info = self.tools[tool_name].copy()
            tool_info['installed'] = self.is_tool_installed(tool_name)
            tool_info['working'] = self.verify_tool(tool_name) if tool_info['installed'] else False
            return tool_info
        return None
    
    def cleanup_tools(self):
        """Clean up temporary files and directories"""
        try:
            # Clean up temporary files
            temp_dir = tempfile.gettempdir()
            for file in os.listdir(temp_dir):
                if file.startswith('nightstalker_') and file.endswith('.tmp'):
                    try:
                        os.unlink(os.path.join(temp_dir, file))
                    except:
                        pass
        except Exception as e:
            logger.error(f"Tool cleanup failed: {e}")

    @staticmethod
    def check_and_install_tools(tool_names, logger=None):
        """Check and install a list of tools, logging results"""
        tm = ToolManager()
        results = {}
        for tool in tool_names:
            if tm.is_tool_installed(tool):
                if logger:
                    logger.info(f"Tool {tool} is already installed.")
                results[tool] = True
            else:
                if logger:
                    logger.info(f"Tool {tool} not found. Installing...")
                results[tool] = tm.install_tool(tool)
        return results

# Global tool manager instance
_tool_manager = None

def get_tool_manager() -> ToolManager:
    """Get the global tool manager instance"""
    global _tool_manager
    if _tool_manager is None:
        _tool_manager = ToolManager()
    return _tool_manager

def is_tool_installed(tool_name: str) -> bool:
    """Check if a tool is installed"""
    return get_tool_manager().is_tool_installed(tool_name)

def install_tool(tool_name: str, force: bool = False) -> bool:
    """Install a tool"""
    return get_tool_manager().install_tool(tool_name, force)

def verify_tool(tool_name: str) -> bool:
    """Verify a tool is working"""
    return get_tool_manager().verify_tool(tool_name)

if __name__ == "__main__":
    # Test the tool manager
    manager = ToolManager()
    
    print("Installing required tools...")
    results = manager.install_required_tools()
    
    print("\nInstallation results:")
    for tool, success in results.items():
        status = "✓" if success else "✗"
        print(f"{status} {tool}")
    
    print(f"\nInstalled tools: {manager.list_installed_tools()}") 