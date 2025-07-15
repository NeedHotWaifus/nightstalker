"""
NightStalker - Advanced Offensive Security Framework
A modular, offline-capable, AI-free, and identity-protective framework
for comprehensive security assessments and penetration testing.

Author: Security Research Team
License: MIT (for authorized security research only)
Version: 1.0.0
"""

__version__ = "1.0.0"
__author__ = "Security Research Team"
__description__ = "Advanced Offensive Security Framework"

# Core imports
from .core.automation import AttackChain

# Red Team imports
from .redteam.payload_builder import PayloadBuilder, PayloadConfig
from .redteam.polymorph import PolymorphicEngine
from .redteam.exfiltration import CovertChannels
from .redteam.infection_watchers import FileMonitor
from .redteam.self_rebuild import EnvironmentManager, EnvironmentConfig
from .redteam.fuzzer import GeneticFuzzer

# C2 imports
from .c2.stealth_c2 import StealthC2

__all__ = [
    'AttackChain',
    'GeneticFuzzer', 
    'CovertChannels',
    'FileMonitor',
    'EnvironmentManager',
    'EnvironmentConfig',
    'PayloadBuilder',
    'PayloadConfig',
    'PolymorphicEngine',
    'StealthC2'
] 