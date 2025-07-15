"""
Red Team modules for NightStalker framework
Contains offensive security tools and payloads
"""

from .payload_builder import PayloadBuilder, PayloadConfig
from .polymorph import PolymorphicEngine
from .exfiltration import CovertChannels
from .infection_watchers import FileMonitor
from .self_rebuild import EnvironmentManager, EnvironmentConfig
from .fuzzer import GeneticFuzzer

# C2 imports
from .c2.command_control import C2Server, C2Client
from .c2.channels import DNSChannel, HTTPSChannel, ICMPChannel, TorDNSChannel
from .c2.stealth import StealthManager

__all__ = [
    'PayloadBuilder',
    'PayloadConfig',
    'PolymorphicEngine',
    'CovertChannels',
    'FileMonitor',
    'EnvironmentManager',
    'EnvironmentConfig',
    'GeneticFuzzer',
    'C2Server',
    'C2Client',
    'DNSChannel',
    'HTTPSChannel',
    'ICMPChannel',
    'TorDNSChannel',
    'StealthManager'
] 