"""
NightStalker C2 Package
Command and Control infrastructure with stealth capabilities
"""

from .command_control import C2Server, C2Client
from .channels import DNSChannel, HTTPSChannel, ICMPChannel, TorDNSChannel
from .stealth import StealthManager

__all__ = [
    'C2Server',
    'C2Client', 
    'DNSChannel',
    'HTTPSChannel',
    'ICMPChannel',
    'TorDNSChannel',
    'StealthManager'
] 