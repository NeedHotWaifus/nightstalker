#!/usr/bin/env python3
"""
NightStalker Stealth Crypto - Covert encryption for C2 communications
"""

import os
import base64
import hashlib
import hmac
import secrets
import json
from typing import Optional, Dict, Any
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class StealthCrypto:
    """Stealth encryption for C2 communications"""
    
    def __init__(self, key: Optional[bytes] = None):
        self.key = key or self._generate_key()
        self.fernet = Fernet(self.key)
        self.backend = default_backend()
    
    def _generate_key(self) -> bytes:
        """Generate encryption key"""
        return Fernet.generate_key()
    
    def encrypt(self, data: str) -> bytes:
        """Encrypt data with multiple layers"""
        try:
            # Convert string to bytes
            if isinstance(data, str):
                data_bytes = data.encode('utf-8')
            else:
                data_bytes = data
            
            # Layer 1: Fernet encryption
            encrypted = self.fernet.encrypt(data_bytes)
            
            # Layer 2: Add random padding
            padding = secrets.token_bytes(16)
            encrypted_with_padding = padding + encrypted
            
            # Layer 3: XOR with random key
            xor_key = secrets.token_bytes(len(encrypted_with_padding))
            xored = bytes(a ^ b for a, b in zip(encrypted_with_padding, xor_key))
            
            # Layer 4: Base64 encoding with custom alphabet
            encoded = self._custom_base64_encode(xored)
            
            return encoded.encode('utf-8')
            
        except Exception as e:
            raise Exception(f"Encryption failed: {e}")
    
    def decrypt(self, encrypted_data: bytes) -> str:
        """Decrypt data with multiple layers"""
        try:
            # Layer 4: Custom base64 decode
            if isinstance(encrypted_data, bytes):
                decoded = self._custom_base64_decode(encrypted_data.decode('utf-8'))
            else:
                decoded = self._custom_base64_decode(encrypted_data)
            
            # Layer 3: XOR with key (extract from first 16 bytes)
            padding = decoded[:16]
            encrypted_with_padding = decoded[16:]
            
            # Reconstruct XOR key (this is a simplified approach)
            # In practice, you'd need to store/transmit the XOR key securely
            xor_key = hashlib.sha256(padding).digest()[:len(encrypted_with_padding)]
            xored = bytes(a ^ b for a, b in zip(encrypted_with_padding, xor_key))
            
            # Layer 2: Remove padding
            encrypted = xored[16:]
            
            # Layer 1: Fernet decryption
            decrypted = self.fernet.decrypt(encrypted)
            
            return decrypted.decode('utf-8')
            
        except Exception as e:
            raise Exception(f"Decryption failed: {e}")
    
    def _custom_base64_encode(self, data: bytes) -> str:
        """Custom base64 encoding with different alphabet"""
        # Use URL-safe base64 but with custom characters
        encoded = base64.urlsafe_b64encode(data).decode('utf-8')
        # Replace some characters to make it less recognizable
        encoded = encoded.replace('-', 'x').replace('_', 'y')
        return encoded
    
    def _custom_base64_decode(self, data: str) -> bytes:
        """Custom base64 decoding"""
        # Restore original characters
        data = data.replace('x', '-').replace('y', '_')
        return base64.urlsafe_b64decode(data)
    
    def encrypt_file(self, file_path: str, output_path: Optional[str] = None) -> str:
        """Encrypt a file"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            encrypted = self.encrypt(data)
            
            if not output_path:
                output_path = file_path + '.encrypted'
            
            with open(output_path, 'wb') as f:
                f.write(encrypted)
            
            return output_path
            
        except Exception as e:
            raise Exception(f"File encryption failed: {e}")
    
    def decrypt_file(self, file_path: str, output_path: Optional[str] = None) -> str:
        """Decrypt a file"""
        try:
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            
            decrypted = self.decrypt(encrypted_data)
            
            if not output_path:
                output_path = file_path.replace('.encrypted', '.decrypted')
            
            with open(output_path, 'wb') as f:
                f.write(decrypted.encode('utf-8') if isinstance(decrypted, str) else decrypted)
            
            return output_path
            
        except Exception as e:
            raise Exception(f"File decryption failed: {e}")
    
    def generate_stealth_key(self, password: str, salt: Optional[bytes] = None) -> bytes:
        """Generate stealth key from password"""
        if not salt:
            salt = secrets.token_bytes(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def encrypt_with_password(self, data: str, password: str) -> Dict[str, Any]:
        """Encrypt data with password-based key"""
        salt = secrets.token_bytes(16)
        key = self.generate_stealth_key(password, salt)
        
        # Create temporary crypto instance
        temp_crypto = StealthCrypto(key)
        encrypted = temp_crypto.encrypt(data)
        
        return {
            'encrypted': base64.b64encode(encrypted).decode(),
            'salt': base64.b64encode(salt).decode()
        }
    
    def decrypt_with_password(self, encrypted_data: Dict[str, Any], password: str) -> str:
        """Decrypt data with password-based key"""
        salt = base64.b64decode(encrypted_data['salt'])
        encrypted = base64.b64decode(encrypted_data['encrypted'])
        
        key = self.generate_stealth_key(password, salt)
        temp_crypto = StealthCrypto(key)
        
        return temp_crypto.decrypt(encrypted)
    
    def create_stealth_container(self, data: str, container_type: str = 'image') -> bytes:
        """Create stealth container (steganography-like)"""
        if container_type == 'image':
            return self._create_image_container(data)
        elif container_type == 'text':
            return self._create_text_container(data)
        else:
            raise ValueError(f"Unknown container type: {container_type}")
    
    def _create_image_container(self, data: str) -> bytes:
        """Create image container with hidden data"""
        # Simple approach: create a minimal PNG with hidden data
        # In practice, you'd use proper steganography libraries
        
        # Create a 1x1 pixel PNG
        png_header = b'\x89PNG\r\n\x1a\n'
        ihdr = b'\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde'
        idat = b'\x00\x00\x00\x0cIDATx\x9cc\xf8\xff\xff?\x00\x05\xfe\x02\xfe\xdc\xccY\xe7\x00\x00\x00\x00IEND\xaeB`\x82'
        
        # Hide encrypted data in IDAT chunk
        encrypted = self.encrypt(data)
        hidden_data = base64.b64encode(encrypted).decode()
        
        # Create custom IDAT with hidden data
        custom_idat = f'IDAT{hidden_data}'.encode()
        
        return png_header + ihdr + custom_idat + idat
    
    def _create_text_container(self, data: str) -> bytes:
        """Create text container with hidden data"""
        # Hide data in seemingly normal text
        encrypted = self.encrypt(data)
        hidden = base64.b64encode(encrypted).decode()
        
        # Create innocent-looking text
        container = f"""
Dear Colleague,

I hope this message finds you well. I wanted to share some important information 
regarding our recent project updates.

Project Status: {hidden[:20]}...
Completion Date: {hidden[20:40]}...
Team Notes: {hidden[40:60]}...

Please review and let me know if you have any questions.

Best regards,
Project Management Team
"""
        
        return container.encode('utf-8')
    
    def extract_from_container(self, container_data: bytes, container_type: str = 'image') -> str:
        """Extract data from stealth container"""
        if container_type == 'image':
            return self._extract_from_image_container(container_data)
        elif container_type == 'text':
            return self._extract_from_text_container(container_data)
        else:
            raise ValueError(f"Unknown container type: {container_type}")
    
    def _extract_from_image_container(self, container_data: bytes) -> str:
        """Extract data from image container"""
        try:
            # Find IDAT chunk and extract hidden data
            idat_start = container_data.find(b'IDAT')
            if idat_start == -1:
                raise Exception("No IDAT chunk found")
            
            # Extract hidden data (simplified)
            hidden_data = container_data[idat_start+4:].decode('utf-8', errors='ignore')
            encrypted = base64.b64decode(hidden_data)
            
            return self.decrypt(encrypted)
            
        except Exception as e:
            raise Exception(f"Failed to extract from image container: {e}")
    
    def _extract_from_text_container(self, container_data: bytes) -> str:
        """Extract data from text container"""
        try:
            text = container_data.decode('utf-8')
            
            # Extract hidden data from text
            import re
            matches = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text)
            
            if not matches:
                raise Exception("No hidden data found in text")
            
            # Combine all matches
            hidden_data = ''.join(matches)
            encrypted = base64.b64decode(hidden_data)
            
            return self.decrypt(encrypted)
            
        except Exception as e:
            raise Exception(f"Failed to extract from text container: {e}")
    
    def get_key_hash(self) -> str:
        """Get hash of current encryption key"""
        return hashlib.sha256(self.key).hexdigest()
    
    def export_key(self, password: str) -> Dict[str, str]:
        """Export encrypted key"""
        key_data = {
            'key': base64.b64encode(self.key).decode(),
            'timestamp': str(int(time.time())),
            'version': '1.0'
        }
        
        return self.encrypt_with_password(json.dumps(key_data), password)
    
    def import_key(self, key_data: Dict[str, str], password: str) -> bool:
        """Import encrypted key"""
        try:
            decrypted_data = self.decrypt_with_password(key_data, password)
            key_info = json.loads(decrypted_data)
            
            self.key = base64.b64decode(key_info['key'])
            self.fernet = Fernet(self.key)
            
            return True
            
        except Exception as e:
            raise Exception(f"Failed to import key: {e}")


def main():
    """CLI for crypto operations"""
    import argparse
    
    parser = argparse.ArgumentParser(description='NightStalker Stealth Crypto')
    parser.add_argument('--encrypt', help='Encrypt file or string')
    parser.add_argument('--decrypt', help='Decrypt file or string')
    parser.add_argument('--file', action='store_true', help='Treat input as file path')
    parser.add_argument('--password', help='Password for encryption/decryption')
    parser.add_argument('--container', choices=['image', 'text'], help='Create stealth container')
    parser.add_argument('--extract', help='Extract from container')
    
    args = parser.parse_args()
    
    crypto = StealthCrypto()
    
    if args.encrypt:
        if args.file:
            output = crypto.encrypt_file(args.encrypt)
            print(f"File encrypted: {output}")
        else:
            encrypted = crypto.encrypt(args.encrypt)
            print(f"Encrypted: {base64.b64encode(encrypted).decode()}")
    
    elif args.decrypt:
        if args.file:
            output = crypto.decrypt_file(args.decrypt)
            print(f"File decrypted: {output}")
        else:
            decrypted = crypto.decrypt(base64.b64decode(args.decrypt))
            print(f"Decrypted: {decrypted}")
    
    elif args.container:
        if not args.encrypt:
            print("Error: --encrypt required for container creation")
            return 1
        
        container = crypto.create_stealth_container(args.encrypt, args.container)
        output_file = f"container.{args.container}"
        
        with open(output_file, 'wb') as f:
            f.write(container)
        
        print(f"Container created: {output_file}")
    
    elif args.extract:
        with open(args.extract, 'rb') as f:
            container_data = f.read()
        
        extracted = crypto.extract_from_container(container_data)
        print(f"Extracted: {extracted}")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    import time
    main() 