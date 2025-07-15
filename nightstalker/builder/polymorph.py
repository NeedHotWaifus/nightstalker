#!/usr/bin/env python3
"""
NightStalker Polymorph Engine
Handles code obfuscation and polymorphism for payloads
"""

import os
import sys
import random
import string
import base64
import hashlib
import re
from typing import Dict, List, Optional, Tuple
from pathlib import Path

from ..utils.logger import Logger
from ..utils.config import Config

class PolymorphEngine:
    """Handles code obfuscation and polymorphism for payloads"""
    
    def __init__(self):
        self.logger = Logger(__name__)
        self.config = Config()
        
        # Obfuscation techniques
        self.techniques = {
            'variable_renaming': True,
            'string_encoding': True,
            'comment_removal': True,
            'whitespace_removal': True,
            'function_renaming': True,
            'import_obfuscation': True,
            'control_flow_obfuscation': True
        }
        
        # Common variable names to obfuscate
        self.common_vars = [
            'host', 'port', 'socket', 'connection', 'payload', 'shell',
            'command', 'output', 'data', 'response', 'request', 'url',
            'file', 'path', 'name', 'key', 'value', 'config', 'settings'
        ]
        
        # Common function names to obfuscate
        self.common_functions = [
            'connect', 'send', 'receive', 'execute', 'run', 'start',
            'stop', 'init', 'setup', 'config', 'load', 'save', 'read',
            'write', 'encode', 'decode', 'encrypt', 'decrypt'
        ]
    
    def obfuscate_python_code(self, code: str, level: str = 'medium') -> str:
        """Obfuscate Python code with various techniques"""
        try:
            self.logger.info(f"Obfuscating Python code with level: {level}")
            
            # Apply techniques based on level
            if level == 'low':
                techniques = ['comment_removal', 'whitespace_removal']
            elif level == 'medium':
                techniques = ['comment_removal', 'whitespace_removal', 'variable_renaming', 'string_encoding']
            else:  # high
                techniques = list(self.techniques.keys())
            
            obfuscated_code = code
            
            for technique in techniques:
                if technique == 'comment_removal':
                    obfuscated_code = self._remove_comments(obfuscated_code)
                elif technique == 'whitespace_removal':
                    obfuscated_code = self._remove_whitespace(obfuscated_code)
                elif technique == 'variable_renaming':
                    obfuscated_code = self._rename_variables(obfuscated_code)
                elif technique == 'string_encoding':
                    obfuscated_code = self._encode_strings(obfuscated_code)
                elif technique == 'function_renaming':
                    obfuscated_code = self._rename_functions(obfuscated_code)
                elif technique == 'import_obfuscation':
                    obfuscated_code = self._obfuscate_imports(obfuscated_code)
                elif technique == 'control_flow_obfuscation':
                    obfuscated_code = self._obfuscate_control_flow(obfuscated_code)
            
            self.logger.info("Python code obfuscation completed")
            return obfuscated_code
            
        except Exception as e:
            self.logger.error(f"Failed to obfuscate Python code: {e}")
            return code
    
    def obfuscate_shell_code(self, code: str, level: str = 'medium') -> str:
        """Obfuscate shell script code"""
        try:
            self.logger.info(f"Obfuscating shell code with level: {level}")
            
            obfuscated_code = code
            
            # Variable renaming
            if level in ['medium', 'high']:
                obfuscated_code = self._rename_shell_variables(obfuscated_code)
            
            # String encoding
            if level in ['medium', 'high']:
                obfuscated_code = self._encode_shell_strings(obfuscated_code)
            
            # Comment removal
            obfuscated_code = self._remove_shell_comments(obfuscated_code)
            
            self.logger.info("Shell code obfuscation completed")
            return obfuscated_code
            
        except Exception as e:
            self.logger.error(f"Failed to obfuscate shell code: {e}")
            return code
    
    def obfuscate_powershell_code(self, code: str, level: str = 'medium') -> str:
        """Obfuscate PowerShell code"""
        try:
            self.logger.info(f"Obfuscating PowerShell code with level: {level}")
            
            obfuscated_code = code
            
            # Variable renaming
            if level in ['medium', 'high']:
                obfuscated_code = self._rename_powershell_variables(obfuscated_code)
            
            # String encoding
            if level in ['medium', 'high']:
                obfuscated_code = self._encode_powershell_strings(obfuscated_code)
            
            # Comment removal
            obfuscated_code = self._remove_powershell_comments(obfuscated_code)
            
            self.logger.info("PowerShell code obfuscation completed")
            return obfuscated_code
            
        except Exception as e:
            self.logger.error(f"Failed to obfuscate PowerShell code: {e}")
            return code
    
    def _remove_comments(self, code: str) -> str:
        """Remove Python comments"""
        # Remove single-line comments
        lines = code.split('\n')
        cleaned_lines = []
        
        for line in lines:
            # Skip lines that are only comments
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            
            # Remove inline comments
            if '#' in line:
                comment_pos = line.find('#')
                # Check if # is in a string
                in_string = False
                string_char = None
                
                for i, char in enumerate(line[:comment_pos]):
                    if char in ['"', "'"]:
                        if not in_string:
                            in_string = True
                            string_char = char
                        elif char == string_char:
                            in_string = False
                
                if not in_string:
                    line = line[:comment_pos].rstrip()
            
            cleaned_lines.append(line)
        
        return '\n'.join(cleaned_lines)
    
    def _remove_whitespace(self, code: str) -> str:
        """Remove unnecessary whitespace"""
        # Remove empty lines
        lines = [line for line in code.split('\n') if line.strip()]
        
        # Remove trailing whitespace
        lines = [line.rstrip() for line in lines]
        
        return '\n'.join(lines)
    
    def _rename_variables(self, code: str) -> str:
        """Rename variables to obfuscate code"""
        # Simple variable renaming - in a real implementation, you'd use AST parsing
        var_mapping = {}
        
        for var in self.common_vars:
            if var in code:
                new_name = ''.join(random.choices(string.ascii_lowercase, k=8))
                var_mapping[var] = new_name
        
        # Apply replacements
        for old_name, new_name in var_mapping.items():
            # Use word boundaries to avoid partial matches
            pattern = r'\b' + re.escape(old_name) + r'\b'
            code = re.sub(pattern, new_name, code)
        
        return code
    
    def _encode_strings(self, code: str) -> str:
        """Encode string literals"""
        # Find string literals and encode some of them
        string_pattern = r'["\']([^"\']*)["\']'
        
        def encode_match(match):
            string_content = match.group(1)
            # Only encode strings that might be sensitive
            sensitive_patterns = ['http://', 'https://', 'cmd.exe', 'powershell.exe', '127.0.0.1']
            
            for pattern in sensitive_patterns:
                if pattern in string_content:
                    encoded = base64.b64encode(string_content.encode()).decode()
                    return f'base64.b64decode("{encoded}").decode()'
            
            return match.group(0)
        
        return re.sub(string_pattern, encode_match, code)
    
    def _rename_functions(self, code: str) -> str:
        """Rename function names"""
        # Simple function renaming - in a real implementation, you'd use AST parsing
        func_mapping = {}
        
        for func in self.common_functions:
            if func in code:
                new_name = ''.join(random.choices(string.ascii_lowercase, k=8))
                func_mapping[func] = new_name
        
        # Apply replacements
        for old_name, new_name in func_mapping.items():
            pattern = r'\b' + re.escape(old_name) + r'\b'
            code = re.sub(pattern, new_name, code)
        
        return code
    
    def _obfuscate_imports(self, code: str) -> str:
        """Obfuscate import statements"""
        # Convert direct imports to dynamic imports
        import_pattern = r'import\s+([a-zA-Z_][a-zA-Z0-9_]*)'
        
        def obfuscate_import(match):
            module_name = match.group(1)
            var_name = ''.join(random.choices(string.ascii_lowercase, k=6))
            return f'{var_name} = __import__("{module_name}")'
        
        return re.sub(import_pattern, obfuscate_import, code)
    
    def _obfuscate_control_flow(self, code: str) -> str:
        """Obfuscate control flow with dummy conditions"""
        # Add dummy if statements around code blocks
        lines = code.split('\n')
        obfuscated_lines = []
        
        for line in lines:
            if line.strip() and not line.strip().startswith('#'):
                # Add dummy condition around non-empty lines
                dummy_var = ''.join(random.choices(string.ascii_lowercase, k=4))
                obfuscated_lines.append(f'if True:  # {dummy_var}')
                obfuscated_lines.append(f'    {line}')
            else:
                obfuscated_lines.append(line)
        
        return '\n'.join(obfuscated_lines)
    
    def _rename_shell_variables(self, code: str) -> str:
        """Rename shell variables"""
        var_mapping = {}
        
        for var in self.common_vars:
            if var in code:
                new_name = ''.join(random.choices(string.ascii_uppercase, k=8))
                var_mapping[var] = new_name
        
        for old_name, new_name in var_mapping.items():
            pattern = r'\$' + re.escape(old_name) + r'\b'
            code = re.sub(pattern, f'${new_name}', code)
        
        return code
    
    def _encode_shell_strings(self, code: str) -> str:
        """Encode shell strings"""
        string_pattern = r'["\']([^"\']*)["\']'
        
        def encode_match(match):
            string_content = match.group(1)
            sensitive_patterns = ['http://', 'https://', '127.0.0.1']
            
            for pattern in sensitive_patterns:
                if pattern in string_content:
                    encoded = base64.b64encode(string_content.encode()).decode()
                    return f'"$(echo "{encoded}" | base64 -d)"'
            
            return match.group(0)
        
        return re.sub(string_pattern, encode_match, code)
    
    def _remove_shell_comments(self, code: str) -> str:
        """Remove shell comments"""
        lines = code.split('\n')
        cleaned_lines = []
        
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            
            if '#' in line:
                comment_pos = line.find('#')
                line = line[:comment_pos].rstrip()
            
            cleaned_lines.append(line)
        
        return '\n'.join(cleaned_lines)
    
    def _rename_powershell_variables(self, code: str) -> str:
        """Rename PowerShell variables"""
        var_mapping = {}
        
        for var in self.common_vars:
            if var in code:
                new_name = ''.join(random.choices(string.ascii_letters, k=8))
                var_mapping[var] = new_name
        
        for old_name, new_name in var_mapping.items():
            pattern = r'\$' + re.escape(old_name) + r'\b'
            code = re.sub(pattern, f'${new_name}', code)
        
        return code
    
    def _encode_powershell_strings(self, code: str) -> str:
        """Encode PowerShell strings"""
        string_pattern = r'["\']([^"\']*)["\']'
        
        def encode_match(match):
            string_content = match.group(1)
            sensitive_patterns = ['http://', 'https://', '127.0.0.1']
            
            for pattern in sensitive_patterns:
                if pattern in string_content:
                    encoded = base64.b64encode(string_content.encode()).decode()
                    return f'[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("{encoded}"))'
            
            return match.group(0)
        
        return re.sub(string_pattern, encode_match, code)
    
    def _remove_powershell_comments(self, code: str) -> str:
        """Remove PowerShell comments"""
        lines = code.split('\n')
        cleaned_lines = []
        
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('#'):
                continue
            
            if '#' in line:
                comment_pos = line.find('#')
                line = line[:comment_pos].rstrip()
            
            cleaned_lines.append(line)
        
        return '\n'.join(cleaned_lines)
    
    def generate_polymorphic_variant(self, original_code: str, language: str = 'python') -> str:
        """Generate a polymorphic variant of the code"""
        try:
            self.logger.info(f"Generating polymorphic variant for {language} code")
            
            # Apply random obfuscation techniques
            techniques = list(self.techniques.keys())
            random.shuffle(techniques)
            
            # Select random subset of techniques
            num_techniques = random.randint(2, len(techniques))
            selected_techniques = techniques[:num_techniques]
            
            obfuscated_code = original_code
            
            for technique in selected_techniques:
                if technique == 'variable_renaming':
                    obfuscated_code = self._rename_variables(obfuscated_code)
                elif technique == 'string_encoding':
                    obfuscated_code = self._encode_strings(obfuscated_code)
                elif technique == 'comment_removal':
                    obfuscated_code = self._remove_comments(obfuscated_code)
                elif technique == 'whitespace_removal':
                    obfuscated_code = self._remove_whitespace(obfuscated_code)
            
            self.logger.info("Polymorphic variant generated")
            return obfuscated_code
            
        except Exception as e:
            self.logger.error(f"Failed to generate polymorphic variant: {e}")
            return original_code 