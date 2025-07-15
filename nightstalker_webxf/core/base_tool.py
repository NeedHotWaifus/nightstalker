#!/usr/bin/env python3
"""
Base Tool Wrapper for NightStalker WebXF
Provides unified interface for external security tools
"""

import os
import sys
import subprocess
import shlex
import time
import signal
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Tuple
import logging
import threading
from abc import ABC, abstractmethod

from .config import get_config
from .logging import get_logger, log_tool_execution

class ToolExecutionError(Exception):
    """Exception raised when tool execution fails"""
    pass

class ToolNotFoundError(Exception):
    """Exception raised when tool is not found"""
    pass

class BaseTool(ABC):
    """Base class for all tool wrappers"""
    
    def __init__(self, tool_name: str, config_path: Optional[str] = None):
        """Initialize base tool wrapper"""
        self.tool_name = tool_name
        self.config = get_config(config_path)
        self.logger = get_logger(f"tools.{tool_name}")
        self.tool_config = self.config.get_tool_config(tool_name)
        
        # Validate tool installation
        self._validate_tool()
        
        # Execution state
        self._process: Optional[subprocess.Popen] = None
        self._output_buffer: List[str] = []
        self._error_buffer: List[str] = []
        self._execution_time: float = 0.0
        self._success: bool = False
    
    def _validate_tool(self) -> None:
        """Validate that the tool is installed and accessible"""
        tool_path = self.tool_config.get("path", self.tool_name)
        
        # Check if tool exists
        if not os.path.exists(tool_path):
            # Try to find tool in PATH
            if not self._find_tool_in_path():
                raise ToolNotFoundError(f"Tool '{self.tool_name}' not found at {tool_path} and not in PATH")
        
        self.logger.debug(f"Tool '{self.tool_name}' validated successfully")
    
    def _find_tool_in_path(self) -> bool:
        """Find tool in system PATH"""
        for path in os.environ.get("PATH", "").split(os.pathsep):
            tool_path = os.path.join(path, self.tool_name)
            if os.path.isfile(tool_path) and os.access(tool_path, os.X_OK):
                self.tool_config["path"] = tool_path
                self.logger.info(f"Found {self.tool_name} at {tool_path}")
                return True
        return False
    
    def _build_command(self, args: List[str]) -> List[str]:
        """Build command list for subprocess execution"""
        tool_path = self.tool_config.get("path", self.tool_name)
        return [tool_path] + args
    
    def _sanitize_args(self, args: List[str]) -> List[str]:
        """Sanitize command line arguments"""
        sanitized = []
        for arg in args:
            # Remove any potentially dangerous characters
            arg = str(arg).strip()
            if arg:
                sanitized.append(arg)
        return sanitized
    
    def _get_timeout(self) -> int:
        """Get timeout for tool execution"""
        return self.tool_config.get("timeout", self.config.get("framework.timeout", 300))
    
    def _get_env(self) -> Dict[str, str]:
        """Get environment variables for tool execution"""
        env = os.environ.copy()
        
        # Add tool-specific environment variables
        tool_env = self.tool_config.get("environment", {})
        env.update(tool_env)
        
        return env
    
    def execute(self, args: List[str], timeout: Optional[int] = None, 
                capture_output: bool = True, working_dir: Optional[str] = None) -> Dict[str, Any]:
        """Execute tool with given arguments"""
        start_time = time.time()
        
        try:
            # Sanitize arguments
            sanitized_args = self._sanitize_args(args)
            
            # Build command
            command = self._build_command(sanitized_args)
            
            # Get timeout
            exec_timeout = timeout or self._get_timeout()
            
            # Get environment
            env = self._get_env()
            
            # Log execution
            self.logger.info(f"Executing {self.tool_name}: {' '.join(command)}")
            
            # Execute command
            if capture_output:
                result = self._execute_with_output(command, exec_timeout, env, working_dir)
            else:
                result = self._execute_without_output(command, exec_timeout, env, working_dir)
            
            # Calculate execution time
            self._execution_time = time.time() - start_time
            self._success = result["return_code"] == 0
            
            # Log result
            log_tool_execution(
                self.tool_name,
                ' '.join(command),
                self._success,
                result.get("output", "")[:500]  # Truncate for logging
            )
            
            if self._success:
                self.logger.info(f"{self.tool_name} executed successfully in {self._execution_time:.2f}s")
            else:
                self.logger.warning(f"{self.tool_name} failed with return code {result['return_code']}")
            
            return result
        
        except subprocess.TimeoutExpired:
            self._execution_time = time.time() - start_time
            self.logger.error(f"{self.tool_name} execution timed out after {self._execution_time:.2f}s")
            raise ToolExecutionError(f"Tool execution timed out after {exec_timeout}s")
        
        except Exception as e:
            self._execution_time = time.time() - start_time
            self.logger.error(f"{self.tool_name} execution failed: {e}")
            raise ToolExecutionError(f"Tool execution failed: {e}")
    
    def _execute_with_output(self, command: List[str], timeout: int, env: Dict[str, str], 
                           working_dir: Optional[str]) -> Dict[str, Any]:
        """Execute command and capture output"""
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                cwd=working_dir,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            self._process = process
            
            # Execute with timeout
            stdout, stderr = process.communicate(timeout=timeout)
            
            return {
                "return_code": process.returncode,
                "output": stdout,
                "error": stderr,
                "command": command,
                "execution_time": time.time()
            }
        
        finally:
            self._process = None
    
    def _execute_without_output(self, command: List[str], timeout: int, env: Dict[str, str], 
                              working_dir: Optional[str]) -> Dict[str, Any]:
        """Execute command without capturing output"""
        try:
            process = subprocess.Popen(
                command,
                env=env,
                cwd=working_dir
            )
            
            self._process = process
            
            # Execute with timeout
            process.communicate(timeout=timeout)
            
            return {
                "return_code": process.returncode,
                "output": "",
                "error": "",
                "command": command,
                "execution_time": time.time()
            }
        
        finally:
            self._process = None
    
    def execute_async(self, args: List[str], callback: Optional[callable] = None) -> threading.Thread:
        """Execute tool asynchronously"""
        def async_execution():
            try:
                result = self.execute(args)
                if callback:
                    callback(result)
            except Exception as e:
                self.logger.error(f"Async execution failed: {e}")
                if callback:
                    callback({"error": str(e)})
        
        thread = threading.Thread(target=async_execution)
        thread.daemon = True
        thread.start()
        return thread
    
    def stop(self) -> None:
        """Stop running tool execution"""
        if self._process and self._process.poll() is None:
            try:
                self._process.terminate()
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
                self._process.wait()
            
            self.logger.info(f"Stopped {self.tool_name} execution")
    
    def get_version(self) -> Optional[str]:
        """Get tool version"""
        try:
            result = self.execute(["--version"])
            if result["return_code"] == 0:
                return result["output"].strip()
        except Exception as e:
            self.logger.debug(f"Failed to get version: {e}")
        
        return None
    
    def check_health(self) -> bool:
        """Check if tool is healthy and working"""
        try:
            result = self.execute(["--help"])
            return result["return_code"] == 0
        except Exception as e:
            self.logger.debug(f"Health check failed: {e}")
            return False
    
    @abstractmethod
    def parse_output(self, output: str) -> Dict[str, Any]:
        """Parse tool output into structured data"""
        pass
    
    def get_execution_stats(self) -> Dict[str, Any]:
        """Get execution statistics"""
        return {
            "tool_name": self.tool_name,
            "execution_time": self._execution_time,
            "success": self._success,
            "output_lines": len(self._output_buffer),
            "error_lines": len(self._error_buffer)
        }
    
    def cleanup(self) -> None:
        """Cleanup resources"""
        self.stop()
        self._output_buffer.clear()
        self._error_buffer.clear()

class ToolManager:
    """Manager for multiple tool instances"""
    
    def __init__(self):
        """Initialize tool manager"""
        self.tools: Dict[str, BaseTool] = {}
        self.logger = get_logger("tool_manager")
    
    def register_tool(self, tool: BaseTool) -> None:
        """Register a tool instance"""
        self.tools[tool.tool_name] = tool
        self.logger.info(f"Registered tool: {tool.tool_name}")
    
    def get_tool(self, tool_name: str) -> Optional[BaseTool]:
        """Get tool instance by name"""
        return self.tools.get(tool_name)
    
    def list_tools(self) -> List[str]:
        """List all registered tools"""
        return list(self.tools.keys())
    
    def check_all_tools(self) -> Dict[str, bool]:
        """Check health of all registered tools"""
        results = {}
        for name, tool in self.tools.items():
            try:
                results[name] = tool.check_health()
            except Exception as e:
                self.logger.error(f"Health check failed for {name}: {e}")
                results[name] = False
        return results
    
    def stop_all_tools(self) -> None:
        """Stop all running tools"""
        for tool in self.tools.values():
            try:
                tool.stop()
            except Exception as e:
                self.logger.error(f"Failed to stop {tool.tool_name}: {e}")
    
    def cleanup_all(self) -> None:
        """Cleanup all tools"""
        for tool in self.tools.values():
            try:
                tool.cleanup()
            except Exception as e:
                self.logger.error(f"Failed to cleanup {tool.tool_name}: {e}")

# Global tool manager instance
_tool_manager = None

def get_tool_manager() -> ToolManager:
    """Get global tool manager instance"""
    global _tool_manager
    if _tool_manager is None:
        _tool_manager = ToolManager()
    return _tool_manager

def register_tool(tool: BaseTool) -> None:
    """Register a tool with the global manager"""
    manager = get_tool_manager()
    manager.register_tool(tool)

def get_tool(tool_name: str) -> Optional[BaseTool]:
    """Get tool from global manager"""
    manager = get_tool_manager()
    return manager.get_tool(tool_name)

def list_tools() -> List[str]:
    """List all registered tools"""
    manager = get_tool_manager()
    return manager.list_tools()

def check_all_tools() -> Dict[str, bool]:
    """Check health of all registered tools"""
    manager = get_tool_manager()
    return manager.check_all_tools()

def stop_all_tools() -> None:
    """Stop all running tools"""
    manager = get_tool_manager()
    manager.stop_all_tools()

def cleanup_all_tools() -> None:
    """Cleanup all tools"""
    manager = get_tool_manager()
    manager.cleanup_all() 