#!/usr/bin/env python3
"""
NightStalker ToolManager Utility
Universal tool checker and installer for external dependencies
"""

import os
import sys
import platform
import subprocess
import logging
from typing import List, Optional

class ToolManager:
    """Universal tool checker and installer for external dependencies"""
    TOOL_COMMANDS = {
        'nmap': 'nmap',
        'amass': 'amass',
        'sqlmap': 'sqlmap',
        'nuclei': 'nuclei',
        'xsstrike': 'xsstrike',
        'ffuf': 'ffuf',
        'gobuster': 'gobuster',
        'feroxbuster': 'feroxbuster',
        'nikto': 'nikto',
        'wpscan': 'wpscan',
        'hydra': 'hydra',
        'msfconsole': 'msfconsole',
        'subfinder': 'subfinder',
        'httpx': 'httpx',
        'smbclient': 'smbclient',
        'impacket': 'impacket-GetUserSPNs',
        'crackmapexec': 'crackmapexec',
        'enum4linux': 'enum4linux',
        'smbmap': 'smbmap',
        'bloodhound': 'bloodhound',
        'rclone': 'rclone',
        'scp': 'scp',
        'ftp': 'ftp',
    }

    @staticmethod
    def is_tool_installed(tool: str) -> bool:
        """Check if a tool is installed and available in PATH"""
        cmd = ToolManager.TOOL_COMMANDS.get(tool, tool)
        return any(
            os.access(os.path.join(path, cmd), os.X_OK)
            for path in os.environ["PATH"].split(os.pathsep)
        )

    @staticmethod
    def check_and_install_tools(tools: List[str], logger: Optional[logging.Logger] = None) -> None:
        """Check for required tools and attempt to install if missing"""
        for tool in tools:
            if not ToolManager.is_tool_installed(tool):
                msg = f"[ToolManager] Tool '{tool}' not found. Attempting to install..."
                if logger:
                    logger.warning(msg)
                else:
                    print(msg)
                ToolManager.install_tool(tool, logger)
            else:
                msg = f"[ToolManager] Tool '{tool}' is already installed."
                if logger:
                    logger.info(msg)
                else:
                    print(msg)

    @staticmethod
    def install_tool(tool: str, logger: Optional[logging.Logger] = None) -> None:
        """Attempt to install a tool using the appropriate package manager"""
        os_type = platform.system().lower()
        try:
            if os_type == 'linux':
                if ToolManager._run_install(['apt', 'install', '-y', tool], logger):
                    return
                if ToolManager._run_install(['yum', 'install', '-y', tool], logger):
                    return
                if ToolManager._run_install(['dnf', 'install', '-y', tool], logger):
                    return
                if ToolManager._run_install(['snap', 'install', tool], logger):
                    return
            elif os_type == 'darwin':
                if ToolManager._run_install(['brew', 'install', tool], logger):
                    return
            elif os_type == 'windows':
                if ToolManager._run_install(['winget', 'install', '-e', '--id', tool], logger):
                    return
                if ToolManager._run_install(['choco', 'install', tool, '-y'], logger):
                    return
            # Try pip as a fallback for Python-based tools
            if ToolManager._run_install([sys.executable, '-m', 'pip', 'install', tool], logger):
                return
            msg = f"[ToolManager] Failed to auto-install tool '{tool}'. Please install it manually."
            if logger:
                logger.error(msg)
            else:
                print(msg)
        except Exception as e:
            msg = f"[ToolManager] Exception during installation of '{tool}': {e}"
            if logger:
                logger.error(msg, exc_info=True)
            else:
                print(msg)

    @staticmethod
    def _run_install(cmd: list, logger: Optional[logging.Logger] = None) -> bool:
        """Run a system install command and return True if successful"""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode == 0:
                msg = f"[ToolManager] Successfully installed with: {' '.join(cmd)}"
                if logger:
                    logger.info(msg)
                else:
                    print(msg)
                return True
            else:
                msg = f"[ToolManager] Install failed: {' '.join(cmd)}\n{result.stderr}"
                if logger:
                    logger.warning(msg)
                else:
                    print(msg)
                return False
        except Exception as e:
            msg = f"[ToolManager] Exception running install command: {' '.join(cmd)}: {e}"
            if logger:
                logger.error(msg, exc_info=True)
            else:
                print(msg)
            return False 