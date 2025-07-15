#!/usr/bin/env python3
"""
NightStalker WebXF - Unified Web Exploitation Framework
Main entry point for the combined framework
"""

import sys
import os
from pathlib import Path

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent))

def main():
    """Main entry point"""
    try:
        from cli.main import NightStalkerWebXFCLI
        
        # Initialize CLI
        cli = NightStalkerWebXFCLI()
        
        # Run CLI
        sys.exit(cli.run())
    
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 