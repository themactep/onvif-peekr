#!/usr/bin/env python3
"""
Launcher script for ONVIF Peekr application
"""

import sys
import os
from pathlib import Path

# Add src directory to Python path
src_dir = Path(__file__).parent / "src"
sys.path.insert(0, str(src_dir))

try:
    from onvif_peekr import main
    
    if __name__ == "__main__":
        print("Starting ONVIF Peekr...")
        main()
        
except ImportError as e:
    print(f"Error importing ONVIF Peekr: {e}")
    print("Please ensure all dependencies are installed:")
    print("pip install -r requirements.txt")
    sys.exit(1)
except Exception as e:
    print(f"Error starting ONVIF Peekr: {e}")
    sys.exit(1)
