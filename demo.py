#!/usr/bin/env python3
"""
Demo script for ONVIF Peekr application
This script demonstrates the application without requiring an actual ONVIF camera
"""

import sys
import os
from pathlib import Path

# Add src directory to Python path
src_dir = Path(__file__).parent / "src"
sys.path.insert(0, str(src_dir))

import tkinter as tk
from tkinter import messagebox
from onvif_peekr import ONVIFPeekr


def demo_mode():
    """Run the application in demo mode"""
    print("Starting ONVIF Peekr in demo mode...")
    print("This will show the GUI interface without requiring an actual ONVIF camera.")
    print("You can explore the interface and see how it would work with a real camera.")
    print()
    print("Features you can test:")
    print("- Enter camera connection details")
    print("- Select save location for XML files")
    print("- Toggle 'Save raw XML files' checkbox to control file organization")
    print("- View the list of ONVIF operations that would be executed")
    print("- See the logging interface")
    print()
    print("Note: The 'Connect' button will attempt to connect to the specified camera.")
    print("If you don't have an ONVIF camera available, the connection will fail,")
    print("but you can still explore the interface.")
    print()

    # Create and run the application
    root = tk.Tk()
    app = ONVIFPeekr(root)

    # Add demo message to log
    app.log_message("ONVIF Peekr started in demo mode")
    app.log_message("Enter camera details and click Connect to test with a real camera")
    app.log_message("Or explore the interface to see available features")

    # Show info about operations
    app.log_message(f"Total ONVIF operations available: {len(app.onvif_operations)}")
    for i, operation_info in enumerate(app.onvif_operations[:5], 1):
        operation, service, soap_body, requires_auth = operation_info
        auth_method = "WS-Security" if requires_auth else "No Auth"
        app.log_message(f"  {i}. {operation} ({service} service) - {auth_method}")
    if len(app.onvif_operations) > 5:
        app.log_message(f"  ... and {len(app.onvif_operations) - 5} more operations")

    # Start the GUI
    root.mainloop()


if __name__ == "__main__":
    try:
        demo_mode()
    except KeyboardInterrupt:
        print("\nDemo interrupted by user")
    except Exception as e:
        print(f"Error running demo: {e}")
        sys.exit(1)
