#!/bin/bash
# Installation script for ONVIF Peekr

set -e

echo "ONVIF Peekr Installation Script"
echo "==============================="

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed. Please install Python 3.7 or later."
    exit 1
fi

# Check Python version
python_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "Found Python version: $python_version"

# Check if we need to install system dependencies
echo "Checking system dependencies..."

# Check for required system packages
missing_packages=()

if ! dpkg -l | grep -q libxml2-dev; then
    missing_packages+=("libxml2-dev")
fi

if ! dpkg -l | grep -q libxslt1-dev; then
    missing_packages+=("libxslt1-dev")
fi

if ! dpkg -l | grep -q python3-dev; then
    missing_packages+=("python3-dev")
fi

if ! dpkg -l | grep -q "^ii  tidy "; then
    missing_packages+=("tidy")
fi

if [ ${#missing_packages[@]} -gt 0 ]; then
    echo "Missing system packages: ${missing_packages[*]}"
    echo "Installing system dependencies..."
    sudo apt update
    sudo apt install -y "${missing_packages[@]}"
fi

# Create virtual environment
echo "Creating virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

# Activate virtual environment and install dependencies
echo "Installing Python dependencies..."
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

echo ""
echo "Installation completed successfully!"
echo ""
echo "To run ONVIF Peekr:"
echo "  1. Activate the virtual environment: source venv/bin/activate"
echo "  2. Run the application: python run_onvif_peekr.py"
echo "  3. Or run the demo: python demo.py"
echo ""
echo "To run tests:"
echo "  source venv/bin/activate && python test_onvif_peekr.py"
echo ""
echo "Enjoy exploring ONVIF cameras!"
