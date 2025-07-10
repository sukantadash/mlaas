#!/bin/bash

# MLaaS CLI Binary Build Script
# This script builds a standalone binary using PyInstaller

set -e

echo "=== MLaaS CLI Binary Builder ==="
echo

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found. Run ./setup.sh first."
    exit 1
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Check if PyInstaller is available
if ! command -v pyinstaller &> /dev/null; then
    echo "❌ PyInstaller not found. Installing..."
    pip install pyinstaller==6.3.0
fi

# Clean previous builds
echo "Cleaning previous builds..."
rm -rf build/ dist/

# Build binary
echo "Building binary with PyInstaller..."
pyinstaller \
    --onefile \
    --name mlaas-cli \
    --console \
    --clean \
    --noconfirm \
    client.py

# Check if build was successful
if [ -f "dist/mlaas-cli" ]; then
    echo "✓ Binary built successfully: dist/mlaas-cli"
    
    # Make binary executable
    chmod +x dist/mlaas-cli
    
    # Test the binary
    echo "Testing the binary..."
    if ./dist/mlaas-cli --help > /dev/null 2>&1; then
        echo "✓ Binary test passed"
        
        # Show binary info
        echo
        echo "Binary information:"
        echo "  Location: $(pwd)/dist/mlaas-cli"
        echo "  Size: $(du -h dist/mlaas-cli | cut -f1)"
        echo "  Executable: ✓"
        
        echo
        echo "Usage:"
        echo "  ./dist/mlaas-cli --health"
        echo "  ./dist/mlaas-cli --list"
        echo
        echo "To install system-wide:"
        echo "  sudo cp dist/mlaas-cli /usr/local/bin/"
        
    else
        echo "❌ Binary test failed"
        exit 1
    fi
else
    echo "❌ Binary build failed"
    exit 1
fi

echo
echo "=== Build Complete ===" 