#!/bin/bash

# MLaaS CLI Setup Script
# This script sets up the MLaaS CLI client with required dependencies

set -e

echo "=== MLaaS CLI Setup ==="
echo

# Check if python3 is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 is required but not installed."
    echo "Please install Python 3.9 or higher."
    exit 1
fi

# Check Python version
python_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "✓ Python version: $python_version"

# Check if we have minimum required version
if ! python3 -c "import sys; exit(0 if sys.version_info >= (3, 9) else 1)"; then
    echo "❌ Error: Python 3.9 or higher is required."
    echo "Current version: $python_version"
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    echo "✓ Virtual environment created"
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

echo "✓ Dependencies installed"

# Make client executable
chmod +x client.py

echo "✓ Client made executable"

# Create example environment file
cat > .env.example << 'EOF'
# MLaaS CLI Environment Variables
# Copy this file to .env and update with your actual values

# Keycloak Configuration (Required)
KEYCLOAK_URL=https://your-keycloak-server.com
KEYCLOAK_REALM=your-realm
KEYCLOAK_CLIENT_ID=your-client-id

# MLaaS Helper Configuration (Optional)
MLAAS_HELPER_URL=http://localhost:5000

# Example Production Configuration:
# KEYCLOAK_URL=https://keycloak.prod.example.com
# KEYCLOAK_REALM=mlaas-prod
# KEYCLOAK_CLIENT_ID=mlaas-client
# MLAAS_HELPER_URL=https://mlaas-helper.prod.example.com
EOF

echo "✓ Created .env.example file"

echo
echo "=== Setup Complete ==="
echo
echo "Next steps:"
echo "1. Copy .env.example to .env and update with your actual values:"
echo "   cp .env.example .env"
echo "   nano .env"
echo
echo "2. Set environment variables:"
echo "   export KEYCLOAK_URL=https://your-keycloak-server.com"
echo "   export KEYCLOAK_REALM=your-realm"
echo "   export KEYCLOAK_CLIENT_ID=your-client-id"
echo "   export MLAAS_HELPER_URL=https://your-mlaas-helper.com"
echo
echo "3. Test the client:"
echo "   ./client.py --health"
echo "   ./client.py --list"
echo
echo "4. For help:"
echo "   ./client.py --help"
echo
echo "5. Run the example:"
echo "   python3 example_usage.py"
echo 