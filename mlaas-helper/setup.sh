#!/bin/bash
# MLaaS Helper Setup Script

echo "Setting up MLaaS Helper..."

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install -r requirements.txt

echo "Setup complete!"
echo ""
echo "Before running the server, set these environment variables:"
echo "export KEYCLOAK_URL=\"https://your-keycloak-instance.com\""
echo "export KEYCLOAK_REALM=\"your_realm_name\""
echo "export KEYCLOAK_CLIENT_ID=\"your_client_id\""
echo "export THREESCALE_ADMIN_API_URL=\"https://your-admin-portal.3scale.net/admin/api/\""
echo "export THREESCALE_ADMIN_API_KEY=\"your_3scale_admin_api_key\""
echo ""
echo "To run the server:"
echo "1. Activate the virtual environment: source venv/bin/activate"
echo "2. Set environment variables (see above)"
echo "3. Run the server: python server.py" 