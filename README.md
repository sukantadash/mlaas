# MLaaS (Machine Learning as a Service)

MLaaS is a comprehensive API management platform designed to simplify access to machine learning services through automated API key provisioning, user authentication, and service discovery.

## 🏗️ Architecture Overview

The MLaaS platform consists of three main components:

1. **Keycloak** - Identity and access management server
2. **MLaaS Helper** - API management and service provisioning server  
3. **MLaaS CLI** - Command-line interface for end users

### Authentication Flow

```
[User] → [MLaaS CLI] → [Keycloak] → [JWT Token]
                    ↓
[MLaaS CLI] → [MLaaS Helper] (with JWT Token) → [3Scale API Management]
```

## 📋 Table of Contents

- [Features](#features)
- [Architecture Components](#architecture-components)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [API Reference](#api-reference)
- [Deployment](#deployment)
- [Development](#development)
- [Contributing](#contributing)

## ✨ Features

### Core Functionality
- **🔐 Authentication**: Secure user authentication via Keycloak with JWT tokens
- **🔑 API Key Management**: Automated API key generation and management through 3Scale
- **📋 Service Discovery**: Dynamic discovery and listing of available ML services
- **🚦 Rate Limiting**: Built-in rate limiting for API endpoints
- **💻 CLI Interface**: User-friendly command-line interface for service interaction
- **🔍 Health Monitoring**: Comprehensive health checks and monitoring
- **📊 Structured Logging**: Advanced logging with structured output for observability

### Security Features
- JWT token-based authentication with Keycloak
- Token refresh and expiration handling
- Secure credential storage and management
- Non-root container execution
- Input validation and sanitization

## 🏗️ Architecture Components

### 1. **Keycloak Authentication Server**
- **Purpose**: Identity and access management
- **Technology**: Keycloak OpenID Connect
- **Key Features**:
  - JWT token issuance and validation
  - User authentication and authorization
  - OAuth2/OpenID Connect flows
  - Token refresh capabilities

### 2. **MLaaS Helper Server** (`mlaas-helper/`)
- **Purpose**: API management and service provisioning
- **Technology**: Flask with Gunicorn WSGI server
- **Key Features**:
  - RESTful API endpoints
  - JWT token validation
  - 3Scale API management integration
  - Service discovery and management
  - Health check endpoints

### 3. **MLaaS CLI Client** (`mlaas-cli/`)
- **Purpose**: Command-line interface for end users
- **Technology**: Python 3.9+
- **Key Features**:
  - Direct Keycloak authentication
  - JWT token management and refresh
  - Service listing and discovery
  - API key initialization
  - Configuration management
  - Comprehensive error handling

### 4. **API Management Layer**
- **3Scale**: API gateway and management platform
- **Service Registry**: Dynamic service discovery
- **Key Provisioning**: Automated API key generation

### 5. **Deployment Infrastructure**
- **Containerization**: Docker/Podman containers
- **Orchestration**: Kubernetes/OpenShift
- **Helm Charts**: Kubernetes deployment templates
- **CI/CD**: Automated build and deployment

## 🛠️ Prerequisites

### System Requirements
- Python 3.9 or higher
- pip package manager
- Access to Keycloak authentication server
- Access to 3Scale API management platform
- Access to MLaaS Helper server

### Configuration
The MLaaS CLI comes with hardcoded configuration for production use:

- **Keycloak URL**: `https://keycloak.prod.example.com`
- **Keycloak Realm**: `mlaas`
- **Keycloak Client ID**: `mlaas-client`
- **MLaaS Helper URL**: `https://mlaas-helper.prod.example.com`

These values can be overridden using command-line parameters if needed.

### Server Environment Variables (for mlaas-helper)
```bash
KEYCLOAK_URL=https://your-keycloak-server.com
KEYCLOAK_REALM=your-realm
KEYCLOAK_CLIENT_ID=your-client-id
THREESCALE_ADMIN_API_URL=https://your-3scale-admin.com
THREESCALE_ADMIN_API_KEY=your-3scale-admin-key
FLASK_ENV=production
```

## 🚀 Installation

### MLaaS CLI Installation

#### Option 1: Binary Installation (Recommended)

1. **Download the pre-built binary**:
```bash
# Download from releases page or build locally (see below)
wget https://github.com/your-org/mlaas/releases/latest/download/mlaas-cli
chmod +x mlaas-cli
```

2. **Test the installation**:
```bash
./mlaas-cli --health
```

#### Option 2: Development Installation

1. **Clone the repository**:
```bash
git clone <repository-url>
cd mlaas/mlaas-cli
```

2. **Run the setup script**:
```bash
chmod +x setup.sh
./setup.sh
```

3. **Test the installation**:
```bash
./client.py --health
```

#### Option 3: Build Binary from Source

1. **Clone and setup**:
```bash
git clone <repository-url>
cd mlaas/mlaas-cli
./setup.sh
```

2. **Activate virtual environment**:
```bash
source venv/bin/activate
```

3. **Build binary (using build script)**:
```bash
chmod +x build.sh
./build.sh
```

**Or build manually with PyInstaller**:
```bash
pyinstaller --onefile --name mlaas-cli client.py
```

4. **Binary location**:
```bash
# Binary will be created at: dist/mlaas-cli
./dist/mlaas-cli --health
```

5. **Install system-wide (optional)**:
```bash
sudo cp dist/mlaas-cli /usr/local/bin/
mlaas-cli --health
```

### MLaaS Helper Installation

1. **Navigate to helper directory**:
```bash
cd mlaas/mlaas-helper
```

2. **Create virtual environment**:
```bash
python -m venv venv
source venv/bin/activate
```

3. **Install dependencies**:
```bash
pip install -r requirements.txt
```

4. **Set environment variables**:
```bash
export KEYCLOAK_URL=https://your-keycloak-server.com
export KEYCLOAK_REALM=your-realm
export KEYCLOAK_CLIENT_ID=your-client-id
export THREESCALE_ADMIN_API_URL=https://your-3scale-admin.com
export THREESCALE_ADMIN_API_KEY=your-3scale-admin-key
```

5. **Run the server**:
```bash
python server.py
```

## ⚙️ Configuration

### CLI Configuration
The CLI stores configuration in `~/.mlaas_client_config.ini`:

```ini
[auth]
access_token = your-jwt-token
refresh_token = your-refresh-token
expires_at = 1234567890
```

### Override Configuration

The CLI uses hardcoded production values but allows command-line overrides:

| Parameter | Default Value | Description |
|-----------|---------------|-------------|
| `--keycloak-url` | `https://keycloak.prod.example.com` | Keycloak server URL |
| `--keycloak-realm` | `mlaas` | Keycloak realm name |
| `--keycloak-client-id` | `mlaas-client` | Keycloak client ID |
| `--mlaas-helper-url` | `https://mlaas-helper.prod.example.com` | MLaaS Helper server URL |

### Server Environment Variables (mlaas-helper only)

| Variable | Description | Required |
|----------|-------------|----------|
| `KEYCLOAK_URL` | Keycloak server URL | Yes |
| `KEYCLOAK_REALM` | Keycloak realm name | Yes |
| `KEYCLOAK_CLIENT_ID` | Keycloak client ID | Yes |
| `THREESCALE_ADMIN_API_URL` | 3Scale admin API URL | Yes |
| `THREESCALE_ADMIN_API_KEY` | 3Scale admin API key | Yes |
| `FLASK_ENV` | Flask environment | No |

## 📖 Usage

### CLI Usage

#### Using Binary (Recommended)

1. **Check server health**:
```bash
mlaas-cli --health
```

2. **Show current configuration**:
```bash
mlaas-cli --config
```

3. **List available services**:
```bash
mlaas-cli --list
```

4. **Initialize API key for a service**:
```bash
mlaas-cli --init id=service-123
mlaas-cli --init name="ML Service Name"
```

5. **Clear stored tokens**:
```bash
mlaas-cli --logout
```

6. **Override configuration if needed**:
```bash
mlaas-cli --keycloak-url https://custom-keycloak.com --list
mlaas-cli --mlaas-helper-url https://custom-helper.com --health
```

7. **Get help**:
```bash
mlaas-cli --help
```

#### Using Python Script (Development)

Replace `mlaas-cli` with `./client.py` in all the above examples.

### Authentication Flow

The CLI handles authentication automatically:

1. **First use**: CLI prompts for Keycloak credentials
2. **Token storage**: JWT tokens are stored locally
3. **Token refresh**: Expired tokens are automatically refreshed
4. **Re-authentication**: If refresh fails, CLI prompts for credentials again

### Programmatic Usage

```python
from client import MLaaSClient

# Initialize client (uses hardcoded production configuration)
client = MLaaSClient()

# Or override configuration if needed
client = MLaaSClient(
    keycloak_url="https://custom-keycloak.com",
    mlaas_helper_url="https://custom-helper.com"
)

# Check configuration
client.show_config()

# List services (will authenticate if needed)
services = client.make_request('GET', '/api/services')
print(f"Available services: {services}")

# Initialize API key
response = client.make_request('POST', '/api/services/init', 
                              data={'service_id': 'your-service-id'})
print(f"API Key: {response.get('api_key')}")
```

## 🔌 API Reference

### MLaaS Helper API Endpoints

#### `GET /api/health`
Check server health status (no authentication required).

**Response**:
```json
{
    "status": "success",
    "data": {
        "status": "healthy"
    }
}
```

#### `GET /api/services`
List all available services for the authenticated user.

**Headers**:
```
Authorization: Bearer <jwt-token>
```

**Response**:
```json
{
    "status": "success",
    "data": {
        "services": [
            {
                "id": "service-1",
                "name": "ML Service 1",
                "proxy_endpoint": "https://api.example.com/ml-service-1",
                "authentication_method": "api_key",
                "has_api_key": true,
                "api_key": "your-api-key"
            }
        ],
        "user": {
            "soeid": "user123",
            "email": "user@example.com"
        },
        "account_id": "3scale-account-id"
    }
}
```

#### `POST /api/services/init`
Initialize or retrieve API key for a specific service.

**Headers**:
```
Authorization: Bearer <jwt-token>
```

**Request Body**:
```json
{
    "service_id": "service-1"
}
```

**Response**:
```json
{
    "status": "success",
    "data": {
        "api_key": "your-generated-api-key",
        "service": {
            "id": "service-1",
            "name": "ML Service 1",
            "proxy_endpoint": "https://api.example.com/ml-service-1",
            "authentication_method": "api_key"
        },
        "plan": {
            "id": "plan-1",
            "name": "Basic Plan"
        },
        "is_new": true,
        "account_id": "3scale-account-id"
    }
}
```

### Error Responses

All API endpoints return standardized error responses:

```json
{
    "status": "error",
    "error": {
        "code": "ERROR_CODE",
        "message": "Human readable error message"
    }
}
```

Common error codes:
- `MISSING_AUTH` (401): Missing or invalid authorization header
- `INVALID_TOKEN` (401): Invalid or expired JWT token
- `ACCOUNT_NOT_FOUND` (404): User account not found in 3Scale
- `SERVICE_NOT_FOUND` (404): Requested service not found
- `CONFIG_ERROR` (500): Server configuration error

## 🚀 Deployment

### Docker Deployment

1. **Build the MLaaS Helper container**:
```bash
cd mlaas/mlaas-helper
docker build -t mlaas-helper -f Containerfile .
```

2. **Run the container**:
```bash
docker run -p 5000:5000 \
  -e KEYCLOAK_URL=https://your-keycloak-server.com \
  -e KEYCLOAK_REALM=your-realm \
  -e KEYCLOAK_CLIENT_ID=your-client-id \
  -e THREESCALE_ADMIN_API_URL=https://your-3scale-admin.com \
  -e THREESCALE_ADMIN_API_KEY=your-3scale-admin-key \
  mlaas-helper
```

### Kubernetes Deployment

1. **Install MLaaS Helper using Helm**:
```bash
cd mlaas/mlaas-helper/helm-chart
helm install mlaas-helper . -f values-example.yaml \
  --set keycloak.url=https://your-keycloak-server.com \
  --set keycloak.realm=your-realm \
  --set keycloak.clientId=your-client-id \
  --set threescale.adminApiUrl=https://your-3scale-admin.com \
  --set threescale.adminApiKey=your-3scale-admin-key
```

2. **OpenShift Deployment**:
```bash
oc apply -f buildconfig.yaml
oc start-build mlaas-helper
```

## 💻 Development

### Development Setup

1. **Install development dependencies**:
```bash
pip install -r requirements.txt
pip install pytest black flake8 mypy
```

2. **Run tests**:
```bash
pytest
```

3. **Code formatting**:
```bash
black .
flake8 .
mypy .
```

### Project Structure

```
mlaas/
├── mlaas-cli/                 # CLI client
│   ├── client.py              # Main CLI client (source)
│   ├── example_usage.py       # Usage examples
│   ├── requirements.txt       # CLI dependencies (includes PyInstaller)
│   ├── setup.sh              # CLI setup script
│   ├── dist/                  # Binary distribution (after build)
│   │   └── mlaas-cli          # Packaged binary
│   └── build/                 # PyInstaller build files
├── mlaas-helper/             # MLaaS Helper server
│   ├── server.py              # Main server application
│   ├── requirements.txt       # Server dependencies
│   ├── Containerfile          # Docker configuration
│   ├── buildconfig.yaml       # OpenShift build config
│   ├── helm-chart/            # Kubernetes deployment
│   │   ├── Chart.yaml
│   │   ├── values.yaml
│   │   ├── values-example.yaml
│   │   └── templates/
│   └── setup.sh              # Server setup script
└── README.md                  # This file
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m 'Add amazing feature'`
4. Push to the branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

### Code Style
- Follow PEP 8 for Python code
- Use type hints where appropriate
- Write comprehensive docstrings
- Include unit tests for new features

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Create an issue in the repository
- Contact the development team
- Check the documentation and examples

## 🗺️ Roadmap

- [x] Direct Keycloak authentication in CLI
- [x] JWT token management and refresh
- [x] Helm chart with configuration validation
- [x] Binary packaging with PyInstaller
- [x] Hardcoded production configuration
- [x] Streamlined logging with error-level default
- [ ] Enhanced error handling and recovery
- [ ] Metrics and monitoring integration
- [ ] Multi-environment support
- [ ] Advanced caching mechanisms
- [ ] WebSocket support for real-time updates
- [ ] GraphQL API support
- [ ] Enhanced security features

## 🔧 Troubleshooting

### Common Issues

1. **Authentication fails**: 
   - Check hardcoded Keycloak configuration matches your environment
   - Override configuration if needed: `--keycloak-url https://your-keycloak.com`
   - Verify network connectivity to Keycloak
   - Ensure user has access to the specified realm

2. **MLaaS Helper connection fails**:
   - Check hardcoded MLaaS Helper URL matches your environment
   - Override if needed: `--mlaas-helper-url https://your-helper.com`
   - Verify the server is running and accessible
   - Check firewall and network configuration

3. **API key initialization fails**:
   - Verify 3Scale configuration on the server
   - Check user permissions in 3Scale
   - Ensure service exists and is configured

4. **Token refresh fails**:
   - Clear stored tokens: `mlaas-cli --logout`
   - Re-authenticate: `mlaas-cli --list`
   - Check Keycloak token settings

5. **Binary execution fails**:
   - Ensure binary has execute permissions: `chmod +x mlaas-cli`
   - Check if binary is compatible with your OS architecture
   - Try rebuilding from source if needed

### Debug Mode

Enable verbose logging for troubleshooting:
```bash
# Binary
mlaas-cli --verbose --health

# Python script (development)
./client.py --verbose --health
``` 