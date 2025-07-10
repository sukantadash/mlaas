# MLaaS Helper - API Gateway for 3Scale Integration

## 📖 Overview

The MLaaS (Machine Learning as a Service) Helper is a Flask-based REST API that provides a secure gateway for managing 3Scale API services and user access. It integrates with Keycloak for authentication and automates API key provisioning and management.

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   MLaaS Helper  │    │   3Scale API    │
│   Applications  │───▶│   (Flask)       │───▶│   Management    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
                       ┌─────────────────┐
                       │   Keycloak      │
                       │   Authentication│
                       └─────────────────┘
```

### Key Components

- **Flask API Server**: Core application handling HTTP requests
- **Keycloak Integration**: JWT token validation and user authentication
- **3Scale Management**: API service discovery and key provisioning
- **Security Layer**: Comprehensive security headers and input validation
- **Container Support**: Docker/OpenShift deployment ready
- **Helm Charts**: Kubernetes deployment automation

## 🚀 Quick Start

### Prerequisites

- Python 3.9+
- Access to Keycloak instance
- 3Scale Admin API access
- Docker (for containerization)
- OpenShift/Kubernetes (for deployment)

### Local Development Setup

1. **Clone and Navigate**
   ```bash
   git clone <repository-url>
   cd mlaas/mlaas-helper
   ```

2. **Run Setup Script**
   ```bash
   chmod +x setup.sh
   ./setup.sh
   ```

3. **Configure Environment Variables**
   ```bash
   # Copy and customize environment template
   cp config.env.example .env
   
   # Edit .env with your configuration
   export KEYCLOAK_URL="https://your-keycloak-instance.com"
   export KEYCLOAK_REALM="your_realm_name"
   export KEYCLOAK_CLIENT_ID="your_client_id"
   export THREESCALE_ADMIN_API_URL="https://your-admin-portal.3scale.net/admin/api/"
   export THREESCALE_ADMIN_API_KEY="your_3scale_admin_api_key"
   ```

4. **Start Development Server**
   ```bash
   source venv/bin/activate
   python server.py
   ```

## ⚙️ Configuration

### Required Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `KEYCLOAK_URL` | Keycloak server URL | `https://auth.example.com` |
| `KEYCLOAK_REALM` | Keycloak realm name | `master` |
| `KEYCLOAK_CLIENT_ID` | Keycloak client ID | `mlaas-client` |
| `THREESCALE_ADMIN_API_URL` | 3Scale admin API URL | `https://admin.3scale.net/admin/api/` |
| `THREESCALE_ADMIN_API_KEY` | 3Scale admin API key | `abc123...` |

### Optional Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FLASK_ENV` | Flask environment | `production` |
| `FLASK_APP` | Flask application entry point | `server.py` |

## 🔧 Development Workflow

### 1. Code Structure

```
mlaas/mlaas-helper/
├── server.py              # Main Flask application
├── requirements.txt       # Python dependencies
├── setup.sh              # Development setup script
├── Containerfile         # Container build instructions
├── buildconfig.yaml      # OpenShift build configuration
├── artifactory-secret.yaml # Container registry secrets
├── pip.conf              # Python package configuration
└── helm-chart/           # Kubernetes deployment charts
    ├── Chart.yaml
    ├── values.yaml
    └── templates/
        ├── deployment.yaml
        ├── service.yaml
        ├── route.yaml
        └── ...
```

### 2. Local Development

**Activate Virtual Environment**
```bash
source venv/bin/activate
```

**Install Dependencies**
```bash
pip install -r requirements.txt
```

**Run Tests** (if implemented)
```bash
python -m pytest tests/
```

**Run with Debug Mode**
```bash
export FLASK_ENV=development
python server.py
```

### 3. Code Quality

**Install Development Dependencies**
```bash
pip install flake8 black isort mypy
```

**Code Formatting**
```bash
black server.py
isort server.py
```

**Linting**
```bash
flake8 server.py
mypy server.py
```

## 🐳 Container Deployment

### Building the Container

```bash
# Build container image
podman build -t mlaas-helper:latest -f Containerfile .

# Or using Docker
docker build -t mlaas-helper:latest -f Containerfile .
```

### Running Container Locally

```bash
# Create environment file
cat > .env << EOF
KEYCLOAK_URL=https://your-keycloak-instance.com
KEYCLOAK_REALM=your_realm_name
KEYCLOAK_CLIENT_ID=your_client_id
THREESCALE_ADMIN_API_URL=https://your-admin-portal.3scale.net/admin/api/
THREESCALE_ADMIN_API_KEY=your_3scale_admin_api_key
EOF

# Run container
podman run -p 5000:5000 --env-file .env mlaas-helper:latest
```

## ☸️ Kubernetes/OpenShift Deployment

### Using Helm Charts

1. **Prepare Values File**
   ```bash
   cp helm-chart/values.yaml helm-chart/values-prod.yaml
   # Edit values-prod.yaml with your configuration
   ```

2. **Deploy to Kubernetes**
   ```bash
   # Install Helm chart
helm install mlaas-helper ./helm-chart -f helm-chart/values-prod.yaml

# Upgrade existing deployment
helm upgrade mlaas-helper ./helm-chart -f helm-chart/values-prod.yaml
   ```

3. **Deploy to OpenShift**
   ```bash
   # Create project
oc new-project mlaas-helper

# Deploy using Helm
helm install mlaas-helper ./helm-chart -f helm-chart/values-prod.yaml
   
   # Or apply manifests directly
   oc apply -f buildconfig.yaml
   oc apply -f artifactory-secret.yaml
   ```

### Using OpenShift BuildConfig

1. **Create Secrets**
   ```bash
   # Update artifactory-secret.yaml with your credentials
   oc apply -f artifactory-secret.yaml
   ```

2. **Start Build**
   ```bash
   # Apply build configuration
   oc apply -f buildconfig.yaml
   
   # Start build from local directory
oc start-build mlaas-helper-build --from-dir=. --follow
   ```

## 🔌 API Documentation

### Endpoints

#### 1. Health Check
```
GET /api/health
```
**Response:**
```json
{
  "status": "success",
  "message": "Health check successful",
  "data": {
    "status": "healthy"
  }
}
```

#### 2. List Services
```
GET /api/services
Authorization: Bearer <jwt-token>
```
**Response:**
```json
{
  "status": "success",
  "message": "Services retrieved",
  "data": {
    "services": [
      {
        "id": "service-id",
        "name": "Service Name",
        "proxy_endpoint": "https://api.example.com",
        "authentication_method": "api_key",
        "api_key": "your-api-key",
        "has_api_key": true
      }
    ],
    "account_id": "account-id",
    "user": {
      "soeid": "user-id",
      "email": "user@example.com"
    }
  }
}
```

#### 3. Initialize API Key
```
POST /api/services/init
Authorization: Bearer <jwt-token>
Content-Type: application/json

{
  "service_id": "service-id"
}
```
**Response:**
```json
{
  "status": "success",
  "message": "API key initialized",
  "data": {
    "service": {
      "id": "service-id",
      "name": "Service Name",
      "proxy_endpoint": "https://api.example.com",
      "authentication_method": "api_key"
    },
    "api_key": "your-new-api-key",
    "is_new": true,
    "plan": {
      "id": "plan-id",
      "name": "Plan Name"
    },
    "account_id": "account-id"
  }
}
```

### Authentication

All endpoints (except `/api/health`) require a valid JWT token in the Authorization header:
```
Authorization: Bearer <jwt-token>
```

The JWT token must be issued by the configured Keycloak instance and contain valid user information.

## 🔒 Security Considerations

### Implemented Security Features

1. **JWT Token Validation**: All API endpoints validate Keycloak-issued tokens
2. **Security Headers**: Comprehensive security headers on all responses
3. **Input Validation**: Request data validation and sanitization
4. **Secure Password Generation**: Cryptographically secure password generation
5. **Non-root Container**: Container runs as non-root user (uid: 1000)
6. **HTTPS Enforcement**: Strict Transport Security headers
7. **Content Security Policy**: Prevents XSS attacks

### Security Headers Applied

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security: max-age=31536000; includeSubDomains`
- `Content-Security-Policy: default-src 'self'`

## 🧪 Testing

### Manual Testing

**Health Check:**
```bash
curl -X GET http://localhost:5000/api/health
```

**List Services (with auth):**
```bash
curl -X GET http://localhost:5000/api/services \
  -H "Authorization: Bearer <your-jwt-token>"
```

**Initialize API Key:**
```bash
curl -X POST http://localhost:5000/api/services/init \
  -H "Authorization: Bearer <your-jwt-token>" \
  -H "Content-Type: application/json" \
  -d '{"service_id": "your-service-id"}'
```

### Automated Testing Script

Use the provided test script for quick API testing:

```bash
# Make script executable
chmod +x test_api.sh

# Run basic tests
./test_api.sh

# Run with JWT token
./test_api.sh -t "your-jwt-token"

# Run with custom URL and token
./test_api.sh -u "https://your-server.com" -t "your-jwt-token"

# Run with environment variables
BASE_URL="https://your-server.com" JWT_TOKEN="your-jwt-token" ./test_api.sh
```

### Testing with Postman

1. Import the API endpoints into Postman
2. Set up environment variables for base URL and tokens
3. Configure Bearer token authentication
4. Test all endpoints with various scenarios

## 🔍 Code Review Findings

### ✅ Strengths

1. **Security First**: Comprehensive security implementation with JWT validation, security headers, and input validation
2. **Structured Logging**: Uses `structlog` for consistent, structured log output
3. **Error Handling**: Standardized error responses with proper HTTP status codes
4. **Configuration Management**: Proper environment variable handling with validation
5. **Container Security**: Non-root user, minimal base image, health checks
6. **API Design**: RESTful design with consistent response format
7. **Caching**: Implements LRU caching for API calls to improve performance
8. **Production Ready**: Gunicorn WSGI server, proper container configuration

### ⚠️ Areas for Improvement

1. **Input Validation**: Could benefit from more comprehensive input validation using libraries like `marshmallow` or `pydantic`
2. **Rate Limiting**: No rate limiting implemented - consider adding `flask-limiter`
3. **API Documentation**: Missing OpenAPI/Swagger documentation
4. **Testing**: No unit tests visible - should add comprehensive test suite
5. **Monitoring**: No metrics or monitoring endpoints beyond basic health check
6. **Error Details**: Some error responses could provide more detailed information for debugging
7. **Configuration**: Some hardcoded values (like page size: 500) should be configurable
8. **Async Support**: Current implementation is synchronous - consider async for better performance

### 🔧 Recommended Improvements

1. **Add Input Validation Schema**
   ```python
   from marshmallow import Schema, fields, validate

   class ServiceInitSchema(Schema):
       service_id = fields.Str(required=True, validate=validate.Length(min=1))
   ```

2. **Implement Rate Limiting**
   ```python
   from flask_limiter import Limiter
   from flask_limiter.util import get_remote_address

   limiter = Limiter(
       app,
       key_func=get_remote_address,
       default_limits=["200 per day", "50 per hour"]
   )
   ```

3. **Add Comprehensive Testing**
   ```python
   import pytest
   from unittest.mock import patch, MagicMock

   def test_health_check():
       # Test implementation
       pass
   ```

4. **Add OpenAPI Documentation**
   ```python
   from flask_restx import Api, Resource, fields

   api = Api(app, doc='/docs/')
   ```

5. **Add Monitoring Metrics**
   ```python
   from prometheus_flask_exporter import PrometheusMetrics

   metrics = PrometheusMetrics(app)
   ```

## 📊 Performance Considerations

### Current Performance Features

- **Connection Pooling**: Uses `requests.Session` for HTTP connection reuse
- **Caching**: LRU cache for frequently accessed data
- **Efficient Logging**: Structured logging with minimal overhead
- **Gunicorn**: Multi-worker WSGI server for production

### Performance Recommendations

1. **Database Connection Pooling**: If adding database persistence
2. **Redis Caching**: For distributed caching across multiple instances
3. **Async Processing**: For heavy API operations
4. **Load Balancing**: Multiple replicas behind a load balancer

## 🐛 Troubleshooting

### Common Issues

1. **Authentication Failures**
   - Check Keycloak configuration
   - Verify JWT token format and expiration
   - Ensure client configuration matches

2. **3Scale API Errors**
   - Verify admin API key permissions
   - Check network connectivity to 3Scale
   - Validate API endpoint URLs

3. **Container Startup Issues**
   - Check environment variables
   - Verify secrets are properly mounted
   - Review container logs for specific errors

### Debug Commands

```bash
# Check container logs
oc logs deployment/mlaas-helper

# Debug pod
oc debug deployment/mlaas-helper

# Port forward for local testing
oc port-forward service/mlaas-helper 5000:5000
```

## 📝 Monitoring and Logging

### Log Analysis

The application uses structured logging with JSON format. Key log fields:

- `timestamp`: ISO format timestamp
- `level`: Log level (INFO, WARNING, ERROR)
- `logger`: Logger name
- `message`: Human readable message
- `user`: User identifier (when available)
- `ip`: Client IP address
- `error`: Error details (for error logs)

### Monitoring Metrics

- Health check endpoint: `/api/health`
- HTTP response codes and latency
- Authentication success/failure rates
- 3Scale API call success rates

## 🚀 Production Deployment Checklist

### Before Deployment

- [ ] Environment variables configured
- [ ] Secrets properly created and mounted
- [ ] Container image built and pushed
- [ ] Network policies configured
- [ ] Resource limits set appropriately
- [ ] Health checks configured
- [ ] Monitoring and alerting setup
- [ ] Backup and disaster recovery plan

### Post-Deployment

- [ ] Health check endpoint responding
- [ ] Authentication working correctly
- [ ] 3Scale integration functional
- [ ] Logs being collected properly
- [ ] Metrics being recorded
- [ ] Performance within expected ranges

## 📚 Additional Resources

- [Flask Documentation](https://flask.palletsprojects.com/)
- [Keycloak Documentation](https://www.keycloak.org/documentation)
- [3Scale Documentation](https://access.redhat.com/documentation/en-us/red_hat_3scale_api_management/)
- [OpenShift Documentation](https://docs.openshift.com/)
- [Helm Documentation](https://helm.sh/docs/)

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run code quality checks
6. Submit a pull request

## 📄 License

[Add your license information here]

## 👥 Support

For questions and support, please contact:
- MLaaS Team: mlaas-team@example.com
- Documentation: [Internal Wiki Link]
- Issues: [GitHub Issues Link] 