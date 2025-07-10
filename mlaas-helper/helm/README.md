# MLaaS Helper Helm Chart

This Helm chart deploys the MLaaS Helper Flask application, which provides a REST API for managing 3Scale API operations with Keycloak authentication.

## Features

- **Flask Application**: REST API server with structured logging
- **JWT Authentication**: Keycloak-based token validation
- **3Scale Integration**: API key management and service registration
- **Security**: Non-root user, security headers, and secure password generation
- **Health Checks**: Comprehensive health monitoring with startup, liveness, and readiness probes
- **Configuration Management**: Environment-based configuration with ConfigMaps and Secrets
- **Pip Configuration**: Support for artifactory/private PyPI repositories

## Prerequisites

- Kubernetes 1.16+
- Helm 3.0+
- OpenShift 4.x+ (for Route support)

## Installation

### Basic Installation

```bash
helm install mlaas-helper ./helm-chart
```

### Installation with Custom Values

```bash
# Copy and modify the example values file
cp ./helm-chart/values-example.yaml my-values.yaml
# Edit my-values.yaml with your configuration
# Then install
helm install mlaas-helper ./helm-chart -f my-values.yaml
```

## Configuration

### Required Environment Variables

The application requires the following environment variables to be set:

```yaml
env:
  KEYCLOAK_URL: "https://your-keycloak-instance.com"
  KEYCLOAK_REALM: "your-realm"
  KEYCLOAK_CLIENT_ID: "your-client-id"
  THREESCALE_ADMIN_API_URL: "https://your-3scale-admin.com"
```

**⚠️ IMPORTANT**: The chart includes validation that will fail deployment if these variables are not properly configured with actual values (not placeholder values).

### Required Secrets

The following secrets must be provided:

```yaml
secrets:
  THREESCALE_ADMIN_API_KEY: "your-3scale-admin-api-key"
  # Optional: For private PyPI repositories
  ARTIFACTORY_USERNAME: "your-artifactory-username"
  ARTIFACTORY_PASSWORD: "your-artifactory-password"
  ARTIFACTORY_URL: "https://your-artifactory-instance.com"
```

### Configuration Validation

The chart includes built-in validation that checks:
- ✅ Required environment variables are set with actual values
- ✅ Required secrets are provided
- ✅ URLs have proper format (http:// or https://)
- ✅ No placeholder values are used

To disable validation (not recommended for production):
```yaml
validation:
  enabled: false
```

### Quick Start with Example Values

A complete example values file is provided at `values-example.yaml`. This file includes:
- ✅ All required configuration sections
- ✅ Detailed comments and examples
- ✅ Production and development configurations
- ✅ Security best practices

Copy and modify this file for your deployment:
```bash
cp ./helm-chart/values-example.yaml my-values.yaml
# Edit my-values.yaml with your actual configuration
helm install mlaas-helper ./helm-chart -f my-values.yaml
```

### Minimal Values File Example

```yaml
# values.yaml
replicaCount: 2

image:
  repository: your-registry/mlaas-helper
  tag: "v1.0.0"
  pullPolicy: IfNotPresent

env:
  KEYCLOAK_URL: "https://keycloak.example.com"
  KEYCLOAK_REALM: "mlaas"
  KEYCLOAK_CLIENT_ID: "mlaas-helper"
  THREESCALE_ADMIN_API_URL: "https://3scale-admin.example.com/admin/api"

secrets:
  THREESCALE_ADMIN_API_KEY: "your-secret-key"

route:
  enabled: true
  host: "mlaas-helper.apps.example.com"
  tls:
    termination: edge
    insecureEdgeTerminationPolicy: Redirect

resources:
  limits:
    cpu: 1000m
    memory: 1Gi
  requests:
    cpu: 200m
    memory: 256Mi

pip:
  enabled: true
  trustedHost: "artifactory.example.com"
  indexUrl: "https://artifactory.example.com/artifactory/api/pypi/pypi-virtual/simple"

# Configuration validation (enabled by default)
validation:
  enabled: true
  failOnMissingConfig: true
```

## Application Endpoints

The Flask application exposes the following endpoints:

- `GET /api/health` - Health check endpoint
- `GET /api/services` - List all services with API key status (requires authentication)
- `POST /api/services/init` - Initialize API key for a service (requires authentication)

## Authentication

All API endpoints (except `/api/health`) require a valid JWT token from Keycloak:

```bash
curl -H "Authorization: Bearer <your-jwt-token>" \
     https://mlaas-helper.apps.example.com/api/services
```

## Health Monitoring

The chart configures three types of health checks:

1. **Startup Probe**: Allows up to 5 minutes for the application to start
2. **Liveness Probe**: Restarts the container if the application becomes unresponsive
3. **Readiness Probe**: Removes the pod from service if it's not ready to handle requests

## Security Features

- **Non-root User**: Application runs as user 1000 (appuser)
- **Security Headers**: Automatic security headers on all responses
- **Secure Password Generation**: Uses cryptographically secure random password generation
- **JWT Validation**: Proper JWT token validation with Keycloak

## Troubleshooting

### Common Issues

1. **Configuration Validation Failed**: Check that all required environment variables are set
2. **Token Validation Error**: Verify Keycloak URL, realm, and client ID configuration
3. **3Scale API Connection Error**: Check the 3Scale admin API URL and key
4. **Helm Validation Errors**: See the validation error troubleshooting section below

### Helm Validation Errors

The chart includes validation that may fail with these errors:

**❌ "Required environment variable 'KEYCLOAK_URL' has placeholder value"**
```bash
# Fix: Update values.yaml with your actual Keycloak URL
env:
  KEYCLOAK_URL: "https://your-actual-keycloak-url.com"
```

**❌ "Required environment variable 'KEYCLOAK_REALM' is empty"**
```bash
# Fix: Set your actual Keycloak realm
env:
  KEYCLOAK_REALM: "your-actual-realm"
```

**❌ "Required secret 'THREESCALE_ADMIN_API_KEY' is empty"**
```bash
# Fix: Set your actual 3Scale admin API key
secrets:
  THREESCALE_ADMIN_API_KEY: "your-actual-api-key"
```

**❌ "KEYCLOAK_URL must start with http:// or https://"**
```bash
# Fix: Ensure URL has proper protocol
env:
  KEYCLOAK_URL: "https://keycloak.example.com"  # ✅ Correct
  # KEYCLOAK_URL: "keycloak.example.com"       # ❌ Wrong
```

### Validation Override (Not Recommended)

For testing purposes only, you can disable validation:
```yaml
validation:
  enabled: false
```

### Logs

To view application logs:

```bash
kubectl logs -f deployment/mlaas-helper
```

### Health Check

To verify the application is running:

```bash
curl https://mlaas-helper.apps.example.com/api/health
```

### Debug Configuration

To check the validation status:
```bash
kubectl get configmap mlaas-helper-validation -o yaml
```

## Scaling

To scale the application:

```bash
helm upgrade mlaas-helper ./helm-chart --set replicaCount=3
```

Or enable horizontal pod autoscaling:

```yaml
autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70
```

## Monitoring

The application uses structured logging with JSON format for easy parsing by log aggregation systems.

## Development

For development deployments:

```yaml
env:
  FLASK_ENV: development

resources:
  limits:
    cpu: 500m
    memory: 512Mi
  requests:
    cpu: 100m
    memory: 128Mi
```

## Contributing

1. Make changes to the chart templates
2. Update the Chart.yaml version
3. Test the changes with `helm template` or `helm install --dry-run`
4. Update this README if needed

## License

This chart is part of the MLaaS project. 