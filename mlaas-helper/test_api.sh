#!/bin/bash

# MLaaS Helper API Testing Script
# This script helps test the MLaaS helper API endpoints

set -e

# Configuration
BASE_URL="${BASE_URL:-http://localhost:5000}"
JWT_TOKEN="${JWT_TOKEN:-}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Test functions
test_health_check() {
    log_info "Testing health check endpoint..."
    response=$(curl -s -w "%{http_code}" "$BASE_URL/api/health" -o /tmp/health_response.json)
    http_code="${response: -3}"
    
    if [ "$http_code" -eq 200 ]; then
        log_info "✓ Health check passed"
        cat /tmp/health_response.json | jq .
    else
        log_error "✗ Health check failed with code $http_code"
        cat /tmp/health_response.json
    fi
    echo
}

test_services_without_auth() {
    log_info "Testing services endpoint without authentication (should fail)..."
    response=$(curl -s -w "%{http_code}" "$BASE_URL/api/services" -o /tmp/services_noauth_response.json)
    http_code="${response: -3}"
    
    if [ "$http_code" -eq 401 ]; then
        log_info "✓ Services endpoint correctly requires authentication"
        cat /tmp/services_noauth_response.json | jq .
    else
        log_error "✗ Services endpoint should require authentication but returned $http_code"
        cat /tmp/services_noauth_response.json
    fi
    echo
}

test_services_with_auth() {
    if [ -z "$JWT_TOKEN" ]; then
        log_warn "JWT_TOKEN not set, skipping authenticated tests"
        return
    fi
    
    log_info "Testing services endpoint with authentication..."
    response=$(curl -s -w "%{http_code}" "$BASE_URL/api/services" \
        -H "Authorization: Bearer $JWT_TOKEN" \
        -o /tmp/services_auth_response.json)
    http_code="${response: -3}"
    
    if [ "$http_code" -eq 200 ]; then
        log_info "✓ Services endpoint with auth succeeded"
        cat /tmp/services_auth_response.json | jq .
    else
        log_error "✗ Services endpoint with auth failed with code $http_code"
        cat /tmp/services_auth_response.json
    fi
    echo
}

test_init_api_key() {
    if [ -z "$JWT_TOKEN" ]; then
        log_warn "JWT_TOKEN not set, skipping init API key test"
        return
    fi
    
    if [ -z "$SERVICE_ID" ]; then
        log_warn "SERVICE_ID not set, skipping init API key test"
        return
    fi
    
    log_info "Testing init API key endpoint..."
    response=$(curl -s -w "%{http_code}" "$BASE_URL/api/services/init" \
        -H "Authorization: Bearer $JWT_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{\"service_id\": \"$SERVICE_ID\"}" \
        -o /tmp/init_response.json)
    http_code="${response: -3}"
    
    if [ "$http_code" -eq 200 ]; then
        log_info "✓ Init API key succeeded"
        cat /tmp/init_response.json | jq .
    else
        log_error "✗ Init API key failed with code $http_code"
        cat /tmp/init_response.json
    fi
    echo
}

# Check dependencies
check_dependencies() {
    if ! command -v curl &> /dev/null; then
        log_error "curl is required but not installed"
        exit 1
    fi
    
    if ! command -v jq &> /dev/null; then
        log_warn "jq is not installed, JSON output will not be formatted"
    fi
}

# Main execution
main() {
    log_info "Starting MLaaS Helper API Tests"
    log_info "Base URL: $BASE_URL"
    
    if [ -n "$JWT_TOKEN" ]; then
        log_info "JWT Token: ${JWT_TOKEN:0:20}..."
    else
        log_warn "No JWT token provided, some tests will be skipped"
    fi
    
    echo "========================"
    
    check_dependencies
    
    test_health_check
    test_services_without_auth
    test_services_with_auth
    test_init_api_key
    
    log_info "API tests completed"
    
    # Cleanup
    rm -f /tmp/health_response.json /tmp/services_noauth_response.json /tmp/services_auth_response.json /tmp/init_response.json
}

# Usage information
usage() {
    echo "Usage: $0 [options]"
    echo
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  -u, --url URL       Base URL for the API (default: http://localhost:5000)"
    echo "  -t, --token TOKEN   JWT token for authentication"
    echo "  -s, --service-id ID Service ID for init API key test"
    echo
    echo "Environment variables:"
    echo "  BASE_URL            Base URL for the API"
    echo "  JWT_TOKEN           JWT token for authentication"
    echo "  SERVICE_ID          Service ID for init API key test"
    echo
    echo "Examples:"
    echo "  $0                                    # Basic tests"
    echo "  $0 -u http://localhost:5000          # Custom URL"
    echo "  $0 -t eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9... # With JWT token"
    echo "  BASE_URL=http://localhost:5000 JWT_TOKEN=eyJ... $0 # Using environment variables"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            exit 0
            ;;
        -u|--url)
            BASE_URL="$2"
            shift 2
            ;;
        -t|--token)
            JWT_TOKEN="$2"
            shift 2
            ;;
        -s|--service-id)
            SERVICE_ID="$2"
            shift 2
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Run main function
main 