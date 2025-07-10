from flask import Flask, request, jsonify
import os
import requests
import json
import jwt
import datetime
import xml.etree.ElementTree as ET
import logging
import secrets
import string
from functools import wraps, lru_cache
from typing import Union, Optional, Dict, List, Tuple
import structlog

# --- Setup Structured Logging ---
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer()
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger(__name__)

app = Flask(__name__)

# --- Security Headers ---
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    return response

# --- Configuration Validation ---
class ConfigError(Exception):
    """Configuration error exception"""
    pass

def validate_config() -> None:
    """Validate required environment variables on startup"""
    required_vars = [
        'KEYCLOAK_URL', 'KEYCLOAK_REALM', 'KEYCLOAK_CLIENT_ID', 'KEYCLOAK_CLIENT_SECRET',
        'THREESCALE_ADMIN_API_URL', 'THREESCALE_ADMIN_API_KEY'
    ]
    missing = [var for var in required_vars if not os.getenv(var)]
    if missing:
        raise ConfigError(f"Missing required environment variables: {missing}")
    
    # Validate URLs
    keycloak_url = os.getenv('KEYCLOAK_URL')
    threescale_url = os.getenv('THREESCALE_ADMIN_API_URL')
    
    if keycloak_url and not keycloak_url.startswith(('http://', 'https://')):
        raise ConfigError("KEYCLOAK_URL must start with http:// or https://")
    
    if threescale_url and not threescale_url.startswith(('http://', 'https://')):
        raise ConfigError("THREESCALE_ADMIN_API_URL must start with http:// or https://")
    
    logger.info("Configuration validation passed")

# --- Environment Variable Handling ---
def get_env_variable(var_name: str, optional: bool = False, default: Optional[str] = None) -> Optional[str]:
    """
    Retrieves an environment variable.
    Returns None if the variable is not set and is optional.
    """
    value = os.getenv(var_name, default)
    if value is None and not optional:
        logger.error("Missing environment variable", variable=var_name)
        return None
    return value

# --- Password Generation ---
def generate_secure_password(length: int = 16) -> str:
    """Generate a secure random password"""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password

# --- API Request Session ---
api_session = requests.Session()
api_session.headers.update({'User-Agent': 'MLaaS-Helper/1.0'})

def make_api_call(method: str, endpoint: str, params: Optional[dict] = None, 
                  data: Optional[dict] = None, headers: Optional[dict] = None, 
                  is_threescale_admin_api: bool = True, is_json_response: bool = False) -> Optional[Union[ET.Element, dict]]:
    """
    Makes an API call using the shared session with improved error handling.
    """
    base_url = ""
    if is_threescale_admin_api:
        base_url = get_env_variable("THREESCALE_ADMIN_API_URL")
        if not base_url or not base_url.endswith('/'):
            base_url = base_url + '/' if base_url else ''
    
    url = f"{base_url}{endpoint}" if is_threescale_admin_api else endpoint

    logger.debug("Making API request", method=method, url=url, is_threescale=is_threescale_admin_api)

    try:
        response = api_session.request(
            method, url, 
            params=params, 
            data=data, 
            headers=headers, 
            timeout=30
        )
        response.raise_for_status()

        if is_json_response or not is_threescale_admin_api:
            return response.json()
        else:
            return ET.fromstring(response.text)

    except requests.exceptions.Timeout:
        logger.error("API request timeout", url=url, method=method)
        return None
    except requests.exceptions.ConnectionError:
        logger.error("API connection error", url=url, method=method)
        return None
    except requests.exceptions.HTTPError as e:
        logger.error("HTTP error", url=url, method=method, status_code=e.response.status_code)
        return None
    except ET.ParseError as e:
        logger.error("XML parsing error", url=url, error=str(e))
        return None
    except json.JSONDecodeError as e:
        logger.error("JSON parsing error", url=url, error=str(e))
        return None
    except Exception as e:
        logger.error("Unexpected API error", url=url, method=method, error=str(e))
        return None

# --- Token Validation ---
@lru_cache(maxsize=1)
def get_jwks_url() -> Optional[str]:
    """
    Construct and return the JWKS URL for the Keycloak realm.
    """
    keycloak_url = get_env_variable("KEYCLOAK_URL")
    keycloak_realm = get_env_variable("KEYCLOAK_REALM")
    
    if not keycloak_url or not keycloak_realm:
        logger.error("KEYCLOAK_URL or KEYCLOAK_REALM not configured")
        return None
        
    return f"{keycloak_url.rstrip('/') if keycloak_url else ''}/realms/{keycloak_realm}/protocol/openid-connect/certs"

def validate_token(token: str) -> Optional[Dict]:
    """
    Validates a Keycloak-issued JWT token using python-jose library.
    """
    try:
        from jose import jwt as jose_jwt
        from jose.exceptions import JWTError, ExpiredSignatureError, JWTClaimsError
        
        # Get Keycloak configuration
        keycloak_url = get_env_variable("KEYCLOAK_URL")
        keycloak_realm = get_env_variable("KEYCLOAK_REALM")
        keycloak_client_id = get_env_variable("KEYCLOAK_CLIENT_ID")
        
        if not all([keycloak_url, keycloak_realm, keycloak_client_id]):
            logger.error("Keycloak configuration incomplete")
            return None
            
        # Get JWKS URL
        jwks_url = get_jwks_url()
        if not jwks_url:
            logger.error("Could not construct JWKS URL")
            return None
            
        # Fetch JWKS
        response = api_session.get(jwks_url, timeout=10)
        response.raise_for_status()
        jwks = response.json()
        
                 # Expected issuer
         expected_issuer = f"{keycloak_url.rstrip('/') if keycloak_url else ''}/realms/{keycloak_realm}"
        
        # Decode and verify token
        decoded_token = jose_jwt.decode(
            token,
            jwks,
            algorithms=["RS256"],
            audience=keycloak_client_id,
            issuer=expected_issuer
        )
        
        logger.debug("Token validation successful", 
                    user=decoded_token.get('preferred_username'),
                    client_id=decoded_token.get('azp'))
        return decoded_token
        
    except ExpiredSignatureError:
        logger.warning("Token expired")
        return None
    except JWTClaimsError as e:
        logger.warning("JWT claims error", error=str(e))
        return None
    except JWTError as e:
        logger.warning("JWT validation error", error=str(e))
        return None
    except Exception as e:
        logger.error("Token validation error", error=str(e))
        return None

# --- Standard Error Response ---
def create_error_response(message: str, error_code: str = "GENERIC_ERROR", 
                         status_code: int = 500) -> Tuple[Dict, int]:
    """Create standardized error response"""
    return {
        "status": "error",
        "error": {
            "code": error_code,
            "message": message
        }
    }, status_code

def create_success_response(data: Dict, message: str = "Success") -> Tuple[Dict, int]:
    """Create standardized success response"""
    return {
        "status": "success",
        "message": message,
        "data": data
    }, 200

def require_auth(f):
    """
    Decorator to require valid authentication token.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            logger.warning("Missing or invalid authorization header", 
                         ip=request.remote_addr)
            return jsonify(*create_error_response(
                "Missing or invalid authorization header", 
                "MISSING_AUTH", 401
            ))
        
        token = auth_header.split(' ')[1]
        decoded_token = validate_token(token)
        
        if not decoded_token:
            logger.warning("Invalid or expired token", ip=request.remote_addr)
            return jsonify(*create_error_response(
                "Invalid or expired token", 
                "INVALID_TOKEN", 401
            ))
        
        request.user = decoded_token
        return f(*args, **kwargs)
    return decorated_function

# --- User Management Functions ---
def extract_user_id(user_token: Dict) -> str:
    """Extract user ID from token with fallback"""
    return user_token.get('preferred_username') or user_token.get('sub') or user_token.get('email', 'unknown')

# --- 3Scale API Helper Functions ---
def find_account_by_soeid(soeid: str, threescale_admin_api_key: str) -> Optional[str]:
    """
    Find account by SOEID in 3Scale.
    """
    try:
        endpoint = "accounts/find.xml"
        params = {
            "access_token": threescale_admin_api_key,
            "username": soeid
        }
        
        root = make_api_call("GET", endpoint, params=params)
        if root is not None and isinstance(root, ET.Element):
            account_id_element = root.find("id")
            if account_id_element is not None and account_id_element.text:
                logger.debug("Account found", soeid=soeid, account_id=account_id_element.text)
                return account_id_element.text
        
        logger.info("Account not found", soeid=soeid)
        return None
        
    except Exception as e:
        logger.error("Error finding account", soeid=soeid, error=str(e))
        return None

def create_threescale_account_via_signup(soeid: str, email: str, threescale_admin_api_key: str) -> Optional[str]:
    """
    Create new 3Scale account with secure password generation.
    """
    try:
        signup_endpoint = "signup.xml"
        # Generate secure password instead of using hardcoded one
        secure_password = generate_secure_password()
        
        payload = {
            "access_token": threescale_admin_api_key,
            "username": soeid,
            "email": email,
            "org_name": email,
            "password": secure_password,
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/xml"
        }
        
        root = make_api_call("POST", signup_endpoint, data=payload, headers=headers)
        if root is not None and isinstance(root, ET.Element):
            account_id_element = root.find("id")
            if account_id_element is not None and account_id_element.text:
                logger.info("Account created", soeid=soeid, account_id=account_id_element.text)
                return account_id_element.text
        
        logger.error("Failed to create account", soeid=soeid)
        return None
        
    except Exception as e:
        logger.error("Error creating account", soeid=soeid, error=str(e))
        return None

@lru_cache(maxsize=1)
def list_services(threescale_admin_api_key: str) -> List[Dict]:
    """
    List all services from 3Scale with improved error handling.
    """
    try:
        endpoint = "services.xml"
        params = {
            "access_token": threescale_admin_api_key,
            "page": 1,
            "per_page": 500  # Configuration should be externalized
        }
        
        root = make_api_call("GET", endpoint, params=params)
        services = []
        
        if root is not None and isinstance(root, ET.Element):
            for service_element in root.findall("service"):
                service_id = service_element.find("id")
                service_name = service_element.find("name")
                if service_id is not None and service_id.text and service_name is not None and service_name.text:
                    services.append({
                        "id": service_id.text,
                        "name": service_name.text,
                        "backend_api_url": service_element.findtext("backend_api_url")
                    })
        
        logger.info("Services retrieved", count=len(services))
        return services
        
    except Exception as e:
        logger.error("Error listing services", error=str(e))
        return []

@lru_cache(maxsize=32)
def get_proxy_details_for_service(service_id: str, threescale_admin_api_key: str) -> Optional[Dict]:
    """
    Get proxy details for a service.
    """
    endpoint = f"services/{service_id}/proxy.xml"
    params = {
        "access_token": threescale_admin_api_key
    }
    
    root = make_api_call("GET", endpoint, params=params)
    if root is not None and isinstance(root, ET.Element):
        endpoint_element = root.find("endpoint")
        auth_method_element = root.find("authentication_method")
        
        return {
            "endpoint": endpoint_element.text if endpoint_element is not None and endpoint_element.text else "N/A",
            "authentication_method": auth_method_element.text if auth_method_element is not None and auth_method_element.text else "N/A"
        }
    return None

def get_account_applications(account_id: str, threescale_admin_api_key: str) -> List[Dict]:
    """
    Get applications for an account.
    """
    endpoint = f"accounts/{account_id}/applications.xml"
    params = {
        "access_token": threescale_admin_api_key
    }
    
    root = make_api_call("GET", endpoint, params=params)
    applications = []
    if root is not None and isinstance(root, ET.Element):
        for app_element in root.findall("application"):
            app_data = {
                "id": app_element.findtext("id"),
                "name": app_element.findtext("name"),
                "user_key": app_element.findtext("user_key"),
                "service_id": app_element.findtext("service_id")
            }
            plan_element = app_element.find("plan")
            if plan_element is not None:
                app_data["plan_id"] = plan_element.findtext("id")
            
            if all(app_data.get(k) for k in ["id", "name", "user_key", "plan_id", "service_id"]):
                applications.append(app_data)
    return applications

def get_application_plans(service_id: str, threescale_admin_api_key: str) -> List[Dict]:
    """
    Get application plans for a service.
    """
    endpoint = f"services/{service_id}/application_plans.xml"
    params = {
        "access_token": threescale_admin_api_key
    }
    
    root = make_api_call("GET", endpoint, params=params)
    plans = []
    if root is not None and isinstance(root, ET.Element):
        for plan_element in root.findall("plan"):
            plan_id = plan_element.find("id")
            plan_name = plan_element.find("name")
            if plan_id is not None and plan_id.text and plan_name is not None and plan_name.text:
                plans.append({
                    "id": plan_id.text,
                    "name": plan_name.text
                })
    return plans

def register_application(account_id: str, plan_id: str, app_name: str, threescale_admin_api_key: str) -> Optional[Dict]:
    """
    Register a new application.
    """
    endpoint = f"accounts/{account_id}/applications.xml"
    data_payload = {
        "name": app_name,
        "plan_id": plan_id,
        "access_token": threescale_admin_api_key
    }
    
    root = make_api_call("POST", endpoint, data=data_payload)
    if root is not None and isinstance(root, ET.Element):
        application_id = root.findtext("id")
        api_key = root.findtext("user_key")
        
        if application_id and api_key:
            return {"app_id": application_id, "api_key": api_key}
    return None

# --- API Endpoints ---
@app.route('/api/services', methods=['GET'])
@require_auth
def get_services():
    """
    List all services with their API key status for the authenticated user.
    """
    threescale_admin_api_key = get_env_variable("THREESCALE_ADMIN_API_KEY")
    if not threescale_admin_api_key:
        return jsonify(*create_error_response(
            "Server configuration error", 
            "CONFIG_ERROR", 500
        ))
    
    soeid = extract_user_id(request.user)
    if not soeid:
        return jsonify(*create_error_response(
            "Unable to determine user ID from token", 
            "USER_ID_ERROR", 400
        ))
    
    # Get account info
    account_id = find_account_by_soeid(soeid, threescale_admin_api_key)
    if not account_id:
        return jsonify(*create_error_response(
            "Account not found in 3Scale", 
            "ACCOUNT_NOT_FOUND", 404
        ))
    
    # Get services and applications
    all_services = list_services(threescale_admin_api_key)
    existing_applications = get_account_applications(account_id, threescale_admin_api_key)
    
    # Create mapping of service_id to api_key
    existing_service_info = {app['service_id']: app['user_key'] for app in existing_applications}
    
    # Enrich services with proxy details and API key status
    services_with_details = []
    for service in all_services:
        proxy_details = get_proxy_details_for_service(service['id'], threescale_admin_api_key)
        service_info = {
            'id': service['id'],
            'name': service['name'],
            'proxy_endpoint': proxy_details['endpoint'] if proxy_details else 'N/A',
            'authentication_method': proxy_details['authentication_method'] if proxy_details else 'N/A',
            'api_key': existing_service_info.get(service['id'], 'N/A'),
            'has_api_key': service['id'] in existing_service_info
        }
        services_with_details.append(service_info)
    
    return jsonify(*create_success_response({
        'services': services_with_details,
        'account_id': account_id,
        'user': {
            'soeid': soeid,
            'email': request.user.get('email')
        }
    }, "Services retrieved"))

@app.route('/api/services/init', methods=['POST'])
@require_auth
def init_api_key():
    """
    Initialize (get/create) an API key for a specific service.
    """
    data = request.get_json()
    if not data or 'service_id' not in data:
        return jsonify(*create_error_response(
            "service_id is required", 
            "MISSING_SERVICE_ID", 400
        ))
    
    service_id = data['service_id']
    threescale_admin_api_key = get_env_variable("THREESCALE_ADMIN_API_KEY")
    if not threescale_admin_api_key:
        return jsonify(*create_error_response(
            "Server configuration error", 
            "CONFIG_ERROR", 500
        ))
    
    soeid = extract_user_id(request.user)
    email = request.user.get('email')
    
    if not soeid or not email:
        return jsonify(*create_error_response(
            "Unable to determine user info from token", 
            "USER_INFO_ERROR", 400
        ))
    
    # Find or create account
    account_id = find_account_by_soeid(soeid, threescale_admin_api_key)
    if not account_id:
        # Create account (need password for 3Scale account creation)
        account_id = create_threescale_account_via_signup(soeid, email, threescale_admin_api_key)
        if not account_id:
            return jsonify(*create_error_response(
                "Failed to create 3Scale account", 
                "ACCOUNT_CREATION_FAILED", 500
            ))
    
    # Verify service exists
    all_services = list_services(threescale_admin_api_key)
    selected_service = next((s for s in all_services if s['id'] == service_id), None)
    if not selected_service:
        return jsonify(*create_error_response(
            "Service not found", 
            "SERVICE_NOT_FOUND", 404
        ))
    
    # Get application plans
    application_plans = get_application_plans(service_id, threescale_admin_api_key)
    if not application_plans:
        return jsonify(*create_error_response(
            "No application plans found for service", 
            "NO_PLANS_FOUND", 500
        ))
    
    target_plan = application_plans[0]  # Use first plan
    
    # Check for existing application
    existing_applications = get_account_applications(account_id, threescale_admin_api_key)
    existing_app = next((app for app in existing_applications 
                        if app['service_id'] == service_id and app['plan_id'] == target_plan['id']), None)
    
    if existing_app:
        api_key = existing_app['user_key']
        is_new = False
    else:
        # Create new application
        app_name = f"helix-app-{soeid}-{service_id}-{target_plan['id']}-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}"
        new_app = register_application(account_id, target_plan['id'], app_name, threescale_admin_api_key)
        if not new_app:
            return jsonify(*create_error_response(
                "Failed to create application", 
                "APPLICATION_CREATION_FAILED", 500
            ))
        
        api_key = new_app['api_key']
        is_new = True
    
    # Get proxy details
    proxy_details = get_proxy_details_for_service(service_id, threescale_admin_api_key)
    
    return jsonify(*create_success_response({
        'service': {
            'id': selected_service['id'],
            'name': selected_service['name'],
            'proxy_endpoint': proxy_details['endpoint'] if proxy_details else 'N/A',
            'authentication_method': proxy_details['authentication_method'] if proxy_details else 'N/A'
        },
        'api_key': api_key,
        'is_new': is_new,
        'plan': target_plan,
        'account_id': account_id
    }, "API key initialized"))

@app.route('/api/health', methods=['GET'])
def health_check():
    """
    Health check endpoint.
    """
    return jsonify(*create_success_response({'status': 'healthy'}, "Health check successful"))

if __name__ == '__main__':
    try:
        # Validate configuration on startup
        validate_config()
        
        # For production, use gunicorn or another WSGI server
        # This is for development only
        debug_mode = os.getenv('FLASK_ENV', 'production') == 'development'
        
        logger.info("Starting MLaaS helper", debug=debug_mode)
        app.run(host='0.0.0.0', port=5000, debug=debug_mode)
        
    except ConfigError as e:
        logger.error("Configuration validation failed", error=str(e))
        exit(1)
    except Exception as e:
        logger.error("Server startup failed", error=str(e))
        exit(1) 