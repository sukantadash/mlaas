#!/usr/bin/env python3
import requests
import json
import argparse
import getpass
import sys
import os
import logging
import time
import urllib.parse
from typing import Optional, Dict, Any, List, Union
from tabulate import tabulate
import configparser

# --- Setup Logging ---
logging.basicConfig(
    level=logging.ERROR,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# --- Hardcoded Configuration ---
DEFAULT_KEYCLOAK_URL = "https://keycloak.prod.example.com"
DEFAULT_KEYCLOAK_REALM = "mlaas"
DEFAULT_KEYCLOAK_CLIENT_ID = "mlaas-client"
DEFAULT_MLAAS_HELPER_URL = "https://mlaas-helper.prod.example.com"

# --- Configuration Management ---
CONFIG_DIR = os.path.expanduser("~")
CONFIG_FILE_NAME = ".mlaas_client_config.ini"
CONFIG_FILE_PATH = os.path.join(CONFIG_DIR, CONFIG_FILE_NAME)

class MLaaSClientError(Exception):
    """Base exception for MLaaS client errors"""
    pass

class AuthenticationError(MLaaSClientError):
    """Authentication related errors"""
    pass

class ServerError(MLaaSClientError):
    """Server related errors"""
    pass

class ConfigurationError(MLaaSClientError):
    """Configuration related errors"""
    pass

class KeycloakAuthClient:
    """Handle Keycloak authentication using OAuth2 flow"""
    
    def __init__(self, keycloak_url: str, realm: str, client_id: str):
        self.keycloak_url = keycloak_url.rstrip('/')
        self.realm = realm
        self.client_id = client_id
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'MLaaS-Client/1.0',
            'Accept': 'application/json'
        })
    
    def get_token_endpoint(self) -> str:
        """Get the token endpoint URL"""
        return f"{self.keycloak_url}/realms/{self.realm}/protocol/openid-connect/token"
    
    def authenticate_with_password(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """Authenticate using username/password flow"""
        try:
            token_url = self.get_token_endpoint()
            
            data = {
                'grant_type': 'password',
                'client_id': self.client_id,
                'username': username,
                'password': password,
                'scope': 'openid profile email'
            }
            
            response = self.session.post(
                token_url,
                data=data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                timeout=30
            )
            
            if response.status_code == 200:
                token_data = response.json()
                logger.debug("Authentication successful with Keycloak")
                return token_data
            else:
                logger.error(f"Keycloak authentication failed: {response.status_code}")
                try:
                    error_data = response.json()
                    logger.error(f"Error details: {error_data}")
                except:
                    logger.error(f"Error response: {response.text}")
                return None
                
        except requests.exceptions.Timeout:
            logger.error("Keycloak authentication timeout")
            return None
        except requests.exceptions.ConnectionError:
            logger.error("Connection error to Keycloak")
            return None
        except Exception as e:
            logger.error(f"Keycloak authentication error: {e}")
            return None

class MLaaSClient:
    def __init__(self, mlaas_helper_url: Optional[str] = None, keycloak_url: Optional[str] = None, 
                 keycloak_realm: Optional[str] = None, keycloak_client_id: Optional[str] = None):
        # Use hardcoded values with fallback to parameters
        self.mlaas_helper_url = mlaas_helper_url or DEFAULT_MLAAS_HELPER_URL
        self.keycloak_url = keycloak_url or DEFAULT_KEYCLOAK_URL
        self.keycloak_realm = keycloak_realm or DEFAULT_KEYCLOAK_REALM
        self.keycloak_client_id = keycloak_client_id or DEFAULT_KEYCLOAK_CLIENT_ID
        
        # Validate URLs
        self.mlaas_helper_url = self._validate_server_url(self.mlaas_helper_url)
        self.keycloak_url = self._validate_server_url(self.keycloak_url)
        
        # Initialize HTTP session
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'MLaaS-Client/1.0',
            'Accept': 'application/json'
        })
        
        # Initialize Keycloak client
        self.keycloak_client = KeycloakAuthClient(
            self.keycloak_url, self.keycloak_realm, self.keycloak_client_id
        )
        
        # Load configuration and tokens
        self.config = self.load_config()
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.token_expires_at: Optional[int] = None
        
        logger.info(f"MLaaS Client initialized:")
        logger.info(f"  MLaaS Helper URL: {self.mlaas_helper_url}")
        logger.info(f"  Keycloak URL: {self.keycloak_url}")
        logger.info(f"  Keycloak Realm: {self.keycloak_realm}")
        logger.info(f"  Keycloak Client ID: {self.keycloak_client_id}")
    
    def _validate_server_url(self, url: str) -> str:
        """Validate and normalize server URL"""
        if not url:
            raise ConfigurationError("Server URL cannot be empty")
        
        if not url.startswith(('http://', 'https://')):
            raise ConfigurationError("Server URL must start with http:// or https://")
        
        try:
            parsed = urllib.parse.urlparse(url)
            if not parsed.netloc:
                raise ConfigurationError("Invalid server URL format")
        except Exception as e:
            raise ConfigurationError(f"Invalid server URL: {e}")
        
        return url.rstrip('/')
        
    def load_config(self) -> configparser.ConfigParser:
        """Load configuration from file with error handling."""
        config = configparser.ConfigParser()
        if os.path.exists(CONFIG_FILE_PATH):
            try:
                config.read(CONFIG_FILE_PATH)
                logger.debug(f"Configuration loaded from {CONFIG_FILE_PATH}")
            except configparser.Error as e:
                logger.error(f"Error reading config file: {e}")
                # Don't fail, just use empty config
        return config
    
    def save_config(self):
        """Save configuration to file with error handling."""
        try:
            os.makedirs(CONFIG_DIR, exist_ok=True)
            with open(CONFIG_FILE_PATH, 'w') as f:
                self.config.write(f)
            logger.debug(f"Configuration saved to {CONFIG_FILE_PATH}")
        except IOError as e:
            logger.error(f"Error saving config: {e}")
            raise ConfigurationError(f"Failed to save configuration: {e}")
    
    def get_stored_token(self) -> Optional[str]:
        """Get stored access token from config."""
        return self.config.get('auth', 'access_token', fallback=None)
    
    def get_stored_refresh_token(self) -> Optional[str]:
        """Get stored refresh token from config."""
        return self.config.get('auth', 'refresh_token', fallback=None)
    
    def store_tokens(self, access_token: str, refresh_token: Optional[str] = None, expires_in: Optional[int] = None):
        """Store tokens in config."""
        if not self.config.has_section('auth'):
            self.config.add_section('auth')
        
        self.config.set('auth', 'access_token', access_token)
        self.access_token = access_token
        
        if refresh_token:
            self.config.set('auth', 'refresh_token', refresh_token)
            self.refresh_token = refresh_token
        
        if expires_in:
            expires_at = int(time.time()) + expires_in
            self.config.set('auth', 'expires_at', str(expires_at))
            self.token_expires_at = expires_at
        
        self.save_config()
    
    def clear_tokens(self):
        """Clear stored tokens."""
        if self.config.has_section('auth'):
            self.config.remove_section('auth')
            self.save_config()
        
        self.access_token = None
        self.refresh_token = None
        self.token_expires_at = None
        logger.info("Authentication tokens cleared")
    
    def is_token_expired(self) -> bool:
        """Check if the current token is expired."""
        if not self.token_expires_at:
            return True
        
        # Add 60 second buffer
        return time.time() >= (self.token_expires_at - 60)
    
    def _handle_response(self, response: requests.Response) -> Optional[Dict[str, Any]]:
        """Handle API response with proper error handling"""
        try:
            if response.status_code == 200:
                data = response.json()
                # Handle both old and new response formats
                if isinstance(data, dict) and data.get('status') == 'success':
                    return data.get('data', data)
                return data
            
            # Handle error responses
            try:
                error_data = response.json()
                if isinstance(error_data, dict):
                    if 'error' in error_data:
                        if isinstance(error_data['error'], dict):
                            error_msg = error_data['error'].get('message', 'Unknown error')
                            error_code = error_data['error'].get('code', 'UNKNOWN')
                        else:
                            error_msg = str(error_data['error'])
                            error_code = 'UNKNOWN'
                        print(f"Error [{error_code}]: {error_msg}")
                    else:
                        print(f"Error: {error_data}")
                else:
                    print(f"Error: {error_data}")
            except:
                print(f"HTTP Error {response.status_code}: {response.text}")
            
            return None
            
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON response: {response.text}")
            print(f"Invalid response format from server")
            return None
        except Exception as e:
            logger.error(f"Error handling response: {e}")
            print(f"Error processing server response: {e}")
            return None
    
    def make_request(self, method: str, endpoint: str, data: Optional[Dict] = None, 
                    require_auth: bool = True, retry_count: int = 0) -> Optional[Dict[str, Any]]:
        """Make HTTP request to MLaaS Helper with retry logic."""
        url = f"{self.mlaas_helper_url}{endpoint}"
        headers = {'Content-Type': 'application/json'}
        
        if require_auth:
            # Load token if not already loaded
            if not self.access_token:
                self.access_token = self.get_stored_token()
                if self.config.has_option('auth', 'expires_at'):
                    try:
                        self.token_expires_at = int(self.config.get('auth', 'expires_at'))
                    except:
                        self.token_expires_at = None
            
            # Check if token is expired and try to refresh
            if self.access_token and self.is_token_expired():
                logger.info("Token expired, attempting to refresh...")
                if not self.refresh_access_token():
                    logger.info("Token refresh failed, requiring re-authentication")
                    self.clear_tokens()
                    self.access_token = None
            
            # If we have a token, use it
            if self.access_token:
                headers['Authorization'] = f'Bearer {self.access_token}'
            else:
                # No valid token, require authentication
                logger.info("Authentication required")
                if not self.authenticate():
                    raise AuthenticationError("Authentication failed")
                if self.access_token:
                    headers['Authorization'] = f'Bearer {self.access_token}'
        
        try:
            logger.debug(f"Making {method} request to {url}")
            response = self.session.request(
                method, url, 
                json=data if data else None, 
                headers=headers,
                timeout=30
            )
            
            # Handle authentication errors
            if response.status_code == 401 and require_auth:
                if retry_count == 0:  # Only retry auth once
                    logger.info("Authentication required or token expired")
                    self.clear_tokens()
                    if self.authenticate():
                        if self.access_token:
                            headers['Authorization'] = f'Bearer {self.access_token}'
                        return self.make_request(method, endpoint, data, require_auth, retry_count + 1)
                    else:
                        raise AuthenticationError("Authentication failed")
                else:
                    raise AuthenticationError("Authentication failed after retry")
            
            return self._handle_response(response)
                
        except requests.exceptions.Timeout:
            logger.error(f"Request timeout: {url}")
            print(f"Request timeout. Server may be unavailable.")
            return None
        except requests.exceptions.ConnectionError:
            logger.error(f"Connection error: {url}")
            print(f"Connection error. Please check server connectivity.")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            print(f"Request failed: {e}")
            return None
        except (AuthenticationError, ServerError) as e:
            print(f"Error: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            print(f"Unexpected error: {e}")
            return None
    
    def refresh_access_token(self) -> bool:
        """Try to refresh the access token using refresh token."""
        refresh_token = self.get_stored_refresh_token()
        if not refresh_token:
            return False
        
        try:
            token_url = self.keycloak_client.get_token_endpoint()
            
            data = {
                'grant_type': 'refresh_token',
                'client_id': self.keycloak_client_id,
                'refresh_token': refresh_token
            }
            
            response = self.session.post(
                token_url,
                data=data,
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                timeout=30
            )
            
            if response.status_code == 200:
                token_data = response.json()
                self.store_tokens(
                    token_data['access_token'],
                    token_data.get('refresh_token', refresh_token),
                    token_data.get('expires_in')
                )
                logger.info("Token refreshed successfully")
                return True
            else:
                logger.warning(f"Token refresh failed: {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Error refreshing token: {e}")
            return False
    
    def authenticate(self) -> bool:
        """Authenticate with Keycloak with improved error handling."""
        try:
            print("\n--- Authentication Required ---")
            logger.info(f"Authenticating with Keycloak: {self.keycloak_url}")
            logger.info(f"Realm: {self.keycloak_realm}")
            logger.info(f"Client: {self.keycloak_client_id}")
            
            # Get default username from system
            default_username = os.getenv('USER', os.getenv('USERNAME', ''))
            username_prompt = f"Enter username (default: {default_username}): " if default_username else "Enter username: "
            
            username = input(username_prompt).strip()
            if not username and default_username:
                username = default_username
            
            if not username:
                print("Username is required.")
                return False
            
            password = getpass.getpass("Enter password: ")
            if not password:
                print("Password is required.")
                return False
            
            # Authenticate with Keycloak
            logger.info("Authenticating with Keycloak...")
            token_data = self.keycloak_client.authenticate_with_password(username, password)
            
            if token_data and 'access_token' in token_data:
                self.store_tokens(
                    token_data['access_token'],
                    token_data.get('refresh_token'),
                    token_data.get('expires_in')
                )
                print(f"✓ Authentication successful! Welcome, {username}")
                logger.info(f"Authentication successful for user: {username}")
                return True
            else:
                print("✗ Authentication failed. Please check your credentials.")
                logger.warning(f"Authentication failed for user: {username}")
                return False
                
        except KeyboardInterrupt:
            print("\nAuthentication cancelled.")
            return False
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            print(f"Authentication error: {e}")
            return False
    
    def list_services(self) -> None:
        """List all available services with improved formatting."""
        print("\n--- Listing Services ---")
        
        try:
            response = self.make_request('GET', '/api/services')
            if not response:
                print("Failed to retrieve services.")
                return
            
            services = response.get('services', [])
            user_info = response.get('user', {})
            
            if user_info:
                print(f"User: {user_info.get('soeid', 'Unknown')} ({user_info.get('email', 'No email')})")
                logger.info(f"Account ID: {response.get('account_id', 'Unknown')}")
            
            if not services:
                print("No services found.")
                return
            
            # Prepare table data
            headers = ["ID", "Service Name", "Proxy Endpoint", "Auth Method", "API Key Status"]
            table_data = []
            
            for service in services:
                api_key_status = "✓ Available" if service.get('has_api_key') else "✗ Not Available"
                api_key_display = service.get('api_key', 'N/A')
                if api_key_display != 'N/A' and len(api_key_display) > 20:
                    api_key_display = f"{api_key_display[:8]}...{api_key_display[-8:]}"
                
                table_data.append([
                    service.get('id', 'N/A'),
                    service.get('name', 'N/A'),
                    service.get('proxy_endpoint', 'N/A'),
                    service.get('authentication_method', 'N/A'),
                    api_key_status
                ])
            
            print(f"\nFound {len(services)} services:")
            print(tabulate(table_data, headers=headers, tablefmt="grid"))
            
            # Show services without API keys
            services_without_keys = [s for s in services if not s.get('has_api_key')]
            if services_without_keys:
                print(f"\nServices without API keys ({len(services_without_keys)}):")
                for service in services_without_keys:
                    print(f"  - {service.get('name')} (ID: {service.get('id')})")
                print("\nUse --init id=<service_id> to initialize API keys for services.")
            else:
                print("\n✓ All services have API keys")
                
        except Exception as e:
            logger.error(f"Error listing services: {e}")
            print(f"Error listing services: {e}")
    
    def init_api_key(self, service_identifier: str) -> None:
        """Initialize API key for a service with improved error handling."""
        print(f"\n--- Initializing API Key for Service: {service_identifier} ---")
        
        try:
            # Parse service identifier
            if '=' in service_identifier:
                identifier_type, identifier_value = service_identifier.split('=', 1)
                identifier_type = identifier_type.strip().lower()
                identifier_value = identifier_value.strip()
            else:
                print("Error: Invalid service identifier format. Use 'id=<service_id>' or 'name=<service_name>'")
                return
            
            if identifier_type not in ['id', 'name']:
                print("Error: Invalid identifier type. Use 'id' or 'name'")
                return
            
            # First, get the list of services to find the service ID
            logger.info("Fetching services list")
            services_response = self.make_request('GET', '/api/services')
            if not services_response:
                print("Failed to get services list.")
                return
            
            services = services_response.get('services', [])
            selected_service = None
            
            for service in services:
                if identifier_type == 'id' and service.get('id') == identifier_value:
                    selected_service = service
                    break
                elif identifier_type == 'name' and service.get('name', '').lower() == identifier_value.lower():
                    selected_service = service
                    break
            
            if not selected_service:
                print(f"Error: Service with {identifier_type} '{identifier_value}' not found.")
                print("Available services:")
                for service in services[:5]:  # Show first 5
                    print(f"  - {service.get('name')} (ID: {service.get('id')})")
                return
            
            service_id = selected_service['id']
            
            # Initialize API key
            logger.info(f"Initializing API key for service: {selected_service.get('name')}")
            response = self.make_request(
                'POST', 
                '/api/services/init',
                data={'service_id': service_id}
            )
            
            if not response:
                print("Failed to initialize API key.")
                return
            
            service_info = response.get('service', {})
            api_key = response.get('api_key')
            is_new = response.get('is_new', False)
            plan_info = response.get('plan', {})
            
            print(f"\n✓ API Key {'Generated' if is_new else 'Retrieved'} Successfully")
            print(f"Service: {service_info.get('name', 'Unknown')} (ID: {service_info.get('id')})")
            print(f"Proxy Endpoint: {service_info.get('proxy_endpoint', 'N/A')}")
            print(f"Authentication Method: {service_info.get('authentication_method', 'N/A')}")
            print(f"Application Plan: {plan_info.get('name', 'Unknown')} (ID: {plan_info.get('id')})")
            print(f"API Key: {api_key}")
            
            print(f"\nYou can now use this API key to access the service at:")
            print(f"  {service_info.get('proxy_endpoint', 'N/A')}")
            print(f"\nExample usage:")
            print(f"  curl -H 'X-API-Key: {api_key}' '{service_info.get('proxy_endpoint', 'N/A')}'")
            
        except Exception as e:
            logger.error(f"Error initializing API key: {e}")
            print(f"Error initializing API key: {e}")
    
    def health_check(self) -> None:
        """Check server health with detailed information."""
        print("\n--- MLaaS Helper Health Check ---")
        
        try:
            start_time = time.time()
            response = self.make_request('GET', '/api/health', require_auth=False)
            response_time = time.time() - start_time
            
            if response:
                status = response.get('status', 'Unknown')
                print(f"✓ Server Status: {status}")
                print(f"✓ Response Time: {response_time:.2f}s")
                logger.info(f"MLaaS Helper URL: {self.mlaas_helper_url}")
                logger.info(f"Keycloak URL: {self.keycloak_url}")
                logger.info(f"Keycloak Realm: {self.keycloak_realm}")
            else:
                print("✗ MLaaS Helper health check failed")
                
        except Exception as e:
            logger.error(f"Health check error: {e}")
            print(f"✗ Health check error: {e}")
    
    def show_config(self) -> None:
        """Show current configuration."""
        print("\n--- Current Configuration ---")
        print(f"MLaaS Helper URL: {self.mlaas_helper_url}")
        print(f"Keycloak URL: {self.keycloak_url}")
        print(f"Keycloak Realm: {self.keycloak_realm}")
        print(f"Keycloak Client ID: {self.keycloak_client_id}")
        
        # Check token status
        stored_token = self.get_stored_token()
        if stored_token:
            if self.is_token_expired():
                print("Authentication: ✗ Token expired")
            else:
                print("Authentication: ✓ Valid token")
        else:
            print("Authentication: ✗ No token")

def main():
    parser = argparse.ArgumentParser(
        description="MLaaS Client - Manage API keys for 3Scale services via Keycloak authentication",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  %(prog)s --health                           # Check server health
  %(prog)s --list                             # List all services
  %(prog)s --init id=service-123              # Initialize API key by service ID
  %(prog)s --init name="ML Service"           # Initialize API key by service name
  %(prog)s --logout                           # Clear stored tokens
  %(prog)s --config                           # Show current configuration
        """
    )
    
    parser.add_argument(
        '--mlaas-helper-url', 
        default=None,
        help=f'MLaaS Helper URL (default: {DEFAULT_MLAAS_HELPER_URL})'
    )
    
    parser.add_argument(
        '--keycloak-url', 
        default=None,
        help=f'Keycloak URL (default: {DEFAULT_KEYCLOAK_URL})'
    )
    
    parser.add_argument(
        '--keycloak-realm', 
        default=None,
        help=f'Keycloak realm (default: {DEFAULT_KEYCLOAK_REALM})'
    )
    
    parser.add_argument(
        '--keycloak-client-id', 
        default=None,
        help=f'Keycloak client ID (default: {DEFAULT_KEYCLOAK_CLIENT_ID})'
    )
    
    parser.add_argument(
        '-l', '--list', 
        action='store_true',
        help='List all services and their API key status'
    )
    
    parser.add_argument(
        '-i', '--init', 
        metavar='SERVICE_IDENTIFIER',
        help='Initialize API key for a service (use id=<service_id> or name=<service_name>)'
    )
    
    parser.add_argument(
        '--health', 
        action='store_true',
        help='Check MLaaS Helper server health'
    )
    
    parser.add_argument(
        '--logout', 
        action='store_true',
        help='Clear stored authentication tokens'
    )
    
    parser.add_argument(
        '--config', 
        action='store_true',
        help='Show current configuration'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging'
    )
    
    args = parser.parse_args()
    
    # Set log level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # If no arguments provided, show help
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    
    try:
        # Initialize client
        client = MLaaSClient(
            mlaas_helper_url=args.mlaas_helper_url,
            keycloak_url=args.keycloak_url,
            keycloak_realm=args.keycloak_realm,
            keycloak_client_id=args.keycloak_client_id
        )
        
        if args.logout:
            client.clear_tokens()
            print("Authentication tokens cleared.")
        
        elif args.config:
            client.show_config()
        
        elif args.health:
            client.health_check()
        
        elif args.list:
            client.list_services()
        
        elif args.init:
            client.init_api_key(args.init)
        
        else:
            parser.print_help()
            sys.exit(1)
            
    except ConfigurationError as e:
        logger.error(f"Configuration error: {e}")
        print(f"Configuration error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        print(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 