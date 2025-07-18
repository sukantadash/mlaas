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
import subprocess
import shutil
import yaml

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
DEFAULT_KEYCLOAK_CLIENT_SECRET = ""  # Must be provided via environment variable or config
DEFAULT_MLAAS_HELPER_URL = "https://mlaas-helper.prod.example.com"

# --- Hardcoded Helix Templates ---
HELIX_TEMPLATES = [
    {
        "name": "python",
        "description": "Flask-based Python function",
        "version": "1.0.2",
        "git_repo": "https://github.com/example/python-template.git",
        "branch": "main"
    },
    {
        "name": "python-fastapi",
        "description": "FastAPI-based Python function",
        "version": "1.0.2",
        "git_repo": "https://github.com/example/python-fastapi-template.git",
        "branch": "main"
    },
    {
        "name": "golang-gin-http",
        "description": "Gin gionic based Golang function",
        "version": "1.0.1",
        "git_repo": "https://github.com/example/golang-gin-template.git",
        "branch": "main"
    },
    {
        "name": "java-http",
        "description": "Java lightweight HttpSever",
        "version": "1.0.2",
        "git_repo": "https://github.com/example/java-http-template.git",
        "branch": "main"
    },
    {
        "name": "python-genai-vertex",
        "description": "Vertex client, entry point to build Generative AI applications on top of it.",
        "version": "1.0.2",
        "git_repo": "https://github.com/example/python-genai-vertex-template.git",
        "branch": "main"
    }
]

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

    def __init__(self, keycloak_url: str, realm: str, client_id: str, client_secret: str):
        self.keycloak_url = keycloak_url.rstrip('/')
        self.realm = realm
        self.client_id = client_id
        self.client_secret = client_secret
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
                'client_secret': self.client_secret,
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
                 keycloak_realm: Optional[str] = None, keycloak_client_id: Optional[str] = None,
                 keycloak_client_secret: Optional[str] = None):
        # Use hardcoded values with fallback to parameters
        self.mlaas_helper_url = mlaas_helper_url or DEFAULT_MLAAS_HELPER_URL
        self.keycloak_url = keycloak_url or DEFAULT_KEYCLOAK_URL
        self.keycloak_realm = keycloak_realm or DEFAULT_KEYCLOAK_REALM
        self.keycloak_client_id = keycloak_client_id or DEFAULT_KEYCLOAK_CLIENT_ID
        self.keycloak_client_secret = keycloak_client_secret or DEFAULT_KEYCLOAK_CLIENT_SECRET or os.getenv('KEYCLOAK_CLIENT_SECRET', '')

        # Validate URLs
        self.mlaas_helper_url = self._validate_server_url(self.mlaas_helper_url)
        self.keycloak_url = self._validate_server_url(self.keycloak_url)

        # Validate client secret for confidential clients
        if not self.keycloak_client_secret:
            raise ConfigurationError(
                "Keycloak client secret is required for confidential clients. "
                "Set KEYCLOAK_CLIENT_SECRET environment variable or pass --keycloak-client-secret"
            )

        # Initialize HTTP session
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'MLaaS-Client/1.0',
            'Accept': 'application/json'
        })

        # Initialize Keycloak client
        self.keycloak_client = KeycloakAuthClient(
            self.keycloak_url, self.keycloak_realm, self.keycloak_client_id, self.keycloak_client_secret
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
                'client_secret': self.keycloak_client_secret,
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

            services = []
            user_info = {}

            # This block handles multiple response formats from the server
            if isinstance(response, tuple):
                response_dict = response[0]
                data_dict = response_dict.get('data', {})
                outer_services_list = data_dict.get('services', [])
                if outer_services_list:
                    services = outer_services_list[0]
                user_info = data_dict.get('user', {})
            elif isinstance(response, dict):
                services = response.get('services', [])
                user_info = response.get('user', {})
            elif isinstance(response, list):
                services = response
            else:
                print("Unexpected response format from server.")
                logger.error(f"Unexpected response format: {type(response)}")
                return

            if user_info:
                print(f"User: {user_info.get('soeid', 'Unknown')} ({user_info.get('email', 'No email')})")
                if isinstance(response, dict):
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

    def list_templates(self) -> None:
        """List all available Helix Function Templates."""
        print("\n--- Available Helix Function Templates ---")

        # Prepare table data from the hardcoded list
        headers = ["NAME", "DESCRIPTION", "LATEST VERSION", "GIT REPO", "BRANCH"]
        table_data = []

        for template in HELIX_TEMPLATES:
            table_data.append([
                template.get('name', 'N/A'),
                template.get('description', 'N/A'),
                template.get('version', 'N/A'),
                template.get('git_repo', 'N/A'),
                template.get('branch', 'N/A')
            ])

        print(tabulate(table_data, headers=headers, tablefmt="grid"))

    def create_app_from_template(self, create_args: List[str]) -> None:
        """Creates a new application by cloning a template Git repository."""
        if len(create_args) != 3:
            print("Error: The create command requires 3 arguments: <template-name> <service-identifier> <app-name>")
            return

        template_name, service_identifier, app_name = create_args

        # Find the selected template from the hardcoded list
        template = next((t for t in HELIX_TEMPLATES if t['name'] == template_name), None)

        if not template:
            print(f"✗ Error: Template '{template_name}' not found.")
            print("Use --list-templates to see available templates.")
            return

        # Check if the destination directory already exists
        clone_path = os.path.join(os.getcwd(), app_name)
        if os.path.exists(clone_path):
            print(f"✗ Error: Directory '{app_name}' already exists in the current path.")
            return

        # Get Git credentials from the user
        print("\n--- Git Repository Authentication ---")
        git_user = input("Enter your Git username: ")
        git_token = getpass.getpass("Enter your Git token or password: ")

        if not git_user or not git_token:
            print("✗ Error: Git username and token/password are required.")
            return

        # Construct the authenticated repository URL
        repo_url = template['git_repo']
        parsed_url = urllib.parse.urlparse(repo_url)
        authed_netloc = f"{urllib.parse.quote(git_user)}:{urllib.parse.quote(git_token)}@{parsed_url.netloc}"
        authed_repo_url = parsed_url._replace(netloc=authed_netloc).geturl()

        branch = template['branch']

        print(f"\nCloning template '{template_name}' from branch '{branch}' into './{app_name}'...")

        # Construct and run the git clone command
        command = ["git", "clone", "--branch", branch, authed_repo_url, app_name]

        try:
            # Use subprocess to run the command, capturing output
            result = subprocess.run(command, check=True, capture_output=True, text=True, encoding='utf-8')
            print(f"✓ Successfully cloned template into '{app_name}'.")
            logger.debug(result.stdout)

            # --- Get service details and update values.yaml ---
            print("\nFetching service details and configuring application...")
            service_details = self.init_api_key(service_identifier, silent=True)

            if not service_details:
                print("✗ Error: Could not retrieve service details. Please check the service identifier.")
                return

            api_key = service_details.get('api_key')
            service_info = service_details.get('service', {})
            endpoint = service_info.get('proxy_endpoint')
            model_name = service_info.get('name')

            if not all([api_key, endpoint, model_name]):
                print("✗ Error: Incomplete service details received from the server.")
                return

            # Update the values.yaml file
            values_yaml_path = os.path.join(clone_path, 'helm', 'values.yaml')
            self.update_values_yaml(values_yaml_path, endpoint, model_name, api_key, app_name)

            print("✓ Application configured successfully.")

            # --- Create pip.conf for Artifactory ---
            self.create_pip_conf()


        except FileNotFoundError:
            print("✗ Error: 'git' command not found. Please ensure Git is installed and in your system's PATH.")
        except subprocess.CalledProcessError as e:
            print("✗ Error cloning repository. Please check your URL, credentials, and permissions.")
            # Print the error from Git for debugging
            logger.error("Git clone failed.")
            print("\n--- Git Error Details ---")
            print(e.stderr)
            # Clean up the partially created directory if the clone fails
            if os.path.exists(clone_path):
                shutil.rmtree(clone_path)
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

    def update_values_yaml(self, file_path: str, api_url: str, model_name: str, api_key: str, app_name: str):
        """Updates the helm/values.yaml file with service details."""
        try:
            if not os.path.exists(file_path):
                print(f"✗ Warning: '{file_path}' not found. Skipping configuration.")
                return

            with open(file_path, 'r') as f:
                values_data = yaml.safe_load(f)

            # Add appName for the deploy command to use
            values_data['appName'] = app_name

            if 'llm' not in values_data:
                values_data['llm'] = {}

            values_data['llm']['apiUrl'] = api_url
            values_data['llm']['modelName'] = model_name
            values_data['llm']['apiKey'] = api_key

            with open(file_path, 'w') as f:
                yaml.dump(values_data, f, default_flow_style=False, sort_keys=False)

            print(f"✓ Updated '{file_path}' with new service configuration.")

        except yaml.YAMLError as e:
            print(f"✗ Error processing YAML file '{file_path}': {e}")
        except IOError as e:
            print(f"✗ Error accessing file '{file_path}': {e}")

    def create_pip_conf(self):
        """Prompts for Artifactory credentials and creates a pip.conf file."""
        print("\n--- Artifactory Configuration ---")
        soeid = input("Enter your Artifactory SOEID: ")
        token = getpass.getpass("Enter your Artifactory token: ")

        if not soeid or not token:
            print("✗ Warning: SOEID and token are required for Artifactory. Skipping pip.conf creation.")
            return

        # Define the content for the pip.conf file
        pip_conf_content = f"""
[global]
index-url = https://{soeid}:{token}@www.artifactory.citigroup.net/artifactory/api/pypi/pypi-dev/simple
index = https://{soeid}:{token}@www.artifactory.citigroup.net/artifactory/api/pypi/pypi-dev
trusted-host = www.artifactory.citigroup.net
"""

        # Write the content to pip.conf in the current directory
        pip_conf_path = os.path.join(os.getcwd(), 'pip.conf')
        try:
            with open(pip_conf_path, 'w') as f:
                f.write(pip_conf_content.strip())
            print(f"✓ Successfully created 'pip.conf' in the current directory.")
        except IOError as e:
            print(f"✗ Error creating 'pip.conf': {e}")

    def deploy_app(self) -> None:
        """Deploys or upgrades an application using Helm, retrieving the app name from values.yaml."""
        print("\n--- Deploying Application ---")

        # Check if helm is installed
        if not shutil.which("helm"):
            print("✗ Error: 'helm' command not found. Please ensure Helm is installed and in your system's PATH.")
            return

        # Define paths and check for existence
        helm_path = os.path.join(os.getcwd(), 'helm')
        values_yaml_path = os.path.join(helm_path, 'values.yaml')

        if not os.path.isdir(helm_path) or not os.path.exists(values_yaml_path):
            print(f"✗ Error: Directory './helm/' or './helm/values.yaml' not found.")
            print("Please run this command from the application's root directory.")
            return

        # Retrieve app name from values.yaml
        try:
            with open(values_yaml_path, 'r') as f:
                values_data = yaml.safe_load(f)
                app_name = values_data.get('name')
                if not app_name:
                    print("✗ Error: 'appName' not found in './helm/values.yaml'.")
                    print("Please ensure the application was created correctly with the '--create' command.")
                    return
        except (yaml.YAMLError, IOError) as e:
            print(f"✗ Error reading '{values_yaml_path}': {e}")
            return

        # Construct the helm command
        command = ["helm", "upgrade", "--install", app_name, helm_path]

        print(f"Running command: {' '.join(command)}")
        print("-" * 20)

        try:
            # Run the helm command and stream output
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding='utf-8')

            for line in iter(process.stdout.readline, ''):
                print(line, end='')

            process.stdout.close()
            return_code = process.wait()

            print("-" * 20)
            if return_code != 0:
                print(f"✗ Helm deployment of '{app_name}' failed with exit code {return_code}.")
                return

            print(f"✓ Helm deployment of '{app_name}' completed successfully.")
            print("\nAttempting to retrieve application URL...")

            # Attempt to get the route URL (assuming OpenShift `oc` CLI or kubectl)
            # This will retry for 30 seconds
            route_url = None
            for i in range(15): # Retry every 2 seconds for 30 seconds
                # Check for `oc` and `kubectl` and use whichever is available
                cli_tool = "oc" if shutil.which("oc") else "kubectl" if shutil.which("kubectl") else None

                if not cli_tool:
                    print("✗ Warning: Neither 'oc' nor 'kubectl' CLI found. Cannot retrieve application URL.")
                    break

                if cli_tool == "oc":
                    get_route_command = ["oc", "get", "route", app_name, "-o", "jsonpath={.spec.host}"]
                else: # Fallback to kubectl ingress
                    get_route_command = ["kubectl", "get", "ingress", app_name, "-o", "jsonpath={.spec.rules[0].host}"]


                try:
                    result = subprocess.run(get_route_command, capture_output=True, text=True, check=True, encoding='utf-8')
                    host = result.stdout.strip()
                    if host:
                        route_url = f"https://{host}"
                        break
                except subprocess.CalledProcessError:
                    time.sleep(2) # Wait before retrying
                except FileNotFoundError:
                     print("✗ Warning: Neither 'oc' nor 'kubectl' CLI found. Cannot retrieve application URL.")
                     break


            if route_url:
                print("\n" + "="*50)
                print(f"🎉 Application can be accessed at the following URL: 🎉")
                print(f"  {route_url}")
                print("="*50)
            else:
                print("\n✗ Could not retrieve application URL after 30 seconds.")
                print(f"  You may need to check the status of the route/ingress for '{app_name}' manually.")


        except FileNotFoundError:
             print("✗ Error: 'helm' command not found. Please ensure Helm is installed and in your system's PATH.")
        except Exception as e:
            print(f"An unexpected error occurred during deployment: {e}")


    def init_api_key(self, service_identifier: str, silent: bool = False) -> Optional[Dict]:
        """Initialize API key for a service with improved error handling."""
        if not silent:
            print(f"\n--- Initializing API Key for Service: {service_identifier} ---")

        try:
            # Parse service identifier
            if '=' in service_identifier:
                identifier_type, identifier_value = service_identifier.split('=', 1)
                identifier_type = identifier_type.strip().lower()
                identifier_value = identifier_value.strip()
            else:
                # Default to name if no identifier type is provided
                identifier_type = 'name'
                identifier_value = service_identifier

            if identifier_type not in ['id', 'name']:
                print("Error: Invalid identifier type. Use 'id' or 'name'")
                return None

            # First, get the list of services to find the service ID
            logger.info("Fetching services list")
            services_response = self.make_request('GET', '/api/services')
            if services_response is None:
                if not silent:
                    print("Failed to get services list.")
                return None

            services = []
            if isinstance(services_response, tuple):
                services = services_response[0].get('data', {}).get('services', [[]])[0]
            elif isinstance(services_response, dict):
                services = services_response.get('services', [])
            elif isinstance(services_response, list):
                services = services_response
            else:
                if not silent:
                    print("Unexpected response format from server.")
                logger.error(f"Unexpected response format: {type(services_response)}")
                return None

            selected_service = None

            for service in services:
                if identifier_type == 'id' and service.get('id') == identifier_value:
                    selected_service = service
                    break
                elif identifier_type == 'name' and service.get('name', '').lower() == identifier_value.lower():
                    selected_service = service
                    break

            if not selected_service:
                if not silent:
                    print(f"Error: Service with {identifier_type} '{identifier_value}' not found.")
                    print("Available services:")
                    for service in services[:5]:  # Show first 5
                        print(f"  - {service.get('name')} (ID: {service.get('id')})")
                return None

            service_id = selected_service['id']

            # Initialize API key
            logger.info(f"Initializing API key for service: {selected_service.get('name')}")
            response = self.make_request(
                'POST',
                '/api/services/init',
                data={'service_id': service_id}
            )

            if not response:
                if not silent:
                    print("Failed to initialize API key.")
                return None

            if silent:
                return response

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
            print(f"""  curl -H 'X-API-Key: {api_key}' '{service_info.get('proxy_endpoint', 'N/A')}'""")
            return response

        except Exception as e:
            if not silent:
                logger.error(f"Error initializing API key: {e}")
                print(f"Error initializing API key: {e}")
            return None

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
        print(f"Keycloak Client Secret: {'✓ Configured' if self.keycloak_client_secret else '✗ Not configured'}")

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
  %(prog)s --list-templates                   # List all available function templates
  %(prog)s --create python my-service my-app  # Create a new app from the 'python' template
  %(prog)s --deploy                           # Deploy the application in the current directory using Helm
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
        '--keycloak-client-secret',
        default=None,
        help='Keycloak client secret (can also be set via KEYCLOAK_CLIENT_SECRET env var)'
    )

    parser.add_argument(
        '-l', '--list',
        action='store_true',
        help='List all services and their API key status'
    )

    parser.add_argument(
        '-lt', '--list-templates',
        action='store_true',
        help='List all available Helix Function Templates'
    )

    parser.add_argument(
        '-c', '--create',
        nargs=3,
        metavar=('TEMPLATE', 'SERVICE', 'APP_NAME'),
        help='Create a new application from a template.'
    )

    parser.add_argument(
        '-d', '--deploy',
        action='store_true',
        help='Deploy the application in the current directory using Helm.'
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
            keycloak_client_id=args.keycloak_client_id,
            keycloak_client_secret=args.keycloak_client_secret
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

        elif args.list_templates:
            client.list_templates()

        elif args.create:
            client.create_app_from_template(args.create)

        elif args.deploy:
            client.deploy_app()

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