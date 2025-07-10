#!/usr/bin/env python3
"""
Example script demonstrating how to use the MLaaS client programmatically.
This shows how to integrate the client functionality into other applications.
"""

import sys
import os
import logging
from client import MLaaSClient, ConfigurationError, AuthenticationError, ServerError

# Configure logging for the example
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    """
    Example usage of the MLaaS client programmatically with improved error handling.
    """
    print("=== MLaaS Client Example ===\n")
    
    # Set up example environment variables if not already set
    if not os.getenv('KEYCLOAK_URL'):
        print("Setting up example environment variables...")
        os.environ['KEYCLOAK_URL'] = 'https://keycloak.example.com'
        os.environ['KEYCLOAK_REALM'] = 'mlaas'
        os.environ['KEYCLOAK_CLIENT_ID'] = 'mlaas-client'
        os.environ['KEYCLOAK_CLIENT_SECRET'] = 'example-client-secret'
        os.environ['MLAAS_HELPER_URL'] = 'http://localhost:5000'
        print("Note: Using example environment variables. Set actual values for real usage.")
    
    try:
        # Initialize client with error handling
        print("1. Initializing client...")
        try:
            client = MLaaSClient()
            print("   ✓ Client initialized successfully")
            print(f"   → MLaaS Helper URL: {client.mlaas_helper_url}")
            print(f"   → Keycloak URL: {client.keycloak_url}")
            print(f"   → Keycloak Realm: {client.keycloak_realm}")
            print(f"   → Keycloak Client ID: {client.keycloak_client_id}")
        except ConfigurationError as e:
            print(f"   ✗ Configuration error: {e}")
            print("\n   Required environment variables:")
            print("     KEYCLOAK_URL")
            print("     KEYCLOAK_REALM")
            print("     KEYCLOAK_CLIENT_ID")
            print("     KEYCLOAK_CLIENT_SECRET")
            print("\n   Optional environment variables:")
            print("     MLAAS_HELPER_URL (default: http://localhost:5000)")
            return
        except Exception as e:
            print(f"   ✗ Error initializing client: {e}")
            return
        
        # Check server health
        print("\n2. Checking MLaaS Helper server health...")
        try:
            response = client.make_request('GET', '/api/health', require_auth=False)
            if response:
                status = response.get('status', 'Unknown')
                print(f"   ✓ MLaaS Helper is healthy: {status}")
            else:
                print("   ✗ MLaaS Helper is not responding")
                print("   → Note: This is expected if the server is not running")
                print("   → The example will continue with other demonstrations")
        except Exception as e:
            print(f"   ✗ Error checking server health: {e}")
            print("   → Continuing with authentication example...")
        
        # Show configuration
        print("\n3. Showing current configuration...")
        try:
            client.show_config()
        except Exception as e:
            print(f"   ✗ Error showing configuration: {e}")
        
        # Check stored token
        print("\n4. Checking stored authentication...")
        stored_token = client.get_stored_token()
        if stored_token:
            print("   ✓ Found stored authentication token")
            client.access_token = stored_token
            
            # Check if token is expired
            if client.is_token_expired():
                print("   → Stored token is expired")
                print("   → In real usage, you would call client.authenticate() here")
            else:
                print("   → Stored token is valid")
        else:
            print("   ✗ No stored authentication token")
            print("   → In real usage, you would call client.authenticate() here")
            print("   → For this example, we'll simulate having a token")
        
        # Demonstrate token management
        print("\n5. Demonstrating token management...")
        try:
            # Simulate clearing tokens
            print("   → Clearing stored tokens...")
            client.clear_tokens()
            print("   ✓ Tokens cleared successfully")
            
            # Show how to store tokens (example data)
            print("   → Storing example token...")
            client.store_tokens(
                access_token="example_access_token_12345",
                refresh_token="example_refresh_token_67890",
                expires_in=3600
            )
            print("   ✓ Token stored successfully")
            
            # Verify token was stored
            stored_again = client.get_stored_token()
            if stored_again:
                print("   ✓ Token retrieval verified")
            else:
                print("   ✗ Token storage failed")
            
        except Exception as e:
            print(f"   ✗ Error with token management: {e}")
        
        # Demonstrate service listing (will fail without real server)
        print("\n6. Demonstrating service listing...")
        try:
            print("   → Attempting to list services...")
            response = client.make_request('GET', '/api/services')
            if response:
                services = response.get('services', [])
                user_info = response.get('user', {})
                
                print(f"   ✓ Found {len(services)} services for user {user_info.get('soeid', 'Unknown')}")
                
                if services:
                    print("   → Available services:")
                    for service in services[:3]:  # Show first 3
                        status = "✓ Has API key" if service.get('has_api_key') else "✗ No API key"
                        print(f"     - {service.get('name')} (ID: {service.get('id')}) - {status}")
                else:
                    print("   → No services found")
            else:
                print("   ✗ Failed to get services (expected if server is not running)")
        except Exception as e:
            print(f"   ✗ Error listing services: {e}")
            print("   → This is expected if the MLaaS Helper server is not running")
        
        # Demonstrate API key initialization (will fail without real server)
        print("\n7. Demonstrating API key initialization...")
        try:
            print("   → Attempting to initialize API key...")
            response = client.make_request(
                'POST', 
                '/api/services/init',
                data={'service_id': 'example-service-123'}
            )
            
            if response:
                service_info = response.get('service', {})
                api_key = response.get('api_key')
                is_new = response.get('is_new', False)
                
                print(f"   ✓ API key {'generated' if is_new else 'retrieved'} for {service_info.get('name')}")
                if api_key:
                    print(f"     API Key: {api_key[:10]}...{api_key[-10:] if len(api_key) > 20 else api_key}")
                    print(f"     Endpoint: {service_info.get('proxy_endpoint')}")
            else:
                print("   ✗ Failed to initialize API key (expected if server is not running)")
        except Exception as e:
            print(f"   ✗ Error initializing API key: {e}")
            print("   → This is expected if the MLaaS Helper server is not running")
        
        # Demonstrate error handling
        print("\n8. Demonstrating error handling...")
        try:
            # Try to access a non-existent endpoint
            print("   → Testing error handling with invalid endpoint...")
            response = client.make_request('GET', '/api/nonexistent')
            if response:
                print("   ✗ Unexpected success")
            else:
                print("   ✓ Error handling working correctly")
        except Exception as e:
            print(f"   ✓ Error caught properly: {e}")
        
        # Show final configuration
        print("\n9. Final configuration check...")
        try:
            client.show_config()
        except Exception as e:
            print(f"   ✗ Error showing final configuration: {e}")
        
        print("\n=== Example completed successfully ===")
        print("\nTo use this client in a real environment:")
        print("1. Set the required environment variables:")
        print("   export KEYCLOAK_URL=https://your-keycloak-server.com")
        print("   export KEYCLOAK_REALM=your-realm")
        print("   export KEYCLOAK_CLIENT_ID=your-client-id")
        print("   export KEYCLOAK_CLIENT_SECRET=your-client-secret")
        print("   export MLAAS_HELPER_URL=https://your-mlaas-helper.com")
        print("2. Start the MLaaS Helper server")
        print("3. Run: python client.py --list")
        print("4. Initialize API keys: python client.py --init id=service-123")
        
    except KeyboardInterrupt:
        print("\n=== Example interrupted by user ===")
        sys.exit(1)
    except ConfigurationError as e:
        print(f"\n=== Configuration Error: {e} ===")
        sys.exit(1)
    except AuthenticationError as e:
        print(f"\n=== Authentication Error: {e} ===")
        sys.exit(1)
    except ServerError as e:
        print(f"\n=== Server Error: {e} ===")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error in example: {e}")
        print(f"\n=== Unexpected Error: {e} ===")
        sys.exit(1)

if __name__ == "__main__":
    main() 