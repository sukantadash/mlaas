# MLaaS High-Level Design Diagram

```mermaid
graph TB
    %% Client Side Components
    subgraph "🖥️ Client Side"
        subgraph "CLI Application"
            USER[👤 End User]
            CLI_MAIN[💻 MLaaS CLI Client<br/>client.py<br/>• Argument Parsing<br/>• Command Routing<br/>• User Interface]
            
            subgraph "Client Core Components"
                AUTH_CLIENT[🔐 Authentication Handler<br/>• Login Flow<br/>• Token Management<br/>• Credential Storage]
                CONFIG_MGR[⚙️ Configuration Manager<br/>• Config File (~/.mlaas_client_config.ini)<br/>• Environment Variables<br/>• Settings Persistence]
                API_CLIENT[🔌 API Client<br/>• HTTP Request Handler<br/>• Response Processing<br/>• Error Handling]
                SERVICE_MGR[📋 Service Manager<br/>• Service Discovery<br/>• API Key Initialization<br/>• Service Interaction]
            end
            
            EXAMPLE[📝 Example Usage<br/>example_usage.py<br/>• Integration Examples<br/>• Programmatic API<br/>• Best Practices]
        end
        
        subgraph "Client Dependencies"
            REQUESTS[🌐 requests<br/>HTTP Library]
            TABULATE[📊 tabulate<br/>Table Formatting]
            CONFIGPARSER[📄 configparser<br/>Configuration Management]
        end
    end
    
    %% Network Layer
    subgraph "🌐 Network Communication"
        HTTP[📡 HTTP/HTTPS<br/>• REST API Calls<br/>• JSON Payload<br/>• JWT Authentication<br/>• SSL/TLS Security]
        
        subgraph "Request Types"
            AUTH_REQ[🔐 Authentication Requests<br/>POST /api/auth/login]
            SERVICE_REQ[📋 Service Requests<br/>GET /api/services]
            INIT_REQ[🔑 Initialization Requests<br/>POST /api/services/init]
            HEALTH_REQ[❤️ Health Check Requests<br/>GET /api/health]
        end
    end
    
    %% Server Side Components
    subgraph "🖥️ Server Side"
        subgraph "Flask Application"
            FLASK_APP[🚀 Flask Application<br/>server.py<br/>• WSGI Application<br/>• Route Handling<br/>• Request Processing]
            
            subgraph "Server Core Components"
                AUTH_SERVER[🔐 Authentication Handler<br/>• Token Validation<br/>• User Authentication<br/>• Session Management]
                RATE_LIMITER[🚦 Rate Limiter<br/>• Request Throttling<br/>• User-based Limits<br/>• API Protection]
                API_ENDPOINTS[🔌 API Endpoints<br/>• Route Definitions<br/>• Request Validation<br/>• Response Formatting]
                SERVICE_HANDLER[📋 Service Handler<br/>• Service Discovery<br/>• API Key Provisioning<br/>• Account Management]
            end
            
            subgraph "Middleware & Utilities"
                LOGGING[📊 Structured Logging<br/>• Request Tracking<br/>• Error Logging<br/>• Audit Trail]
                ERROR_HANDLER[❌ Error Handler<br/>• Exception Handling<br/>• Standard Responses<br/>• Error Codes]
                VALIDATOR[✅ Request Validator<br/>• Input Validation<br/>• Schema Validation<br/>• Security Checks]
            end
        end
        
        subgraph "Server Dependencies"
            FLASK[🌶️ Flask<br/>Web Framework]
            GUNICORN[🦄 Gunicorn<br/>WSGI Server]
            LIMITER[🚦 Flask-Limiter<br/>Rate Limiting]
            STRUCTLOG[📊 structlog<br/>Structured Logging]
            JWT_LIB[🔐 PyJWT<br/>Token Processing]
        end
    end
    
    %% External Services
    subgraph "🔗 External Services"
        KEYCLOAK[🔑 Keycloak<br/>Identity Provider<br/>• User Authentication<br/>• JWT Token Generation<br/>• Role Management]
        
        THREESCALE[🎯 3Scale API Management<br/>• API Gateway<br/>• Key Management<br/>• Service Registry<br/>• Usage Analytics]
        
        ML_SERVICES[🤖 ML Services<br/>• Text Analytics<br/>• Computer Vision<br/>• Speech Processing<br/>• Custom Models]
    end
    
    %% Client Internal Flow
    USER --> CLI_MAIN
    CLI_MAIN --> AUTH_CLIENT
    CLI_MAIN --> CONFIG_MGR
    CLI_MAIN --> API_CLIENT
    CLI_MAIN --> SERVICE_MGR
    
    AUTH_CLIENT --> CONFIG_MGR
    API_CLIENT --> CONFIG_MGR
    SERVICE_MGR --> API_CLIENT
    
    CLI_MAIN --> REQUESTS
    API_CLIENT --> REQUESTS
    SERVICE_MGR --> TABULATE
    CONFIG_MGR --> CONFIGPARSER
    
    %% Client to Server Communication
    API_CLIENT -->|HTTP Requests| HTTP
    HTTP --> AUTH_REQ
    HTTP --> SERVICE_REQ
    HTTP --> INIT_REQ
    HTTP --> HEALTH_REQ
    
    %% Server Request Processing
    AUTH_REQ --> FLASK_APP
    SERVICE_REQ --> FLASK_APP
    INIT_REQ --> FLASK_APP
    HEALTH_REQ --> FLASK_APP
    
    %% Server Internal Flow
    FLASK_APP --> RATE_LIMITER
    FLASK_APP --> API_ENDPOINTS
    FLASK_APP --> AUTH_SERVER
    FLASK_APP --> SERVICE_HANDLER
    
    FLASK_APP --> LOGGING
    FLASK_APP --> ERROR_HANDLER
    FLASK_APP --> VALIDATOR
    
    API_ENDPOINTS --> FLASK
    FLASK_APP --> GUNICORN
    RATE_LIMITER --> LIMITER
    LOGGING --> STRUCTLOG
    AUTH_SERVER --> JWT_LIB
    
    %% Server to External Services
    AUTH_SERVER -->|Authentication| KEYCLOAK
    SERVICE_HANDLER -->|API Management| THREESCALE
    THREESCALE -->|Proxied Requests| ML_SERVICES
    
    %% Response Flow (dotted lines)
    KEYCLOAK -.->|JWT Token| AUTH_SERVER
    THREESCALE -.->|Service Info| SERVICE_HANDLER
    ML_SERVICES -.->|ML Results| THREESCALE
    
    SERVICE_HANDLER -.->|Response| API_ENDPOINTS
    API_ENDPOINTS -.->|JSON Response| HTTP
    HTTP -.->|Response| API_CLIENT
    API_CLIENT -.->|Processed Data| CLI_MAIN
    CLI_MAIN -.->|Output| USER
    
    %% Styling
    classDef clientLayer fill:#e3f2fd,stroke:#1565c0,stroke-width:2px
    classDef networkLayer fill:#f3e5f5,stroke:#6a1b9a,stroke-width:2px
    classDef serverLayer fill:#e8f5e8,stroke:#2e7d32,stroke-width:2px
    classDef externalLayer fill:#fff3e0,stroke:#f57c00,stroke-width:2px
    classDef dependencyLayer fill:#fafafa,stroke:#616161,stroke-width:1px
    
    class USER,CLI_MAIN,AUTH_CLIENT,CONFIG_MGR,API_CLIENT,SERVICE_MGR,EXAMPLE clientLayer
    class HTTP,AUTH_REQ,SERVICE_REQ,INIT_REQ,HEALTH_REQ networkLayer
    class FLASK_APP,AUTH_SERVER,RATE_LIMITER,API_ENDPOINTS,SERVICE_HANDLER,LOGGING,ERROR_HANDLER,VALIDATOR serverLayer
    class KEYCLOAK,THREESCALE,ML_SERVICES externalLayer
    class REQUESTS,TABULATE,CONFIGPARSER,FLASK,GUNICORN,LIMITER,STRUCTLOG,JWT_LIB dependencyLayer
```

## Component Descriptions

### Client Side Components

#### **MLaaS CLI Client (`client.py`)**
- **Purpose**: Main command-line interface for users
- **Responsibilities**:
  - Argument parsing and command routing
  - User interaction and feedback
  - Configuration management
  - API communication orchestration

#### **Authentication Handler**
- **Purpose**: Manages user authentication flow
- **Responsibilities**:
  - Login credential handling
  - JWT token storage and retrieval
  - Token validation and refresh
  - Secure credential management

#### **Configuration Manager**
- **Purpose**: Handles application configuration
- **Responsibilities**:
  - Config file management (`~/.mlaas_client_config.ini`)
  - Environment variable processing
  - Settings persistence and retrieval
  - Default configuration handling

#### **API Client**
- **Purpose**: HTTP communication with server
- **Responsibilities**:
  - REST API request construction
  - Response processing and parsing
  - Error handling and retry logic
  - Authentication header management

#### **Service Manager**
- **Purpose**: Manages ML service interactions
- **Responsibilities**:
  - Service discovery and listing
  - API key initialization
  - Service metadata handling
  - User-friendly service display

### Server Side Components

#### **Flask Application (`server.py`)**
- **Purpose**: Main web application server
- **Responsibilities**:
  - HTTP request routing
  - Middleware coordination
  - Response generation
  - Application lifecycle management

#### **Authentication Handler**
- **Purpose**: Server-side authentication processing
- **Responsibilities**:
  - JWT token validation
  - User authentication with Keycloak
  - Session management
  - Authorization checks

#### **Rate Limiter**
- **Purpose**: API protection and throttling
- **Responsibilities**:
  - Request rate limiting (200/day, 50/hour)
  - User-based quota management
  - Abuse prevention
  - Performance protection

#### **Service Handler**
- **Purpose**: ML service management
- **Responsibilities**:
  - 3Scale API integration
  - Service discovery from registry
  - API key provisioning
  - Account management

### Communication Flow

1. **Authentication Flow**:
   - User → CLI → Authentication Handler → Server → Keycloak
   - JWT token returned and stored in configuration

2. **Service Discovery Flow**:
   - CLI → API Client → Server → 3Scale → Service Registry
   - Service list returned with metadata

3. **API Key Provisioning Flow**:
   - CLI → Service Handler → Server → 3Scale Admin API
   - API key generated and returned to user

4. **ML Service Access Flow**:
   - User → API Key → 3Scale Proxy → ML Services
   - Results returned through proxy

### Key Features

- **Secure Authentication**: JWT-based authentication with Keycloak integration
- **Rate Limiting**: Built-in protection against abuse
- **Error Handling**: Comprehensive error handling at all levels
- **Configuration Management**: Persistent configuration with secure token storage
- **Logging**: Structured logging for debugging and monitoring
- **Extensibility**: Modular design for easy feature additions 