# Secure Helix MLaaS command on OpenShift

A secure Machine Learning as a Service (MLaaS) implementation for OpenShift that allows end-users to run Python scripts with their own arguments inside pods without exposing access tokens.

## Overview

This architecture enables users to execute ML scripts remotely while maintaining security by:
- Running the main script in a locked-down pod
- Providing users with a local client script for secure interaction
- Using OpenShift RBAC to prevent shell access
- Storing sensitive tokens as Kubernetes secrets

## Table of Contents

- [Architecture](#architecture)
- [Administrator Setup](#administrator-setup)
- [End-User Guide](#end-user-guide)
- [Security Features](#security-features)
- [Prerequisites](#prerequisites)

## Architecture

The system consists of two main components:
1. **Remote Script**: Runs in a secure OpenShift pod with access to sensitive tokens
2. **Local Client**: User-facing script that communicates with the remote script via `oc` commands

## Administrator Setup

These steps are performed once by the OpenShift project administrator to deploy and secure the service within the `helix-mlaas` namespace.

### Step 1: Create the OpenShift Secret

First, we securely store the access tokens in an OpenShift `Secret` within the `helix-mlaas` namespace. This prevents the token from ever being hard-coded in your application or container image.

```bash
# Replace 'your-super-secret-token' with the actual token value
oc create secret generic my-api-secret --from-literal=ACCESS_TOKEN='your-super-secret-token' -n helix-mlaas
```

### Step 2: Prepare the Application and Container

You need two Python scripts:

1.  `mlaas.py`: The remote script that runs in the pod (provided in a previous step).
2.  `run_remote_mlaas.py`: The local client script for users (from the artifact `mlaas_client_script`).

You also need a `Dockerfile` to build a secure, "shell-less" container image. This prevents users from getting a shell inside the pod.

**`Dockerfile`**

```dockerfile
# Stage 1: Build the application with all the tools
FROM python:3.9-slim as builder

WORKDIR /app
COPY mlaas.py .
# If you have dependencies, add a requirements.txt and uncomment the next line
# RUN pip install --no-cache-dir -r requirements.txt

# Stage 2: Create the final, minimal image from a distroless base
FROM gcr.io/distroless/python3-debian11

WORKDIR /app
COPY --from=builder /app /app
# If you have dependencies, also copy site-packages
# COPY --from=builder /usr/local/lib/python3.9/site-packages /usr/local/lib/python3.9/site-packages

# Set the entrypoint to your script. Note: This is not strictly necessary
# as we call it directly with 'oc exec', but it's good practice.
CMD ["python", "mlaas.py"]
```

Build and push this image to your container registry (e.g., Docker Hub, Quay.io, or the internal OpenShift registry).

### Step 3: Deploy the Application

Create a `deployment.yaml` file to deploy your application. This configuration mounts the secret as an environment variable and uses the container image you just built.

**`deployment.yaml`**

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-python-app
  namespace: helix-mlaas # <-- Specify the namespace
spec:
  replicas: 1
  selector:
    matchLabels:
      app: python-app
  template:
    metadata:
      labels:
        app: python-app
    spec:
      containers:
      - name: python-container
        image: your-registry/your-image-name:latest # <-- IMPORTANT: Change this
        env:
        - name: SUPER_USER_TOKEN
          valueFrom:
            secretKeyRef:
              name: my-api-secret
              key: ACCESS_TOKEN
```

Deploy it to your project:

```bash
oc apply -f deployment.yaml -n helix-mlaas
```

### Step 4: Create and Apply the "No-Exec" Role

To prevent users from getting a shell in the pod, create a `Role` that denies them `pods/exec` permission within the `helix-mlaas` namespace.

**`no-exec-role.yaml`**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: no-exec-role
  namespace: helix-mlaas # <-- Specify the namespace
rules:
- apiGroups: [""]
  resources: ["pods", "pods/log"]
  verbs: ["get", "list", "watch"]
```

Apply it:

```bash
oc apply -f no-exec-role.yaml -n helix-mlaas
```

### Step 5: Bind the Role to All Users

Create a `RoleBinding` to apply this restrictive role to every authenticated user in the `helix-mlaas` namespace. This is more efficient than managing individual user permissions.

**`no-exec-binding.yaml`**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: no-exec-for-all-users
  namespace: helix-mlaas # <-- Specify the namespace
subjects:
- kind: Group
  name: system:authenticated # This group includes all logged-in users
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: no-exec-role
  apiGroup: rbac.authorization.k8s.io
```

Apply it to your project:

```bash
oc apply -f no-exec-binding.yaml -n helix-mlaas
```

The administrator's setup is now complete.

## End-User Guide

These are the instructions you would provide to the end-users of your MLaaS.

### Prerequisites

Before you begin, ensure you have the following:

1.  **Python 3** installed on your local machine.
2.  The **OpenShift CLI (`oc`)** installed and configured. You must be able to log in to the cluster by running `oc login` and have access to the `helix-mlaas` project.

### Installation

Download the client script `run_remote_mlaas.py` (from the artifact `mlaas_client_script`) and save it to your computer.

### Usage

You can now execute the remote MLaaS script by running the local client from your terminal. The client will handle finding the pod and passing your arguments securely.

Open your terminal, navigate to the directory where you saved `run_remote_mlaas.py`, and run it.

**Syntax:**

```bash
python run_remote_mlaas.py [ARGUMENT_1] [ARGUMENT_2] [...]
```

**Examples:**

Running with arguments:
```bash
python run_remote_mlaas.py "sentiment-model" "This movie was fantastic"
```

Running with no arguments:
```bash
python run_remote_mlaas.py
```

The output from the remote script running inside the pod will be streamed directly to your terminal, but the underlying super-user token remains secure and hidden on the server.

## Security Features

- **Token Isolation**: Super-user tokens are stored as Kubernetes secrets and never exposed to end-users
- **Pod Security**: Uses distroless container images to prevent shell access
- **RBAC Controls**: Role-based access control prevents `pods/exec` permissions
- **Namespace Isolation**: All resources are contained within the `helix-mlaas` namespace
- **Secure Communication**: All interactions happen through the OpenShift API via `oc` commands

## Prerequisites

### For Administrators
- OpenShift cluster access with admin privileges
- Docker or Podman for building container images
- Access to a container registry

### For End-Users
- OpenShift CLI (`oc`) installed and configured
- Valid OpenShift credentials with access to the `helix-mlaas` project
