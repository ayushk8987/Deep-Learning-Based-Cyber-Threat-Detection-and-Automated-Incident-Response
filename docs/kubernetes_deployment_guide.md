# Kubernetes & Containerization Deployment Guide
## Deep Learning Cyber Threat Detection & SOAR Platform (with FreeLLMAPI)

This guide documents the enterprise containerization and Kubernetes orchestration architecture for the **Deep Learning-Based Cyber Threat Detection and Automated Incident Response (SOAR)** platform, including integration with **FreeLLMAPI** for automated AI threat intelligence.

---

## 1. Architecture Overview

```
                          [ Client / Security Analyst ]
                                        │
                                        ▼ (HTTP:80 / HTTPS:443)
                         [ Kubernetes Ingress (Nginx) ]
                                        │
                                        ▼
                         [ Service: cyber-soc-service ]
                                        │
                 ┌──────────────────────┴──────────────────────┐
                 ▼ (Port 5050)                                 ▼ (Port 5050)
      [ Pod: cyber-soc-app-1 ]                     [ Pod: cyber-soc-app-2 ]
      ├── CNN-LSTM + Attention                     ├── CNN-LSTM + Attention
      ├── SOAR Response Engine                     ├── SOAR Response Engine
      └── FreeLLMAPI Copilot                       └── FreeLLMAPI Copilot
                 │                                             │
                 ├──────────────────────┬──────────────────────┤
                 ▼                      ▼                      ▼
      [ PersistentVolumeClaim ]   [ ConfigMap/Secrets ]   [ FreeLLMAPI Gateway ]
      (data/cyber_soc.db & models) (App & Model Settings) (freellmapi-service:8000)
```

### Components
1. **Application Pods (`cyber-soc-app`)**: Multi-replica deployment running Flask, TensorFlow/Keras inference engine, and rule-based SOAR simulator.
2. **Persistent Storage (`cyber-soc-data-pvc`)**: 5Gi storage volume ensuring SQLite incidents database and model weights survive pod restarts.
3. **FreeLLMAPI Gateway (`freellmapi-service`)**: Aggregates free-tier LLM providers into an OpenAI-compatible `/v1` endpoint for AI incident briefings.
4. **Horizontal Pod Autoscaler (`cyber-soc-hpa`)**: Dynamically scales replicas between 2 and 6 based on CPU and memory thresholds.

---

## 2. Manifest Hierarchy (`k8s/`)

| Manifest | Purpose |
| :--- | :--- |
| `k8s/namespace.yaml` | Dedicated `cyber-soc` isolated namespace |
| `k8s/configmap.yaml` | Non-sensitive configs (Port, Host, FreeLLMAPI URL & model) |
| `k8s/secret.yaml` | Sensitive credentials (`FLASK_SECRET_KEY`, `FREELLMAPI_API_KEY`) |
| `k8s/pvc.yaml` | Persistent storage claim for DB and model weights |
| `k8s/deployment.yaml` | 2-replica high-availability deployment with probes & limits |
| `k8s/service.yaml` | ClusterIP service routing port 80 to port 5050 |
| `k8s/ingress.yaml` | Nginx Ingress routing for `soc.local` |
| `k8s/hpa.yaml` | Horizontal Pod Autoscaler (scales at >75% CPU) |
| `k8s/freellmapi.yaml` | Optional in-cluster FreeLLMAPI Gateway deployment & service |
| `k8s/kustomization.yaml` | Kustomize bundling for 1-command deployment |

---

## 3. Step-by-Step Deployment Instructions

### Prerequisites
- Docker Engine 24.0+ installed
- `kubectl` CLI installed
- A running Kubernetes cluster:
  - **Local**: Minikube, Kind, Docker Desktop K8s, or K3s
  - **Cloud**: Google Kubernetes Engine (GKE), AWS EKS, or Azure AKS

---

### Step 1: Build & Tag the Docker Image

From the project root directory:

```bash
# 1. Build the production image
docker build -t cyber-soc-ids:1.0.0 .

# 2. (If using Minikube, load image into Minikube cluster)
minikube image load cyber-soc-ids:1.0.0

# 3. (If using Kind)
kind load docker-image cyber-soc-ids:1.0.0

# 4. (If pushing to a container registry like DockerHub or GHCR)
docker tag cyber-soc-ids:1.0.0 <your-registry>/cyber-soc-ids:1.0.0
docker push <your-registry>/cyber-soc-ids:1.0.0
```

---

### Step 2: Configure FreeLLMAPI

Choose one of two options depending on where FreeLLMAPI is running:

#### Option A: In-Cluster FreeLLMAPI (Included)
The manifest `k8s/freellmapi.yaml` deploys FreeLLMAPI directly inside the cluster as `http://freellmapi-service:8000/v1`. This is already pre-configured in `k8s/configmap.yaml`!

#### Option B: External / Local FreeLLMAPI
If you already run FreeLLMAPI on your host or a separate server, edit `k8s/configmap.yaml`:
```yaml
data:
  FREELLMAPI_BASE_URL: "http://host.minikube.internal:8000/v1"  # Or your URL
  FREELLMAPI_MODEL: "gemini-1.5-flash"                         # Or llama-3.3-70b
```
And update `k8s/secret.yaml` with your API key if required:
```yaml
stringData:
  FREELLMAPI_API_KEY: "your-actual-api-key"
```

---

### Step 3: Deploy to Kubernetes

Deploy all resources in the `cyber-soc` namespace with a single command:

```bash
# 1-Command Kustomize Deployment
kubectl apply -k k8s/
```

*Or apply manifests individually:*
```bash
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/configmap.yaml
kubectl apply -f k8s/secret.yaml
kubectl apply -f k8s/pvc.yaml
kubectl apply -f k8s/freellmapi.yaml
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml
kubectl apply -f k8s/ingress.yaml
kubectl apply -f k8s/hpa.yaml
```

---

### Step 4: Verify Deployment Status

Check that all pods, services, and PVCs are running:

```bash
# Check all resources in the namespace
kubectl get all,pvc,ingress -n cyber-soc

# Sample output:
# NAME                                         READY   STATUS    RESTARTS   AGE
# pod/cyber-soc-deployment-7bb5df8cd6-9p2q1    1/1     Running   0          45s
# pod/cyber-soc-deployment-7bb5df8cd6-vx8lm    1/1     Running   0          45s
# pod/freellmapi-deployment-64d856b7db-k8m7n   1/1     Running   0          45s
#
# NAME                          TYPE        CLUSTER-IP       PORT(S)
# service/cyber-soc-service     ClusterIP   10.96.142.18     80/TCP
# service/freellmapi-service    ClusterIP   10.96.205.81     8000/TCP
```

Check live pod logs:
```bash
kubectl logs -f -l app.kubernetes.io/name=cyber-soc-app -n cyber-soc
```

---

### Step 5: Access the Application

#### Method 1: Port-Forwarding (Quick Local Access)
```bash
kubectl port-forward svc/cyber-soc-service 5050:80 -n cyber-soc
```
Open **[http://localhost:5050](http://localhost:5050)** in your browser.

#### Method 2: Ingress (`soc.local`)
Add the cluster IP to your `/etc/hosts`:
```bash
# Get ingress or cluster IP
minikube ip  # e.g., 192.168.49.2

# Add to /etc/hosts
192.168.49.2  soc.local
```
Navigate to **`http://soc.local`**.

---

### Step 6: Testing FreeLLMAPI AI Intelligence in Pods

1. Open an incident in the dashboard or via API:
```bash
# Simulate a DoS threat flow
curl -X POST http://localhost:5050/api/detection/simulate-preset \
  -H "Content-Type: application/json" \
  -d '{"category":"dos","count":2}'

# Query FreeLLMAPI threat intelligence for incident
curl http://localhost:5050/api/incidents/<incident_id>/ai-explain
```
2. The response will return the AI briefing generated via FreeLLMAPI (or the resilient rule engine fallback if FreeLLMAPI is starting up).

---

### Step 7: Teardown / Cleanup

To delete all deployed resources:
```bash
kubectl delete -k k8s/
```
Or delete the entire namespace:
```bash
kubectl delete namespace cyber-soc
```
