# Cloud Deployment & Production Operations Guide

**Project Name:** Deep Learning-Based Cyber Threat Detection and Automated Incident Response  
**Target Platform:** `[DEPLOYMENT_PLATFORM]`  
**Status:** Prepared for Production Deployment  

---

## 1. Project Prerequisites

Before deploying the application to `[DEPLOYMENT_PLATFORM]`, verify the following requirements:
* **Operating System / Container Runtime:** Docker Engine 24.0+ and Docker Compose v2.0+ (or Linux VM: Ubuntu 22.04 LTS / Debian 12).
* **Python Runtime:** Python 3.11, 3.12, or 3.13 (if deploying directly to bare-metal / VM without containers).
* **Memory & Storage:**
  * Minimum: 2 GB RAM (sufficient for model inference and SQLite).
  * Recommended: 4 GB RAM for multi-worker concurrency.
  * Disk space: 5 GB free for datasets, model weights, and logs.
* **Network Ports:** Port `5050` (or `80`/`443` through Nginx reverse proxy).

---

## 2. Environment Variables Configuration

Create a `.env` file from `.env.example`:

```bash
cp .env.example .env
```

| Variable | Description | Example / Recommended Value |
| :--- | :--- | :--- |
| `PROJECT_NAME` | Canonical application title | `Deep Learning Cyber Threat Detection` |
| `DEPLOYMENT_PLATFORM` | Cloud provider identifier | `[DEPLOYMENT_PLATFORM]` |
| `API_BASE_URL` | Base public API URL | `[API_BASE_URL]` |
| `HOST` | Interface IP binding | `0.0.0.0` (all interfaces in container) |
| `PORT` | Listening network port | `5050` |
| `FLASK_DEBUG` | Development debug flag | `False` (Must be False in production) |
| `FLASK_SECRET_KEY` | Session encryption secret | `generate-random-secret-key-min-32-chars` |
| `MAX_UPLOAD_SIZE_MB` | Flow CSV upload threshold | `100` |
| `RESPONSE_MODE` | Active SOAR safety mode | `SIMULATION_ONLY` |
| `DATABASE_PATH` | Path to persistent SQLite file| `data/cyber_soc.db` |
| `KERAS_HOME` | Isolated Keras configuration | `/app/.keras` |
| `MPLCONFIGDIR` | Isolated Matplotlib cache | `/app/.matplotlib_cache` |

---

## 3. Dependency Installation & Production Build

### Method A: Docker Container Build (Recommended)

1. Build the production container image:
   ```bash
   docker build -t cyber-soc-ids:v1.0 .
   ```

2. Run with Docker Compose:
   ```bash
   docker compose up -d
   ```

### Method B: Native Virtual Environment Build

1. Create a dedicated virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. Install production dependencies:
   ```bash
   pip install --upgrade pip setuptools wheel
   pip install -r requirements.txt
   ```

3. Initialize the database schema:
   ```bash
   PYTHONPATH=. python3 -c "from src.database import init_db; init_db(); print('Database initialized.')"
   ```

---

## 4. Cloud Hosting Setup (`[DEPLOYMENT_PLATFORM]`)

The system is configured to run on container-based or serverless container services on `[DEPLOYMENT_PLATFORM]` (such as AWS ECS / App Runner, Google Cloud Run, Azure Container Instances, or Render / Railway).

### Deployment Procedure Placeholder

The deployment execution follows these steps:

```text
[DEPLOYMENT_STEPS]
```

---

## 5. Reverse Proxy & HTTPS Configuration (Nginx)

When exposing the application to public internet traffic, route connections through Nginx (using `nginx.conf`):

1. **Copy configuration:**
   ```bash
   sudo cp nginx.conf /etc/nginx/nginx.conf
   sudo nginx -t
   sudo systemctl restart nginx
   ```

2. **Obtain SSL Certificate (Certbot / Let's Encrypt):**
   ```bash
   sudo certbot --nginx -d [DOMAIN_NAME_PLACEHOLDER]
   ```

---

## 6. Post-Deployment Verification Checklist

Execute these checks after initiating deployment:

1. **Health Check Probe:**
   ```bash
   curl -f http://[API_BASE_URL]/api/health
   ```
   *Expected Response:* HTTP 200 with `{"status":"healthy","model_loaded":true,"response_mode":"SIMULATION_ONLY"}`.

2. **Authentication Portal:**
   Access `http://[API_BASE_URL]/login` and test authentication with default analyst credentials:
   - Email: `analyst@soc.local`
   - Password: `Secure@SOC2026!`

3. **Inference Test:**
   Submit a test payload via `/api/detection/predict` or through the **Traffic Analysis** web UI.

4. **Persistence Verification:**
   Confirm that incident records persist across container restarts in the mapped `data/` volume.
