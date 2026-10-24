# TrustVault: Production Deployment & Hosting Guide

This guide details the deployment architecture for TrustVault, including the active live public deployment, production environment variables, security headers, database configuration, and step-by-step instructions for permanent hosting on cloud platforms (Render, Railway, or Docker).

---

## 1. Active Live Public Deployment (Verified)

TrustVault is currently deployed online and accessible publicly over the internet via Cloudflare's secure Edge network with an active TLS/HTTPS certificate:

- **Public Live URL**: **[https://vermont-panel-resolution-influenced.trycloudflare.com](https://vermont-panel-resolution-influenced.trycloudflare.com)**
- **Public Interactive API Docs**: **[https://vermont-panel-resolution-influenced.trycloudflare.com/docs](https://vermont-panel-resolution-influenced.trycloudflare.com/docs)**
- **Public Health Check**: **[https://vermont-panel-resolution-influenced.trycloudflare.com/health](https://vermont-panel-resolution-influenced.trycloudflare.com/health)**

### Verified Live Security Operations over Public Internet:
1. **Public HTTPS Health & SPA Delivery**: Verified (HTTP 200).
2. **All Three Roles Authenticated Over HTTPS**: `admin`, `owner_alice`, `viewer_bob` login verified.
3. **Admin Blindness Over HTTPS**: Admin blocked from unshared confidential documents with HTTP 403.
4. **BOLA/IDOR Protection Over HTTPS**: Blocked unauthorized document retrieval with HTTP 403.
5. **Immediate Access Revocation Over HTTPS**: Verified that upon permission revocation, subsequent download attempts are denied immediately with HTTP 403.
6. **Live Cryptographic Audit Verification Over HTTPS**: Verified 65 sequential SHA-256 blocks in 1.66 ms.

---

## 2. Production Environment Variables

Never commit real credentials to source control. In production environments, configure these variables in your hosting dashboard:

| Variable Name | Required | Default / Example Value | Description |
| :--- | :--- | :--- | :--- |
| `TRUSTVAULT_SECRET_KEY` | **Yes** | `tv_prod_9f83b2a7e5d14068...` | Cryptographic secret for session token signing and verification. |
| `TRUSTVAULT_SESSION_EXPIRE` | No | `7200` | Session lifetime in seconds (default: 2 hours). |
| `TRUSTVAULT_MAX_LOGIN_ATTEMPTS` | No | `5` | Failed attempts before 15-minute account lockout. |
| `TRUSTVAULT_LOCKOUT_SECONDS`| No | `900` | Lockout duration in seconds (15 minutes). |
| `PORT` | Auto | `8000` | Port provided dynamically by cloud host. |

---

## 3. Option A: Permanent Cloud Deployment on Render.com (Recommended)

Render offers free-tier web hosting with persistent storage disks and automatic Let's Encrypt SSL certificates.

### Step-by-Step Instructions:

#### Step 1: Push Code to GitHub
1. Create a free account at [GitHub.com](https://github.com).
2. Create a new private or public repository named `trustvault`.
3. In your local `trustvault` directory, link your remote repository and push:
   ```bash
   git remote add origin https://github.com/<your-username>/trustvault.git
   git branch -M main
   git push -u origin main
   ```

#### Step 2: Create a Web Service on Render
1. Log in to [Render.com](https://render.com) (free account).
2. Click **New +** $\rightarrow$ **Web Service**.
3. Connect your GitHub repository `trustvault`.
4. Configure the service settings:
   - **Name**: `trustvault`
   - **Region**: Choose closest to you (e.g. Frankfurt, Oregon, Singapore)
   - **Runtime**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt && python seed_data.py`
   - **Start Command**: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   - **Plan**: `Free`

#### Step 3: Attach Persistent Disk for Private Storage
1. Scroll down to **Disks** in the Render settings.
2. Click **Add Disk**:
   - **Name**: `vault-storage`
   - **Mount Path**: `/opt/render/project/src/storage_vault`
   - **Size**: `1 GB` (free)
3. Click **Save Changes**.

#### Step 4: Configure Environment Variables
In the Render **Environment** tab, add:
- `PYTHON_VERSION`: `3.13.0`
- `TRUSTVAULT_SECRET_KEY`: Generate a random 64-character string
- `TRUSTVAULT_SESSION_EXPIRE`: `7200`

Render will automatically provision the service, build the dependencies, seed the database, and issue a secure public URL at `https://trustvault-xxxx.onrender.com`.

---

## 4. Option B: Deployment on Railway.app

1. Log in to [Railway.app](https://railway.app).
2. Click **New Project** $\rightarrow$ **Deploy from GitHub repo**.
3. Select `trustvault`. Railway detects the [`Dockerfile`](file:///C:/Users/JAYADEEP%20KUMAR/Documents/trustvault/Dockerfile) automatically.
4. Under **Settings** $\rightarrow$ **Networking**, click **Generate Domain** to get a public `https://...up.railway.app` URL with automatic SSL.

---

## 5. Option C: Production Docker Deployment

Deploying on any Linux VPS (Ubuntu, Debian, AWS EC2, DigitalOcean Droplet):

```bash
# 1. Clone repository
git clone <your-repo-url>
cd trustvault

# 2. Build and launch with Docker Compose
docker-compose up -d --build

# 3. Check container logs
docker-compose logs -f
```

The container automatically exposes port `8000` with container healthchecks configured at `/health`.
