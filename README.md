# 🔍 BAC Scanner — Broken Access Control Detection Platform

A production-level cybersecurity tool that detects **Broken Access Control** vulnerabilities (OWASP A01:2021) across REST and GraphQL APIs.

## ✨ Features

| Feature | Description |
|---|---|
| 🎯 IDOR Detection | Mutates resource IDs to detect cross-user data leakage |
| 🔓 Auth Bypass | Tests null/empty/invalid tokens + header injection |
| ⬆️ Privilege Escalation | Cross-tests admin vs user tokens + role header injection |
| 🔄 Method Manipulation | Probes all HTTP methods for unprotected handlers |
| 📊 Access Matrix | D3.js heatmap of endpoint × user role permissions |
| 📚 Learning Mode | Explanations + fix suggestions for every vulnerability type |
| 🐛 Demo Target | Intentionally vulnerable Flask API with 4 real vulnerabilities |

---

## 🚀 Quick Start (Docker — Recommended)

```bash
# 1. Clone and enter the project
cd "AI-assisted Access Control Analysis Tool"

# 2. Start all services
docker-compose up --build

# Services will be available at:
# Frontend:    http://localhost:5173
# Backend API: http://localhost:8000
# API Docs:    http://localhost:8000/docs
# Demo Target: http://localhost:8001
```

---

## 🛠️ Manual Setup (Without Docker)

### Prerequisites
- Python 3.11+
- Node.js 20+
- PostgreSQL 15+
- Redis 7+

### 1. PostgreSQL Setup
```sql
CREATE DATABASE bacscanner;
CREATE USER bac WITH PASSWORD 'bacpass';
GRANT ALL PRIVILEGES ON DATABASE bacscanner TO bac;
```

### 2. Backend Setup
```bash
cd backend
pip install -r requirements.txt
cp .env.example .env   # Edit values if needed
uvicorn app.main:app --reload --port 8000
```

### 3. Celery Worker (new terminal)
```bash
cd backend
celery -A app.worker.celery_app worker --loglevel=info
```

### 4. Demo Target API (new terminal)
```bash
cd demo-target
pip install -r requirements.txt
python server.py
```

### 5. Frontend (new terminal)
```bash
cd frontend
npm install
npm run dev
```

---

## 🧪 Demo Walkthrough

### Step 1: Register & Login
Go to **http://localhost:5173** → Register an account → Log in

### Step 2: Load Demo Tokens
Go to **Scanner** → Click **"Load Demo Target Tokens"** (auto-fills Admin, Alice, Bob tokens)

### Step 3: Paste a Vulnerable Request
```
GET /api/users/2/profile HTTP/1.1
Host: localhost:8001
Authorization: Bearer <alice_token>
```

### Step 4: Start Scan
Click **🚀 Start Scan** — The scanner will:
1. Try accessing user 2's profile with user 3's token (IDOR)
2. Try with no token at all (Auth Bypass)
3. Try admin endpoints with regular user token (Privilege Escalation)
4. Test DELETE, PUT, PATCH methods (Method Manipulation)

### Step 5: View Results
- **Dashboard** → Filter by severity
- **Access Matrix** → Visual heatmap
- **Learning Mode** → Fix suggestions

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                   React Frontend                     │
│  Dashboard │ Scanner │ Access Matrix │ Learning Mode │
└──────────────────────┬──────────────────────────────┘
                       │ HTTP + REST API
┌──────────────────────▼──────────────────────────────┐
│                   FastAPI Backend                     │
│  Auth │ Projects │ Scans API │ WebSocket             │
│  ┌────────────────────────────────────────────┐      │
│  │              Scanner Engine                │      │
│  │  IDOR │ Auth Bypass │ Priv Esc │ Method    │      │
│  └────────────────────────────────────────────┘      │
└──────────────────────┬──────────────────────────────┘
           ┌───────────┼──────────────┐
    ┌──────▼──────┐ ┌──▼──┐ ┌────────▼───────┐
    │ PostgreSQL  │ │Redis│ │ Demo Target API│
    │  (Results)  │ │(MQ) │ │  (Vulnerable) │
    └─────────────┘ └─────┘ └────────────────┘
```

---

## 📁 Project Structure

```
├── backend/           # FastAPI + Scanner Engine
│   ├── app/
│   │   ├── api/       # Route handlers
│   │   ├── core/      # Config, DB, Security
│   │   ├── models/    # SQLAlchemy ORM
│   │   ├── scanner/   # Attack modules
│   │   └── worker/    # Celery tasks
│   └── Dockerfile
├── frontend/          # React + Vite
│   └── src/
│       ├── pages/     # Dashboard, Scanner, Matrix, Learning
│       ├── components/
│       ├── services/  # API client
│       └── store/     # Zustand auth
├── demo-target/       # Vulnerable Flask API
│   └── server.py
└── docker-compose.yml
```

---

## ⚠️ Disclaimer

The Demo Target API (`demo-target/server.py`) is **intentionally vulnerable**. It must **only be run locally** for testing purposes. Never deploy it to any public server.

---

## 🔐 Vulnerabilities in Demo Target

| Endpoint | Vulnerability | Type |
|---|---|---|
| `GET /api/users/{id}/profile` | No ownership check | IDOR |
| `GET /api/admin/stats` | Auth header not validated | AUTH_BYPASS |
| `GET /api/admin/users` | Trusts X-Role header | PRIVILEGE_ESCALATION |
| `DELETE /api/documents/{id}` | No auth on DELETE | METHOD_MANIPULATION |

---

*Built with FastAPI, React, PostgreSQL, Redis, Celery, D3.js*
