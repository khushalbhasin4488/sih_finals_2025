# Complete Setup Guide - Running from Scratch

This guide will help you set up and run the Log Analyzer Tool from scratch.

## Prerequisites

Before starting, ensure you have:

- **Python 3.11+** installed
- **Node.js 18+** and npm installed
- **Git** (if cloning from repository)

### Verify Prerequisites

```bash
# Check Python version
python3 --version  # Should be 3.11 or higher

# Check Node.js version
node --version  # Should be 18 or higher

# Check npm version
npm --version
```

## Step 1: Clone/Download Project

If you have the project already, skip this step.

```bash
# If cloning from git
git clone <repository-url>
cd sih_finals
```

## Step 2: Backend Setup

### 2.1 Create Virtual Environment

```bash
cd backend
python3 -m venv .venv  # or: python3 -m venv venv

# Activate virtual environment
# On macOS/Linux:
source .venv/bin/activate
# On Windows:
# .venv\Scripts\activate
```

### 2.2 Install Dependencies

```bash
# Upgrade pip
pip install --upgrade pip

# Install all requirements
pip install -r requirements.txt
```

**Note**: This may take a few minutes. The installation includes:
- FastAPI and web server
- DuckDB database
- Machine learning libraries (scikit-learn, numpy)
- Data processing (pandas)
- And other dependencies

### 2.3 Verify Backend Setup

```bash
# Check if key packages are installed
python3 -c "import fastapi; import duckdb; import numpy; print('✓ All packages installed')"
```

## Step 3: Frontend Setup

### 3.1 Install Dependencies

Open a **new terminal** (keep backend terminal open):

```bash
cd frontend
npm install
```

This will install:
- Next.js framework
- React components
- Tailwind CSS
- Framer Motion (animations)
- And other frontend dependencies

### 3.2 Verify Frontend Setup

```bash
# Check if node_modules exists
ls node_modules | head -5
```

## Step 4: Create Required Directories

```bash
# From project root
mkdir -p data/duckdb
mkdir -p data/archives
mkdir -p logs
mkdir -p updates
```

## Step 5: Initialize Database

The database will be created automatically when you first run the API, but you can verify the directory exists:

```bash
# Ensure data directory exists
ls -la data/duckdb/
```

## Step 6: Start the Application

You need **two terminals** running simultaneously:

### Terminal 1: Backend API

```bash
cd backend
source .venv/bin/activate  # Activate virtual environment
python3 -m uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

**Expected output:**
```
INFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)
INFO:     Started reloader process
INFO:     Started server process
INFO:     Waiting for application startup.
INFO:     Starting up API...
INFO:     Orchestrator initialized
INFO:     Analysis service started (runs every 60 seconds)
INFO:     Application startup complete.
```

**API will be available at:** http://localhost:8000
**API Documentation:** http://localhost:8000/docs

### Terminal 2: Frontend

```bash
cd frontend
npm run dev
```

**Expected output:**
```
  ▲ Next.js 16.0.6
  - Local:        http://localhost:3000
  - ready started server on 0.0.0.0:3000
```

**Frontend will be available at:** http://localhost:3000

## Step 7: Generate Initial Data (Optional but Recommended)

To see stats and alerts, you need logs in the database. Use the seeder:

### Terminal 3: Generate Logs

```bash
# From project root
python3 temp_seeder/seeder.py 30 2
```

This generates:
- 30 logs every 2 seconds
- Mix of normal traffic, attacks, and anomalies
- Let it run for 5-10 minutes to build baselines

**Recommended:** Run for at least 5 minutes, then press `Ctrl+C`

## Step 8: Access the Application

Once everything is running:

1. **Dashboard**: http://localhost:3000/dashboard
2. **Alerts**: http://localhost:3000/alerts
3. **Reports**: http://localhost:3000/reports
4. **Logs**: http://localhost:3000/logs
5. **API Docs**: http://localhost:8000/docs

## Quick Setup Script (Alternative)

If you prefer automation, use the setup script:

```bash
# Make script executable
chmod +x scripts/setup.sh

# Run setup
./scripts/setup.sh
```

Then follow steps 6-8 above.

## Verification Checklist

After setup, verify everything works:

### ✅ Backend Check

```bash
# In Terminal 1 (backend running)
curl http://localhost:8000/api/v1/health
```

Should return:
```json
{
  "status": "healthy",
  "database": "connected",
  "total_logs": <number>
}
```

### ✅ Frontend Check

Open browser: http://localhost:3000

Should see the dashboard (may be empty if no logs yet).

### ✅ Analysis Check

```bash
curl http://localhost:8000/ | jq
```

Should show:
```json
{
  "auto_analysis": true,
  "baseline_scheduler": true
}
```

## Troubleshooting

### Backend Issues

**Problem: Module not found errors**
```bash
# Solution: Reinstall dependencies
cd backend
source .venv/bin/activate
pip install -r requirements.txt
```

**Problem: Port 8000 already in use**
```bash
# Solution: Use different port
python3 -m uvicorn api.main:app --reload --port 8001
# Then update frontend .env: NEXT_PUBLIC_API_BASE_URL=http://localhost:8001
```

**Problem: Database errors**
```bash
# Solution: Ensure data directory exists
mkdir -p data/duckdb
# Database will be created automatically
```

### Frontend Issues

**Problem: npm install fails**
```bash
# Solution: Clear cache and reinstall
rm -rf node_modules package-lock.json
npm cache clean --force
npm install
```

**Problem: Port 3000 already in use**
```bash
# Solution: Use different port
npm run dev -- -p 3001
```

**Problem: Can't connect to API**
- Check backend is running on port 8000
- Check `frontend/.env.local` has: `NEXT_PUBLIC_API_BASE_URL=http://localhost:8000`
- Check browser console for CORS errors

### Data/Stats Issues

**Problem: No stats showing**
- Run seeder to generate logs (Step 7)
- Wait 60 seconds for first analysis cycle
- Check API logs for errors

**Problem: No anomaly detection**
- Ensure you have >100 logs for baselines
- Check `data/baselines.json` exists
- Wait for baseline creation on API startup

## Project Structure

```
sih_finals/
├── backend/              # Python backend
│   ├── api/            # FastAPI REST API
│   ├── analyzers/      # Detection engines
│   ├── storage/        # Database interface
│   └── requirements.txt
├── frontend/           # Next.js frontend
│   ├── src/
│   └── package.json
├── config/             # Configuration files
│   ├── signatures/     # Attack signatures
│   └── rules/          # Detection rules
├── data/               # Data storage
│   └── duckdb/         # Database files
├── temp_seeder/        # Log generator
└── scripts/             # Setup scripts
```

## Next Steps

1. **Generate logs** using seeder (Step 7)
2. **Explore dashboard** at http://localhost:3000/dashboard
3. **View alerts** at http://localhost:3000/alerts
4. **Check reports** at http://localhost:3000/reports
5. **Read documentation**:
   - `GENERATE_STATS_GUIDE.md` - How to generate stats
   - `AUTOMATIC_ANALYSIS_GUIDE.md` - How analysis works
   - `plan.md` - Project architecture

## Development Tips

### Hot Reload
- Backend: Auto-reloads on code changes (--reload flag)
- Frontend: Auto-reloads on code changes (Next.js default)

### Logs
- Backend logs: Check terminal running uvicorn
- Frontend logs: Check browser console (F12)

### Database
- Location: `data/duckdb/logs.db`
- Can be deleted to start fresh (will be recreated)

## Stopping the Application

1. **Stop seeder**: Press `Ctrl+C` in seeder terminal
2. **Stop frontend**: Press `Ctrl+C` in frontend terminal
3. **Stop backend**: Press `Ctrl+C` in backend terminal

All services will shutdown gracefully.

## Summary

**Quick Start (3 commands):**

```bash
# Terminal 1: Backend
cd backend && source .venv/bin/activate && python3 -m uvicorn api.main:app --reload

# Terminal 2: Frontend  
cd frontend && npm run dev

# Terminal 3: Generate data
python3 temp_seeder/seeder.py 30 2
```

Then visit: **http://localhost:3000/dashboard**

That's it! 🎉

