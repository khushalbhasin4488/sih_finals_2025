# Running the Backend API

## Prerequisites

- Python 3.11+ with virtual environment activated
- DuckDB database with logs and alerts

## Starting the API Server

```bash
# From the project root
cd backend

# Activate virtual environment
source .venv/bin/activate

# Run the API server
python3 -m uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

The API will be available at `http://localhost:8000`

## API Documentation

Once the server is running, visit:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

## Available Endpoints

### Health & Stats
- `GET /` - Root endpoint
- `GET /api/v1/health` - Health check
- `GET /api/v1/stats` - Dashboard statistics

### Logs
- `GET /api/v1/logs` - Get logs (with filters: limit, offset, appname, host, search)
- `GET /api/v1/logs/{log_id}` - Get specific log by ID
- `GET /api/v1/appnames` - Get list of unique appnames
- `GET /api/v1/hosts` - Get list of unique hosts

### Alerts
- `GET /api/v1/alerts` - Get alerts (with filters: limit, severity, acknowledged)

## Example Requests

```bash
# Get stats
curl http://localhost:8000/api/v1/stats

# Get recent logs
curl http://localhost:8000/api/v1/logs?limit=10

# Get logs for specific appname
curl http://localhost:8000/api/v1/logs?appname=sshd

# Get critical alerts
curl http://localhost:8000/api/v1/alerts?severity=critical

# Search logs
curl "http://localhost:8000/api/v1/logs?search=failed"
```

## CORS Configuration

The API is configured to allow requests from:
- `http://localhost:3000` (Next.js default)
- `http://localhost:3001`

## Running with Frontend

1. Start the backend API (port 8000)
2. Start the frontend (port 3000)
3. Frontend will automatically connect to the API

```bash
# Terminal 1: Backend
cd backend
source .venv/bin/activate
python3 -m uvicorn api.main:app --reload

# Terminal 2: Frontend
cd frontend
npm run dev
```
