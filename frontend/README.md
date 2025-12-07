# Frontend Setup and Running Guide

## Quick Start

### 1. Install Dependencies

```bash
cd frontend
npm install
```

### 2. Configure Environment

Create `.env.local` file (optional - defaults work):

```bash
# API Base URL (default: http://localhost:8000)
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
```

### 3. Start Development Server

```bash
npm run dev
```

The frontend will be available at `http://localhost:3000`

## Pages Available

1. **Dashboard** (`/dashboard` or `/`)
   - Real-time statistics
   - Alert severity distribution
   - Top hosts and alert types
   - Auto-refreshes every 10 seconds

2. **Logs** (`/logs`)
   - Search and filter logs
   - Filter by appname and host
   - View log details

3. **Alerts** (`/alerts`)
   - View signature detection results
   - Filter by severity
   - Expandable metadata view
   - Auto-refreshes every 10 seconds

## Prerequisites

- Backend API must be running on port 8000
- Node.js 18+ installed
- Database with logs and alerts data

## Running Both Backend and Frontend

### Terminal 1: Backend API
```bash
cd backend
source .venv/bin/activate
python3 -m uvicorn api.main:app --reload
```

### Terminal 2: Frontend
```bash
cd frontend
npm run dev
```

### Terminal 3: Log Seeder (Optional)
```bash
python3 temp_seeder/seeder.py 10 5
```

## Troubleshooting

### Frontend can't connect to API
- Ensure backend is running on port 8000
- Check CORS settings in `backend/api/main.py`
- Verify `NEXT_PUBLIC_API_BASE_URL` in `.env.local`

### No data showing
- Ensure database has logs and alerts
- Run the log seeder to generate test data
- Check browser console for errors

### 307 Redirect Loop
- This has been fixed - dashboard page now has proper content
- Clear browser cache if issue persists

## Development

### Adding New Pages
1. Create page in `frontend/src/app/[page-name]/page.tsx`
2. Add route to sidebar in `frontend/src/components/layout/Sidebar.tsx`

### Styling
- Uses Tailwind CSS v4
- Dark theme by default
- Glassmorphism effects
- Framer Motion for animations
