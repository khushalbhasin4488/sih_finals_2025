# Anomaly Visualization Implementation Guide

## Overview
This document describes the anomaly visualization system added to the log analyzer.

## Components Created

### Backend API Endpoints (`backend/api/routes/analytics.py`)

1. **GET /api/analytics/anomalies/timeline** - Anomaly detection timeline
   - Params: `hours` (default: 24)
   - Returns: Hourly aggregated anomaly counts and average scores

2. **GET /api/analytics/anomalies/baselines** - Baseline metrics
   - Returns: Current baseline values for all metrics (mean, std, min, max)

3. **GET /api/analytics/anomalies/distribution** - Top anomalous IPs
   - Params: `limit` (default: 100)
   - Returns: IPs with highest anomaly counts

4. **GET /api/analytics/anomalies/severity** - Severity distribution
   - Returns: Count of anomalies by severity level

5. **GET /api/analytics/anomalies/types** - Anomaly types
   - Returns: Top 10 anomaly types by count

### Frontend Components (`frontend/components/charts/AnomalyCharts.tsx`)

1. **AnomalyTimeline** - Line chart showing anomalies over time
2. **BaselineMetrics** - Bar chart of baseline mean and std dev
3. **AnomalyDistribution** - Horizontal bar chart of top anomalous IPs
4. **SeverityDistribution** - Pie chart of anomalies by severity
5. **AnomalyTypes** - Bar chart of anomaly types
6. **AnomalyDashboard** - Combined dashboard with all charts

### Pages

- **`/dashboard/anomalies`** - Full anomaly visualization dashboard

## Usage

### Access the Dashboard

1. Start the backend API:
```bash
cd backend
source .venv/bin/activate
uvicorn api.main:app --reload
```

2. Start the frontend:
```bash
cd frontend
npm run dev
```

3. Navigate to: `http://localhost:3000/dashboard/anomalies`

### Available Charts

1. **Timeline** - See when anomalies occurred in the last 24 hours
2. **Baselines** - View current baseline metrics for comparison
3. **Distribution** - Identify which IPs are generating most anomalies
4. **Severity** - Understand the severity breakdown of anomalies
5. **Types** - See what types of anomalies are being detected

## Customization

### Change Time Range

```tsx
<AnomalyTimeline hours={48} />  // Last 48 hours
```

### Styling

All components use Tailwind CSS and support dark mode automatically.

### Adding New Charts

1. Create endpoint in `backend/api/routes/analytics.py`
2. Create React component in `frontend/components/charts/AnomalyCharts.tsx`
3. Add to `AnomalyDashboard` component

## Dependencies

- **Backend**: FastAPI, DuckDB, structlog
- **Frontend**: Next.js 14, React, Recharts, Tailwind CSS

## API Response Format

All endpoints return:
```json
{
  "success": true,
  "data": [...],
  "timeRange": "Last 24 hours"  // Optional
}
```
